package config_test

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
)

// Cancellation is triggered at an observed work checkpoint, without sleeps or
// scheduler races. The context is used only by the synchronous scanner under test.
type scanCancellation struct {
	context.Context
	remaining int
}

func (c *scanCancellation) Err() error {
	c.remaining--
	if c.remaining <= 0 {
		return context.Canceled
	}
	return nil
}

func TestScanningEntryContracts(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	empty := source(t, "")
	classify := func(config.Statement, []string) (config.Boundary, string) { return config.Member, "" }
	for _, tc := range []struct {
		name string
		run  func() error
		want error
	}{
		{"empty-statements-canceled", func() error { _, err := config.Statements(ctx, empty); return err }, context.Canceled},
		{"nil-statements", func() error { _, err := config.Statements(context.Background(), nil); return err }, config.ErrInvalid},
		{"uninitialized-statements", func() error { _, err := config.Statements(t.Context(), &config.Content{}); return err }, config.ErrInvalid},
		{"canceled-nil-statements", func() error { _, err := config.Statements(ctx, nil); return err }, context.Canceled},
		{"nil-classifier", func() error { _, err := config.Blocks(context.Background(), empty, nil); return err }, config.ErrInvalid},
		{"nil-block-content", func() error { _, err := config.Blocks(context.Background(), nil, classify); return err }, config.ErrInvalid},
		{"uninitialized-block-content", func() error { _, err := config.Blocks(t.Context(), &config.Content{}, classify); return err }, config.ErrInvalid},
		{"canceled-nil-blocks", func() error { _, err := config.Blocks(ctx, nil, nil); return err }, context.Canceled},
		{"nil-parser", func() error {
			var p config.ParseFunc
			_, err := p.Parse(context.Background(), config.Source{}, fm.Metadata{})
			return err
		}, config.ErrInvalid},
		{"canceled-nil-parser", func() error {
			var p config.ParseFunc
			_, err := p.Parse(ctx, config.Source{}, fm.Metadata{})
			return err
		}, context.Canceled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if v := recover(); v != nil {
					t.Errorf("entrypoint panicked: %v", v)
				}
			}()
			if err := tc.run(); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
	called := false
	p := config.ParseFunc(func(context.Context, config.Source, fm.Metadata) (*fm.Firewall, error) {
		called = true
		return nil, nil
	})
	if _, err := p.Parse(ctx, config.Source{}, fm.Metadata{}); !errors.Is(err, context.Canceled) || called {
		t.Fatalf("canceled callback invoked: %v, %v", called, err)
	}
}

func TestStatementScanCancelsInsideLongQuotedLine(t *testing.T) {
	c := source(t, "set description \""+strings.Repeat("防火墙", 1<<16)+"\"\n")
	before := c.Evidence()
	ctx := &scanCancellation{Context: context.Background(), remaining: 5}
	statements, err := config.Statements(ctx, c)
	if statements != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("long scan ignored cancellation: %d, %v", len(statements), err)
	}
	if !reflect.DeepEqual(before, c.Evidence()) {
		t.Fatal("structural scan changed evidence")
	}
}

func TestInvalidPhasesFailBeforeRunning(t *testing.T) {
	called := false
	run := func(context.Context, *config.Builder) error { called = true; return nil }
	for _, tc := range []struct {
		name string
		run  func(context.Context, *config.Builder) error
	}{{"", run}, {"  ", run}, {"interfaces", nil}} {
		b, err := config.NewBuilder(source(t, "pending\n"), fm.Metadata{})
		if err != nil {
			t.Fatal(err)
		}
		if err = b.Phase(context.Background(), tc.name, tc.run); !errors.Is(err, config.ErrInvalid) || called {
			t.Fatalf("invalid phase: called=%v, error=%v", called, err)
		}
	}
}
func TestBlocksCancellationAfterClassifierReturnsNoPartialDocument(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	d, err := config.Blocks(ctx, source(t, "member\n"), func(config.Statement, []string) (config.Boundary, string) { cancel(); return config.Member, "" })
	if !errors.Is(err, context.Canceled) || !reflect.DeepEqual(d, config.Document{}) {
		t.Fatalf("partial document returned: %+v, %v", d, err)
	}
}

func TestContentConstructionHonorsCancellationAndSourceErrors(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, raw := range []string{"", "\xff", strings.Repeat("界", 1<<16)} {
		c, err := config.NewContent(canceled, config.Source{Text: raw}, config.Limits{MaxBytes: 1})
		if c != nil || !errors.Is(err, context.Canceled) {
			t.Fatalf("content precedence: %v, %v", c, err)
		}
		d, err := config.XML(canceled, config.Source{Text: raw}, config.Limits{MaxBytes: 1})
		if d.Content != nil || d.Root != nil || !errors.Is(err, context.Canceled) {
			t.Fatalf("XML precedence: %v", err)
		}
	}
	raw := strings.Repeat("界", 1<<16)
	for _, xml := range []bool{false, true} {
		ctx := &scanCancellation{Context: context.Background(), remaining: 8}
		var c *config.Content
		var err error
		if xml {
			var d config.XMLDocument
			d, err = config.XML(ctx, config.Source{Text: raw}, config.Limits{})
			c = d.Content
		} else {
			c, err = config.NewContent(ctx, config.Source{Text: raw}, config.Limits{})
		}
		if c != nil || !errors.Is(err, context.Canceled) {
			t.Fatalf("long construction: %v, %v", c, err)
		}
	}
	// Multibyte runes straddling scanner chunk boundaries remain valid. Invalid
	// continuations and truncation retain ErrSource, rather than replacement text.
	for _, suffix := range []string{"界\r\nlast", "\xff", "\xe7\x95"} {
		raw := strings.Repeat("x", 4095) + suffix
		c, err := config.NewContent(context.Background(), config.Source{Text: raw}, config.Limits{})
		if suffix == "界\r\nlast" {
			if err != nil || len(c.Lines()) != 2 || c.Lines()[0].Raw != raw[:len(raw)-4] {
				t.Fatalf("UTF8 boundary: %v", err)
			}
		} else if c != nil || !errors.Is(err, config.ErrSource) {
			t.Fatalf("invalid UTF8: %v, %v", c, err)
		}
	}
}

func TestContentCancelsAfterUTF8Validation(t *testing.T) {
	raw := strings.Repeat("x", 4096*8)
	// Cancellation remains observable after validation, while the shared source
	// index and evidence are being constructed.
	for _, xml := range []bool{false, true} {
		ctx := &scanCancellation{Context: context.Background(), remaining: 14}
		var c *config.Content
		var err error
		if xml {
			var d config.XMLDocument
			d, err = config.XML(ctx, config.Source{Text: raw}, config.Limits{})
			c = d.Content
		} else {
			c, err = config.NewContent(ctx, config.Source{Text: raw}, config.Limits{})
		}
		if c != nil || !errors.Is(err, context.Canceled) {
			t.Fatalf("post-validation scan: %v, %v", c, err)
		}
	}
}

func TestXMLCancelsDuringLargeTextToken(t *testing.T) {
	raw := "<config>" + strings.Repeat("x", 4096*16) + "</config>"
	ctx := &scanCancellation{Context: context.Background(), remaining: 30}
	d, err := config.XML(ctx, config.Source{Text: raw}, config.Limits{})
	if !errors.Is(err, context.Canceled) || d.Root != nil || d.Content != nil {
		t.Fatalf("partial XML returned: %v", err)
	}
}

func TestStatementsPreserveQuotedMultilineRawBytes(t *testing.T) {
	raw := "set description \"界\r\nsecond\"\r\nnext\r"
	c := source(t, raw)
	statements, err := config.Statements(context.Background(), c)
	if err != nil || len(statements) != 2 {
		t.Fatalf("statements: %v", err)
	}
	if statements[0].Raw+statements[1].Raw != raw || statements[0].Span != (fm.Span{First: 1, Last: 2}) || statements[1].Span != (fm.Span{First: 3, Last: 3}) || statements[0].Words[2] != "界\r\nsecond" {
		t.Fatalf("raw bytes or line spans changed: %+v", statements)
	}
}
