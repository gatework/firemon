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
		{"canceled-nil-statements", func() error { _, err := config.Statements(ctx, nil); return err }, context.Canceled},
		{"nil-classifier", func() error { _, err := config.Blocks(context.Background(), empty, nil); return err }, config.ErrInvalid},
		{"nil-block-cursor", func() error { _, err := config.Blocks(context.Background(), nil, classify); return err }, config.ErrInvalid},
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

func TestInvalidStagesWrapErrInvalidBeforeRunning(t *testing.T) {
	called := false
	run := func(context.Context, *config.Session) error { called = true; return nil }
	for _, stages := range [][]config.Stage{
		{{Name: "", Run: run}}, {{Name: "  ", Run: run}}, {{Name: "interfaces"}},
		{{Name: "interfaces", Run: run}, {Name: "interfaces", Run: run}},
		{{Name: "routes", Requires: []string{"interfaces"}, Run: run}},
	} {
		session, err := config.NewSession(source(t, "pending\n"), fm.Metadata{})
		if err != nil {
			t.Fatal(err)
		}
		if err = session.Run(context.Background(), stages); !errors.Is(err, config.ErrInvalid) || called {
			t.Fatalf("invalid stages: called=%v, err=%v", called, err)
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

func TestCursorConstructionHonorsCancellationAndSourceErrors(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, raw := range []string{"", "\xff", strings.Repeat("界", 1<<16)} {
		c, err := config.NewCursor(canceled, config.Source{Text: raw}, config.Limits{MaxBytes: 1})
		if c != nil || !errors.Is(err, context.Canceled) {
			t.Fatalf("cursor precedence: %v, %v", c, err)
		}
		c, err = config.NewFragmentCursor(canceled, config.Source{Text: raw}, []fm.Span{{First: 9}}, config.Limits{MaxBytes: 1})
		if c != nil || !errors.Is(err, context.Canceled) {
			t.Fatalf("fragment precedence: %v, %v", c, err)
		}
	}
	raw := strings.Repeat("界", 1<<16)
	for _, fragment := range []bool{false, true} {
		ctx := &scanCancellation{Context: context.Background(), remaining: 8}
		var c *config.Cursor
		var err error
		if fragment {
			c, err = config.NewFragmentCursor(ctx, config.Source{Text: raw}, []fm.Span{{First: 1, Last: 1, EndByte: len(raw)}}, config.Limits{})
		} else {
			c, err = config.NewCursor(ctx, config.Source{Text: raw}, config.Limits{})
		}
		if c != nil || !errors.Is(err, context.Canceled) {
			t.Fatalf("long construction: %v, %v", c, err)
		}
	}
	// Multibyte runes straddling scanner chunk boundaries remain valid. Invalid
	// continuations and truncation retain ErrSource, rather than replacement text.
	for _, suffix := range []string{"界\r\nlast", "\xff", "\xe7\x95"} {
		raw := strings.Repeat("x", 4095) + suffix
		c, err := config.NewCursor(context.Background(), config.Source{Text: raw}, config.Limits{})
		if suffix == "界\r\nlast" {
			if err != nil || len(c.Lines()) != 2 || c.Lines()[0].Raw != raw[:len(raw)-4] {
				t.Fatalf("UTF8 boundary: %v", err)
			}
		} else if c != nil || !errors.Is(err, config.ErrSource) {
			t.Fatalf("invalid UTF8: %v, %v", c, err)
		}
	}
}

func TestFragmentScannerPreservesSplitUTF8AndPhysicalSpans(t *testing.T) {
	raw := "界\r\nlast"
	spans := []fm.Span{{First: 1, Last: 1, StartByte: 0, EndByte: 1}, {First: 1, Last: 1, StartByte: 1, EndByte: 5}, {First: 2, Last: 2, StartByte: 5, EndByte: len(raw)}}
	c, err := config.NewFragmentCursor(context.Background(), config.Source{Text: raw}, spans, config.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	for i, e := range c.Evidence() {
		if e.Span != spans[i] || e.State != fm.Pending {
			t.Fatalf("evidence changed: %+v", e)
		}
	}
}

func TestCursorCancelsAfterUTF8Validation(t *testing.T) {
	raw := strings.Repeat("x", 4096*8)
	// Eight validation chunks plus entry/exit checks complete before cancellation;
	// the next checks occur inside the physical-line and fragment byte scans.
	for _, fragment := range []bool{false, true} {
		ctx := &scanCancellation{Context: context.Background(), remaining: 14}
		var c *config.Cursor
		var err error
		if fragment {
			c, err = config.NewFragmentCursor(ctx, config.Source{Text: raw}, []fm.Span{{First: 1, Last: 1, EndByte: len(raw)}}, config.Limits{})
		} else {
			c, err = config.NewCursor(ctx, config.Source{Text: raw}, config.Limits{})
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
	if !errors.Is(err, context.Canceled) || d.Root != nil || d.Cursor != nil {
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
