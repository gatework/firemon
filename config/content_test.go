package config_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
)

func source(t *testing.T, s string) *config.Content {
	t.Helper()
	c, err := config.NewContent(context.Background(), config.Source{Text: s, Complete: true}, config.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	return c
}
func TestReadingKeepsEvidenceUntilCommit(t *testing.T) {
	c := source(t, "interface eth0\nrule 1\n")
	b, err := config.NewBuilder(c, fm.Metadata{})
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := config.Statements(t.Context(), c); err != nil {
			t.Fatal(err)
		}
		for _, e := range c.Evidence() {
			if e.State != fm.Pending {
				t.Fatal("reading consumed evidence")
			}
		}
	}
	tx := b.Begin()
	tx.Emit(fm.Data{Interfaces: []fm.InterfaceRecord{{Object: fm.Object{ID: "eth0"}}}})
	tx.Parse(1)
	if err := b.Commit(tx); err != nil {
		t.Fatal(err)
	}
	if _, err := config.Statements(t.Context(), c); err != nil {
		t.Fatal(err)
	}
	if c.Evidence()[0].State != fm.Parsed || c.Evidence()[1].State != fm.Pending {
		t.Fatal("reading changed committed evidence")
	}
	failed := b.Begin()
	failed.Emit(fm.Data{Rules: []fm.RuleRecord{{Object: fm.Object{ID: "r1"}}}})
	failed.Parse(2, 1)
	if err := b.Commit(failed); err == nil {
		t.Fatal("duplicate claim accepted")
	}
	if len(b.Data().Rules) != 0 || c.Evidence()[1].State != fm.Pending {
		t.Fatal("failed commit leaked draft or evidence")
	}
}
func TestRollbackPreservesEvidenceAndKnownIgnoreRequiresReason(t *testing.T) {
	c := source(t, "a\nb\n")
	b, err := config.NewBuilder(c, fm.Metadata{})
	if err != nil {
		t.Fatal(err)
	}
	tx := b.Begin()
	tx.Parse(1)
	tx.Rollback()
	if c.Evidence()[0].State != fm.Pending {
		t.Fatal("rollback consumed evidence")
	}
	tx = b.Begin()
	tx.Ignore("", 1)
	if err := b.Commit(tx); err == nil {
		t.Fatal("unexplained ignore")
	}
	tx = b.Begin()
	tx.Ignore("blank/comment", 1)
	if err := b.Commit(tx); err != nil {
		t.Fatal(err)
	}
	evidence := c.Evidence()
	if evidence[0].State != fm.Ignored || evidence[0].Reason != "blank/comment" || evidence[1].State != fm.Pending {
		t.Fatal("ignore changed unrelated evidence", evidence)
	}
}
func TestPhaseRollsBackFailedWork(t *testing.T) {
	c := source(t, "interface eth0\n")
	b, err := config.NewBuilder(c, fm.Metadata{Device: "test", Vendor: "test"})
	if err != nil {
		t.Fatal(err)
	}
	run := func(ctx context.Context, b *config.Builder) error {
		tx := b.Begin()
		tx.Parse(1)
		tx.Emit(fm.Data{Interfaces: []fm.InterfaceRecord{{Object: fm.Object{ID: "eth0"}}}})
		if err := b.Commit(tx); err != nil {
			return err
		}
		return errors.New("bad block")
	}
	if err := b.Phase(context.Background(), "interfaces", run); err == nil {
		t.Fatal("phase failure lost")
	}
	if len(b.Interfaces()) != 0 || c.Evidence()[0].State != fm.Pending {
		t.Fatal("phase rollback not atomic")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := b.Phase(ctx, "interfaces", run); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
func TestContentBoundsAndMultilineTokenSource(t *testing.T) {
	if _, err := config.NewContent(context.Background(), config.Source{Text: strings.Repeat("x", 12)}, config.Limits{MaxBytes: 8}); err == nil {
		t.Fatal("byte limit ignored")
	}
	c := source(t, "banner \"hello\ninterface eth0\nworld\"\ninterface eth1\n")
	statements, err := config.Statements(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if len(statements) != 2 || statements[0].Span.Last != 3 || statements[1].Words[1] != "eth1" {
		t.Fatal(statements)
	}
	if _, err := config.Statements(context.Background(), source(t, "banner \"broken\n")); err == nil {
		t.Fatal("unterminated quote accepted")
	}
}

func TestNativeBlocksKeepUnknownScopesAndUnclaimedChildren(t *testing.T) {
	c := source(t, "admin user\nrule 10\nexit\ninterface eth0\nunknown option\nexit\n")
	classify := func(s config.Statement, path []string) (config.Boundary, string) {
		if len(s.Words) == 0 {
			return config.Member, ""
		}
		if s.Words[0] == "exit" {
			return config.CloseBlock, ""
		}
		if len(path) == 0 && (s.Words[0] == "admin" || s.Words[0] == "interface") {
			return config.OpenBlock, s.Words[0]
		}
		return config.Member, ""
	}
	doc, err := config.Blocks(context.Background(), c, classify)
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Roots) != 2 || doc.Roots[0].Members[0].Words[0] != "rule" {
		t.Fatal("unknown scope leaked", doc)
	}
	b, err := config.NewBuilder(c, fm.Metadata{})
	if err != nil {
		t.Fatal(err)
	}
	tx := b.Begin()
	tx.Parse(doc.Roots[1].Header.Lines()...)
	tx.Parse(doc.Roots[1].End.Lines()...)
	if err := b.Commit(tx); err != nil {
		t.Fatal(err)
	}
	if c.Evidence()[4].State != fm.Pending {
		t.Fatal("parent swallowed unrecognized member")
	}
	broken, err := config.Blocks(context.Background(), source(t, "interface eth0\n"), classify)
	if err != nil || len(broken.Diagnostics) != 1 {
		t.Fatal(broken, err)
	}
}

func TestPhysicalLinesRetainIndentationOffsetsAndSourceDigest(t *testing.T) {
	raw := "  interface eth0\r\n\tzone trust\r# note\nexit"
	c := source(t, raw)
	parts := []string{"  interface eth0\r\n", "\tzone trust\r", "# note\n", "exit"}
	if len(c.Lines()) != len(parts) {
		t.Fatal("wrong physical line count")
	}
	end := 0
	for i, line := range c.Lines() {
		if line.Number != i+1 || line.StartByte != end || line.Raw != parts[i] {
			t.Fatalf("line %d: %+v", i+1, line)
		}
		end += len(parts[i])
		if line.EndByte != end || line.Text != strings.TrimRight(parts[i], "\r\n") {
			t.Fatalf("line boundary or indentation changed: %+v", line)
		}
	}
	if end != len(raw) {
		t.Fatal("missing physical lines")
	}
	lines := c.Lines()
	lines[0].Raw = "changed"
	if c.Lines()[0].Raw != parts[0] {
		t.Fatal("mutable source lines escaped")
	}
	b, err := config.NewBuilder(c, fm.Metadata{})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := b.Metadata().SourceDigest, fmt.Sprintf("%x", sha256.Sum256([]byte(raw))); got != want {
		t.Fatalf("source digest = %s, want %s", got, want)
	}
}
