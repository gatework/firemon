package config_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
)

func source(t *testing.T, s string) *config.Cursor {
	t.Helper()
	c, err := config.NewCursor(config.Source{Text: s, Complete: true}, config.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	return c
}
func TestSkipAndRewindKeepPendingWhileCommitIsAtomic(t *testing.T) {
	c := source(t, "interface eth0\nrule 1\n")
	d := fm.Data{}
	line, ok := c.NextPending()
	if !ok || line.Number != 1 {
		t.Fatal(line)
	}
	c.Rewind()
	line, _ = c.NextPending()
	if line.Number != 1 {
		t.Fatal("skipped line was consumed")
	}
	tx := c.Begin()
	tx.Emit(fm.Data{Interfaces: []fm.InterfaceRecord{{Object: fm.Object{ID: "eth0"}}}})
	tx.Parse(1)
	if err := tx.Commit(&d); err != nil {
		t.Fatal(err)
	}
	c.Rewind()
	line, _ = c.NextPending()
	if line.Number != 2 {
		t.Fatal("committed line remained pending")
	}
	failed := c.Begin()
	failed.Emit(fm.Data{Rules: []fm.RuleRecord{{Object: fm.Object{ID: "r1"}}}})
	failed.Parse(2, 1)
	if err := failed.Commit(&d); err == nil {
		t.Fatal("duplicate claim accepted")
	}
	if len(d.Rules) != 0 || c.Evidence()[1].State != fm.Pending {
		t.Fatal("failed commit leaked draft or evidence")
	}
}
func TestRollbackRestoresPositionAndKnownIgnoreRequiresReason(t *testing.T) {
	c := source(t, "a\nb\n")
	d := fm.Data{}
	tx := c.Begin()
	c.NextPending()
	tx.Parse(1)
	tx.Rollback()
	line, _ := c.Peek()
	if line.Number != 1 {
		t.Fatal("rollback position")
	}
	tx = c.Begin()
	tx.Ignore("", 1)
	if err := tx.Commit(&d); err == nil {
		t.Fatal("unexplained ignore")
	}
	tx = c.Begin()
	tx.Ignore("blank/comment", 1)
	if err := tx.Commit(&d); err != nil {
		t.Fatal(err)
	}
	c.Rewind()
	line, _ = c.NextPending()
	if line.Number != 2 {
		t.Fatal(line)
	}
}
func TestStagesValidateDependenciesAndRollbackFailedStage(t *testing.T) {
	c := source(t, "interface eth0\n")
	s := config.NewSession(c, fm.Metadata{Device: "test", Vendor: "test"})
	stages := []config.Stage{{Name: "interfaces", Run: func(ctx context.Context, s *config.Session) error {
		tx := s.Cursor.Begin()
		tx.Parse(1)
		tx.Emit(fm.Data{Interfaces: []fm.InterfaceRecord{{Object: fm.Object{ID: "eth0"}}}})
		if err := s.Commit(tx); err != nil {
			return err
		}
		return errors.New("bad block")
	}}}
	if err := s.Run(context.Background(), stages); err == nil {
		t.Fatal("stage failure lost")
	}
	if len(s.Data().Interfaces) != 0 || c.Evidence()[0].State != fm.Pending {
		t.Fatal("stage rollback not atomic")
	}
	called := false
	err := s.Run(context.Background(), []config.Stage{{Name: "routes", Requires: []string{"interfaces"}, Run: func(context.Context, *config.Session) error { called = true; return nil }}})
	if err == nil || called {
		t.Fatal("invalid stage graph executed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err = s.Run(ctx, stages); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
func TestCursorBoundsAndMultilineTokenSource(t *testing.T) {
	if _, err := config.NewCursor(config.Source{Text: strings.Repeat("x", 12)}, config.Limits{MaxBytes: 8}); err == nil {
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
	tx := c.Begin()
	tx.Parse(doc.Roots[1].Header.Lines()...)
	tx.Parse(doc.Roots[1].End.Lines()...)
	d := fm.Data{}
	if err := tx.Commit(&d); err != nil {
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

func TestFragmentCursorClaimsExactBytesWithinSamePhysicalLine(t *testing.T) {
	raw := "<known>x</known><unknown>y</unknown>"
	split := len("<known>x</known>")
	c, err := config.NewFragmentCursor(config.Source{Text: raw, Complete: true}, []fm.Span{{First: 1, Last: 1, StartByte: 0, EndByte: split}, {First: 1, Last: 1, StartByte: split, EndByte: len(raw)}}, config.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	d := fm.Data{}
	tx := c.Begin()
	tx.Parse(1)
	tx.Emit(fm.Data{Addresses: []fm.AddressRecord{{Object: fm.Object{ID: "known"}}}})
	if err := tx.Commit(&d); err != nil {
		t.Fatal(err)
	}
	evidence := c.Evidence()
	if evidence[0].Span.EndByte != split || evidence[1].State != fm.Pending || evidence[1].Span.StartByte != split {
		t.Fatal("same-line unknown syntax was claimed", evidence)
	}
	tx = c.Begin()
	tx.Parse(2, 1)
	if err := tx.Commit(&d); err == nil || c.Evidence()[1].State != fm.Pending {
		t.Fatal("fragment rollback leaked source claim")
	}
	if _, err := config.NewFragmentCursor(config.Source{Text: raw}, []fm.Span{{First: 1, Last: 1, StartByte: 1, EndByte: len(raw)}}, config.Limits{}); err == nil {
		t.Fatal("unclaimed byte gap accepted")
	}
}
