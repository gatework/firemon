package config

import (
	"context"
	"errors"
	"testing"

	fm "github.com/gatework/firemon"
)

func TestClosedTransactionCannotAccumulateEffects(t *testing.T) {
	c, _ := NewCursor(Source{Text: "a\n", Complete: true}, Limits{})
	tx := c.Begin()
	tx.Emit(fm.Data{Addresses: []fm.AddressRecord{{Object: fm.Object{ID: "a"}}}})
	tx.Parse(1)
	var dst fm.Data
	if err := tx.Commit(&dst); err != nil {
		t.Fatal(err)
	}
	if len(tx.draft.Addresses) != 0 {
		t.Fatal("moved draft retained")
	}
	tx.Emit(fm.Data{Addresses: []fm.AddressRecord{{Object: fm.Object{ID: "b"}}}})
	tx.Parse(1)
	tx.Ignore("closed", 1)
	if len(tx.draft.Addresses) != 0 || len(tx.claims) != 0 {
		t.Fatal("closed transaction accumulated effects")
	}
	if !errors.Is(tx.Commit(&dst), ErrClosed) {
		t.Fatal("closed commit accepted")
	}
}

func TestCanceledStageRestoresPriorDataEvidenceAndPosition(t *testing.T) {
	c, _ := NewCursor(Source{Text: "a\nb\n", Complete: true}, Limits{})
	s, err := NewSession(c, fm.Metadata{})
	if err != nil {
		t.Fatal(err)
	}
	first := c.Begin()
	first.Parse(1)
	first.Emit(fm.Data{Addresses: []fm.AddressRecord{{Object: fm.Object{ID: "a"}}}})
	if err := s.Commit(first); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	err = s.Run(ctx, []Stage{{Name: "cancel", Run: func(_ context.Context, s *Session) error {
		s.Cursor().NextPending()
		tx := s.Cursor().Begin()
		tx.Parse(2)
		tx.Emit(fm.Data{Addresses: []fm.AddressRecord{{Object: fm.Object{ID: "b"}}}})
		if err := s.Commit(tx); err != nil {
			return err
		}
		cancel()
		return nil
	}}})
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	d := s.Data()
	if len(d.Addresses) != 1 || d.Addresses[0].ID != "a" || d.Evidence[0].State != fm.Parsed || d.Evidence[1].State != fm.Pending {
		t.Fatal(d)
	}
	line, _ := c.Peek()
	if line.Number != 1 {
		t.Fatal(line)
	}
}

func TestTransactionAndSessionRetainCopyIsolation(t *testing.T) {
	c, _ := NewCursor(Source{Text: "a\n", Complete: true}, Limits{})
	s, err := NewSession(c, fm.Metadata{})
	if err != nil {
		t.Fatal(err)
	}
	d := fm.Data{Addresses: []fm.AddressRecord{{Object: fm.Object{ID: "a", Unsupported: []string{"original"}}}}}
	tx := c.Begin()
	tx.Parse(1)
	tx.Emit(d)
	d.Addresses[0].Unsupported[0] = "producer mutation"
	if err := s.Commit(tx); err != nil {
		t.Fatal(err)
	}
	exported := s.Data()
	exported.Addresses[0].Unsupported[0] = "reader mutation"
	if s.Data().Addresses[0].Unsupported[0] != "original" {
		t.Fatal("mutable alias escaped")
	}
}

func TestNestedStageRollbackRetainsOuterUndo(t *testing.T) {
	c, _ := NewCursor(Source{Text: "a\nb\n", Complete: true}, Limits{})
	s, err := NewSession(c, fm.Metadata{})
	if err != nil {
		t.Fatal(err)
	}
	err = s.Run(context.Background(), []Stage{{Name: "outer", Run: func(ctx context.Context, s *Session) error {
		tx := c.Begin()
		tx.Parse(1)
		if err := s.Commit(tx); err != nil {
			return err
		}
		if err := s.Run(ctx, []Stage{{Name: "inner", Run: func(context.Context, *Session) error { tx := c.Begin(); tx.Parse(2); return s.Commit(tx) }}}); err != nil {
			return err
		}
		return errors.New("outer failure")
	}}})
	if err == nil || c.Evidence()[0].State != fm.Pending || c.Evidence()[1].State != fm.Pending {
		t.Fatal("nested stage lost outer evidence rollback", err, c.Evidence())
	}
}
