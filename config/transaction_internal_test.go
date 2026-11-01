package config

import (
	"context"
	"errors"
	fm "github.com/gatework/firemon"
	"testing"
)

func testBuilder(t *testing.T, raw string) *Builder {
	t.Helper()
	c, err := NewContent(context.Background(), Source{Text: raw, Complete: true}, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewBuilder(c, fm.Metadata{})
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func TestBuilderRejectsNilTransactionWithoutChangingEvidence(t *testing.T) {
	b := testBuilder(t, "a\n")
	if err := b.Commit(nil); !errors.Is(err, ErrClaim) {
		t.Fatal(err)
	}
	if b.Content().Evidence()[0].State != fm.Pending || len(b.Addresses()) != 0 {
		t.Fatal("invalid transaction changed builder")
	}
}
func TestClosedTransactionCannotAccumulateEffects(t *testing.T) {
	b := testBuilder(t, "a\n")
	tx := b.Begin()
	tx.Parse(1)
	tx.Emit(fm.Data{Addresses: []fm.AddressRecord{{Object: fm.Object{ID: "a"}}}})
	if err := b.Commit(tx); err != nil {
		t.Fatal(err)
	}
	if len(tx.draft.Addresses) != 0 {
		t.Fatal("moved draft retained")
	}
	tx.Emit(fm.Data{Addresses: []fm.AddressRecord{{Object: fm.Object{ID: "b"}}}})
	tx.Replace(fm.Data{Addresses: []fm.AddressRecord{{Object: fm.Object{ID: "a"}}}})
	tx.Parse(1)
	tx.Ignore("closed", 1)
	if len(tx.draft.Addresses) != 0 || len(tx.replacements.Addresses) != 0 || len(tx.claims) != 0 {
		t.Fatal("closed transaction accumulated effects")
	}
	if !errors.Is(b.Commit(tx), ErrClosed) {
		t.Fatal("closed commit accepted")
	}
}
func TestCanceledPhaseRestoresPriorDataEvidenceAndPosition(t *testing.T) {
	b := testBuilder(t, "a\nb\n")
	c := b.Content()
	first := b.Begin()
	first.Parse(1)
	first.Emit(fm.Data{Addresses: []fm.AddressRecord{{Object: fm.Object{ID: "a"}}}})
	if err := b.Commit(first); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	err := b.Phase(ctx, "cancel", func(_ context.Context, b *Builder) error {
		b.Content().NextPending()
		tx := b.Begin()
		tx.Parse(2)
		tx.Emit(fm.Data{Addresses: []fm.AddressRecord{{Object: fm.Object{ID: "b"}}}})
		if err := b.Commit(tx); err != nil {
			return err
		}
		cancel()
		return nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	d := b.Data()
	if len(d.Addresses) != 1 || d.Addresses[0].ID != "a" || d.Evidence[0].State != fm.Parsed || d.Evidence[1].State != fm.Pending {
		t.Fatal(d)
	}
	line, _ := c.Peek()
	if line.Number != 1 {
		t.Fatal(line)
	}
	if _, ok := b.Address("b"); ok {
		t.Fatal("canceled identity still indexed")
	}
}
func TestTransactionAndBuilderRetainCopyIsolation(t *testing.T) {
	b := testBuilder(t, "a\n")
	d := fm.Data{Addresses: []fm.AddressRecord{{Object: fm.Object{ID: "a", Unsupported: []string{"original"}}}}}
	tx := b.Begin()
	tx.Parse(1)
	tx.Emit(d)
	d.Addresses[0].Unsupported[0] = "producer mutation"
	if err := b.Commit(tx); err != nil {
		t.Fatal(err)
	}
	exported := b.Data()
	exported.Addresses[0].Unsupported[0] = "reader mutation"
	if b.Data().Addresses[0].Unsupported[0] != "original" {
		t.Fatal("mutable alias escaped")
	}
}
func TestNestedPhaseRollbackRetainsOuterUndo(t *testing.T) {
	b := testBuilder(t, "a\nb\n")
	c := b.Content()
	err := b.Phase(context.Background(), "outer", func(ctx context.Context, b *Builder) error {
		tx := b.Begin()
		tx.Parse(1)
		if err := b.Commit(tx); err != nil {
			return err
		}
		if err := b.Phase(ctx, "inner", func(context.Context, *Builder) error { tx := b.Begin(); tx.Parse(2); return b.Commit(tx) }); err != nil {
			return err
		}
		return errors.New("outer failure")
	})
	if err == nil || c.Evidence()[0].State != fm.Pending || c.Evidence()[1].State != fm.Pending {
		t.Fatal("nested phase lost outer rollback", err, c.Evidence())
	}
}
func TestTransactionCannotEscapeItsPhase(t *testing.T) {
	b := testBuilder(t, "a\n")
	var tx *Transaction
	if err := b.Phase(context.Background(), "owner", func(context.Context, *Builder) error { tx = b.Begin(); tx.Parse(1); return nil }); err != nil {
		t.Fatal(err)
	}
	if err := b.Commit(tx); !errors.Is(err, ErrClaim) {
		t.Fatal("escaped transaction accepted", err)
	}
	if b.Content().Evidence()[0].State != fm.Pending {
		t.Fatal("escaped claim consumed")
	}
}
