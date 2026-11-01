package config_test

import (
	"context"
	"errors"
	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
	"reflect"
	"testing"
)

func TestDuplicateRecordCannotClaimSource(t *testing.T) {
	c := source(t, "first\nsecond\n")
	b, err := config.NewBuilder(c, fm.Metadata{Device: "test", Vendor: "test"})
	if err != nil {
		t.Fatal(err)
	}
	first := b.Begin()
	first.Parse(1)
	first.Emit(fm.Data{Addresses: []fm.AddressRecord{{Object: fm.Object{ID: "a"}}}})
	if err := b.Commit(first); err != nil {
		t.Fatal(err)
	}
	duplicate := b.Begin()
	duplicate.Parse(2)
	duplicate.Emit(fm.Data{Addresses: []fm.AddressRecord{{Object: fm.Object{ID: "a"}}}})
	if err := b.Commit(duplicate); err == nil {
		t.Fatal("duplicate record accepted and source claimed")
	}
	if len(b.Data().Addresses) != 1 || c.Evidence()[1].State != fm.Pending {
		t.Fatal("failed record validation changed records or evidence")
	}
}

func TestReplaceRetainsOrderAndRollbackRestoresIndexAndGraph(t *testing.T) {
	c := source(t, "a\nb\nchange\n")
	b, _ := config.NewBuilder(c, fm.Metadata{Device: "test", Vendor: "test"})
	tx := b.Begin()
	tx.Parse(1, 2)
	tx.Emit(fm.Data{Addresses: []fm.AddressRecord{{Object: fm.Object{ID: "a", Name: "original"}}, {Object: fm.Object{ID: "b"}}}})
	if err := b.Commit(tx); err != nil {
		t.Fatal(err)
	}
	before, err := b.Seal()
	if err != nil {
		t.Fatal(err)
	}
	err = b.Phase(context.Background(), "failed-reopen", func(_ context.Context, b *config.Builder) error {
		change := b.Begin()
		change.Replace(fm.Data{Addresses: []fm.AddressRecord{{Object: fm.Object{ID: "a", Name: "changed"}}}})
		change.Emit(fm.Data{Addresses: []fm.AddressRecord{{Object: fm.Object{ID: "c"}}}})
		change.Parse(3)
		if err := b.Commit(change); err != nil {
			return err
		}
		changed, err := b.Seal()
		if err != nil {
			return err
		}
		if changed == before {
			t.Fatal("stale graph after replacement")
		}
		return errors.New("failed after commit")
	})
	if err == nil {
		t.Fatal("phase error lost")
	}
	a, ok := b.Address("a")
	if !ok || a.Name != "original" {
		t.Fatal("replacement did not roll back", a)
	}
	if _, ok := b.Address("c"); ok {
		t.Fatal("rolled-back index entry remains")
	}
	restored, err := b.Seal()
	if err != nil || restored != before {
		t.Fatal("cached graph was not restored", err)
	}
	if c.Evidence()[2].State != fm.Pending {
		t.Fatal("source claim did not roll back")
	}
	change := b.Begin()
	change.Replace(fm.Data{Addresses: []fm.AddressRecord{{Object: fm.Object{ID: "a", Name: "final"}}}})
	change.Parse(3)
	if err := b.Commit(change); err != nil {
		t.Fatal(err)
	}
	got := b.Addresses()
	if len(got) != 2 || got[0].ID != "a" || got[0].Name != "final" || got[1].ID != "b" {
		t.Fatal("replacement changed order", got)
	}
}

func TestBuilderAccessorsDoNotExposeMutableRecords(t *testing.T) {
	b, _ := config.NewBuilder(source(t, "a\n"), fm.Metadata{})
	tx := b.Begin()
	tx.Emit(fm.Data{Addresses: []fm.AddressRecord{{Object: fm.Object{ID: "a", Unsupported: []string{"original"}}}}})
	if err := b.Commit(tx); err != nil {
		t.Fatal(err)
	}
	a, _ := b.Address("a")
	a.Unsupported[0] = "lookup mutation"
	all := b.Addresses()
	all[0].Unsupported[0] = "list mutation"
	if got, _ := b.Address("a"); got.Unsupported[0] != "original" {
		t.Fatal(got)
	}
}

func TestReplacementValidationPrecedesAllChanges(t *testing.T) {
	b, _ := config.NewBuilder(source(t, "a\n"), fm.Metadata{})
	for _, d := range []fm.Data{
		{Addresses: []fm.AddressRecord{{Object: fm.Object{ID: "missing"}}}},
		{Addresses: []fm.AddressRecord{{Object: fm.Object{ID: ""}}}},
	} {
		tx := b.Begin()
		tx.Parse(1)
		tx.Emit(fm.Data{Services: []fm.ServiceRecord{{Object: fm.Object{ID: "accepted-only-on-success"}}}})
		tx.Replace(d)
		if err := b.Commit(tx); !errors.Is(err, fm.ErrGraph) {
			t.Fatal("invalid replacement", err)
		}
		if b.Content().Evidence()[0].State != fm.Pending || len(b.Services()) != 0 {
			t.Fatal("partial commit")
		}
	}
}

func TestContentHasOneBuilderOwner(t *testing.T) {
	c := source(t, "a\n")
	if _, err := config.NewBuilder(c, fm.Metadata{}); err != nil {
		t.Fatal(err)
	}
	if _, err := config.NewBuilder(c, fm.Metadata{}); !errors.Is(err, config.ErrInvalid) {
		t.Fatal("shared mutable source owner", err)
	}
}

func TestNestedReplacementRollbackRestoresOuterReplacement(t *testing.T) {
	b, _ := config.NewBuilder(source(t, "a\nb\nc\n"), fm.Metadata{})
	tx := b.Begin()
	tx.Emit(fm.Data{Addresses: []fm.AddressRecord{{Object: fm.Object{ID: "a", Name: "original"}}}})
	tx.Parse(1)
	if err := b.Commit(tx); err != nil {
		t.Fatal(err)
	}
	err := b.Phase(context.Background(), "outer", func(ctx context.Context, b *config.Builder) error {
		tx := b.Begin()
		tx.Replace(fm.Data{Addresses: []fm.AddressRecord{{Object: fm.Object{ID: "a", Name: "outer"}}}})
		tx.Parse(2)
		if err := b.Commit(tx); err != nil {
			return err
		}
		err := b.Phase(ctx, "inner", func(_ context.Context, b *config.Builder) error {
			tx := b.Begin()
			tx.Replace(fm.Data{Addresses: []fm.AddressRecord{{Object: fm.Object{ID: "a", Name: "inner"}}}})
			tx.Parse(3)
			if err := b.Commit(tx); err != nil {
				return err
			}
			return errors.New("inner")
		})
		if err == nil {
			t.Fatal("inner error lost")
		}
		a, _ := b.Address("a")
		if a.Name != "outer" {
			t.Fatal(a)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	a, _ := b.Address("a")
	if a.Name != "outer" {
		t.Fatal(a)
	}
	if got := b.Content().Evidence(); !reflect.DeepEqual([]fm.LineState{got[0].State, got[1].State, got[2].State}, []fm.LineState{fm.Parsed, fm.Parsed, fm.Pending}) {
		t.Fatal(got)
	}
}

func TestBuilderMembershipAndEvidenceInvalidateCachedGraph(t *testing.T) {
	b, _ := config.NewBuilder(source(t, "a\n"), fm.Metadata{Device: "test", Vendor: "test"})
	if b.HasAddress("a") || b.HasAddressGroup("a") || b.HasService("a") || b.HasServiceGroup("a") {
		t.Fatal("empty catalogs contain objects")
	}
	tx := b.Begin()
	tx.Emit(fm.Data{Addresses: []fm.AddressRecord{{Object: fm.Object{ID: "a"}}}})
	if err := b.Commit(tx); err != nil {
		t.Fatal(err)
	}
	if !b.HasAddress("a") || b.HasAddressGroup("a") {
		t.Fatal("typed membership is ambiguous")
	}
	before, err := b.Seal()
	if err != nil {
		t.Fatal(err)
	}
	cached, err := b.Seal()
	if err != nil || cached != before {
		t.Fatal("unchanged graph not reused", err)
	}
	tx = b.Begin()
	tx.Ignore("known unrelated synthetic declaration", 1)
	if err := b.Commit(tx); err != nil {
		t.Fatal(err)
	}
	after, err := b.Seal()
	if err != nil {
		t.Fatal(err)
	}
	if before == after || before.Complete() || !after.Complete() {
		t.Fatal("evidence-only commit reused stale graph")
	}
}
