package config_test

import (
	"context"
	"errors"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
)

func serviceCapacityBuilder(t *testing.T, limit int) *config.Builder {
	t.Helper()
	c, err := config.NewContent(t.Context(), config.Source{Text: "first\nsecond\nthird\n", Complete: true}, config.Limits{MaxServiceTerms: limit})
	if err != nil {
		t.Fatal(err)
	}
	b, err := config.NewBuilder(c, fm.Metadata{})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func serviceCapacityData(id fm.ID, count int) fm.Data {
	return fm.Data{Services: []fm.ServiceRecord{{Object: fm.Object{ID: id}, Terms: make([]fm.ServiceTerm, count)}}}
}

func TestServiceCapacityIncludesPreviouslyCommittedRecords(t *testing.T) {
	b := serviceCapacityBuilder(t, 3)
	first := b.Begin()
	first.Parse(1)
	first.Emit(serviceCapacityData("first", 2))
	if err := b.Commit(first); err != nil {
		t.Fatal(err)
	}
	second := b.Begin()
	second.Parse(2)
	second.Emit(serviceCapacityData("second", 2))
	if err := b.Commit(second); !errors.Is(err, config.ErrSource) {
		t.Fatalf("catalog exceeded service capacity: %v", err)
	}
	if b.HasService("second") || b.Content().Evidence()[1].State != fm.Pending || len(b.Services()) != 1 {
		t.Fatal("capacity failure published a partial record or source claim")
	}
}

func TestPendingServiceCapacityPrecedesIdentityValidation(t *testing.T) {
	for _, replace := range []bool{false, true} {
		t.Run(map[bool]string{false: "emit", true: "replace"}[replace], func(t *testing.T) {
			b := serviceCapacityBuilder(t, 3)
			tx := b.Begin()
			tx.Parse(1)
			tx.Emit(serviceCapacityData("first", 2))
			// This second submission exceeds the pending capacity even though its
			// identity is also invalid. Capacity must be checked before accepting it.
			if replace {
				tx.Replace(serviceCapacityData("absent", 2))
			} else {
				tx.Emit(serviceCapacityData("", 2))
			}
			if err := b.Commit(tx); !errors.Is(err, config.ErrSource) {
				t.Fatalf("pending capacity was not enforced first: %v", err)
			}
			if len(b.Services()) != 0 || b.Content().Evidence()[0].State != fm.Pending {
				t.Fatal("failed pending transaction published data or evidence")
			}
		})
	}
}

func TestServiceCapacityReplacementAndCanceledNestedPhase(t *testing.T) {
	b := serviceCapacityBuilder(t, 4)
	first := b.Begin()
	first.Parse(1)
	first.Emit(serviceCapacityData("first", 3))
	if err := b.Commit(first); err != nil {
		t.Fatal(err)
	}
	// The final catalog fits even when additions are submitted before a
	// replacement that releases capacity. Capacity is not cumulative work.
	change := b.Begin()
	change.Parse(2)
	change.Emit(serviceCapacityData("second", 2))
	change.Replace(serviceCapacityData("first", 2))
	if err := b.Commit(change); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	err := b.Phase(ctx, "outer", func(ctx context.Context, b *config.Builder) error {
		if err := b.Phase(ctx, "inner", func(_ context.Context, b *config.Builder) error {
			tx := b.Begin()
			tx.Parse(3)
			tx.Replace(serviceCapacityData("first", 1))
			return b.Commit(tx)
		}); err != nil {
			return err
		}
		cancel()
		return nil
	})
	if !errors.Is(err, context.Canceled) || b.Content().Evidence()[2].State != fm.Pending {
		t.Fatalf("canceled phase did not restore evidence: %v", err)
	}
	if record, ok := b.Service("first"); !ok || len(record.Terms) != 2 {
		t.Fatal("canceled replacement changed the accepted catalog")
	}
	full := b.Begin()
	full.Emit(serviceCapacityData("third", 1))
	if err := b.Commit(full); !errors.Is(err, config.ErrSource) {
		t.Fatalf("canceled replacement leaked capacity: %v", err)
	}
	shrink := b.Begin()
	shrink.Replace(serviceCapacityData("first", 1))
	if err := b.Commit(shrink); err != nil {
		t.Fatal(err)
	}
	last := b.Begin()
	last.Parse(3)
	last.Emit(serviceCapacityData("third", 1))
	if err := b.Commit(last); err != nil || !b.HasService("third") {
		t.Fatalf("replacement did not release capacity: %v", err)
	}
}

func TestServiceCapacityPhaseFailureRestoresAcceptedCapacity(t *testing.T) {
	b := serviceCapacityBuilder(t, 2)
	err := b.Phase(t.Context(), "services", func(_ context.Context, b *config.Builder) error {
		first := b.Begin()
		first.Parse(1)
		first.Emit(serviceCapacityData("first", 2))
		if err := b.Commit(first); err != nil {
			return err
		}
		second := b.Begin()
		second.Parse(2)
		second.Emit(serviceCapacityData("second", 1))
		return b.Commit(second)
	})
	if !errors.Is(err, config.ErrSource) || len(b.Services()) != 0 {
		t.Fatalf("capacity failure did not roll back the phase: %v", err)
	}
	for _, evidence := range b.Content().Evidence() {
		if evidence.State != fm.Pending {
			t.Fatal("capacity failure retained a source claim")
		}
	}
	retry := b.Begin()
	retry.Parse(1)
	retry.Emit(serviceCapacityData("first", 2))
	if err := b.Commit(retry); err != nil {
		t.Fatalf("failed phase retained accepted capacity: %v", err)
	}
}
