package deploy_test

import (
	"context"
	"errors"
	"github.com/gatework/firemon/deploy"
	"testing"
	"time"
)

func TestFileJournalOwnsOperationAcrossInstancesAndRestoresReceipts(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	a, err := deploy.OpenJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	l, err := a.Acquire(ctx, "op/unsafe-path")
	if err != nil {
		t.Fatal(err)
	}
	r, err := l.Save(ctx, deploy.Record{ID: "op/unsafe-path", Device: "fw", Phase: deploy.WriteIntent, WriteStarted: true, Receipts: []deploy.Receipt{{Phase: "apply", Index: 0, Written: true}}})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := deploy.OpenJournal(dir)
	short, cancel := context.WithTimeout(ctx, 30*time.Millisecond)
	defer cancel()
	if _, err := b.Acquire(short, r.ID); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("operation lock bypassed", err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	restored, err := b.Acquire(ctx, r.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	got, err := restored.Load(ctx)
	if err != nil || got.Sequence != 1 || !got.WriteStarted || len(got.Receipts) != 1 {
		t.Fatal("durable receipts lost", got, err)
	}
	r.Sequence = 0
	if _, err := restored.Save(ctx, r); !errors.Is(err, deploy.ErrJournalConflict) {
		t.Fatal("stale record replaced intent", err)
	}
}
