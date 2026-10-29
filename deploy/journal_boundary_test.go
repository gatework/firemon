package deploy_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/gatework/firemon/deploy"
)

func TestJournalCancellationPrecedesValidation(t *testing.T) {
	journal, err := deploy.OpenJournal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := journal.Acquire(ctx, ""); !errors.Is(err, context.Canceled) {
		t.Fatalf("acquire: %v", err)
	}
	lease, err := journal.Acquire(context.Background(), "op")
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	if _, err := lease.Save(ctx, deploy.Record{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("save: %v", err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := lease.Load(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("closed load: %v", err)
	}
}

func TestJournalRejectsEmptyRoot(t *testing.T) {
	t.Chdir(t.TempDir())
	if _, err := deploy.OpenJournal(""); !errors.Is(err, deploy.ErrInvalid) {
		t.Fatalf("empty journal root: %v", err)
	}
}

func TestJournalDistinguishesCorruptionFromConflict(t *testing.T) {
	dir := t.TempDir()
	journal, err := deploy.OpenJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := journal.Acquire(context.Background(), "op")
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	if _, err := lease.Save(context.Background(), deploy.Record{ID: "op", Device: "fw"}); err != nil {
		t.Fatal(err)
	}
	files, err := filepath.Glob(filepath.Join(dir, "*.gob"))
	if err != nil || len(files) != 1 {
		t.Fatal(files, err)
	}
	if err := os.WriteFile(files[0], []byte("truncated"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := lease.Load(context.Background()); !errors.Is(err, deploy.ErrJournalFormat) || errors.Is(err, deploy.ErrJournalConflict) {
		t.Fatalf("corrupt journal: %v", err)
	}
	if _, err := lease.Save(context.Background(), deploy.Record{ID: "op", Device: "fw"}); !errors.Is(err, deploy.ErrJournalFormat) {
		t.Fatalf("corrupt journal overwritten: %v", err)
	}
}
func TestZeroJournalsRejectAcquire(t *testing.T) {
	for _, journal := range []*deploy.FileJournal{nil, {}} {
		if _, err := journal.Acquire(context.Background(), "op"); !errors.Is(err, deploy.ErrInvalid) {
			t.Fatal(err)
		}
	}
}
