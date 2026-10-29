package config_test

import (
	"context"
	"errors"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
)

func TestNewSessionRejectsNilCursor(t *testing.T) {
	s, err := config.NewSession(nil, fm.Metadata{})
	if s != nil || !errors.Is(err, config.ErrInvalid) {
		t.Fatalf("nil cursor: session=%v, error=%v", s, err)
	}
}

func TestSessionRejectsForeignTransactionWithoutClosingItsOwner(t *testing.T) {
	c := source(t, "owner\n")
	s, err := config.NewSession(c, fm.Metadata{})
	if err != nil {
		t.Fatal(err)
	}
	other, err := config.NewSession(source(t, "other\n"), fm.Metadata{})
	if err != nil {
		t.Fatal(err)
	}
	tx := s.Cursor().Begin()
	tx.Parse(1)
	tx.Emit(fm.Data{Addresses: []fm.AddressRecord{{Object: fm.Object{ID: "owned"}}}})
	if err := other.Commit(tx); !errors.Is(err, config.ErrClaim) {
		t.Fatalf("foreign transaction: %v", err)
	}
	if other.Data().Evidence[0].State != fm.Pending || len(other.Data().Addresses) != 0 || c.Evidence()[0].State != fm.Pending {
		t.Fatal("foreign commit changed data or source evidence")
	}
	if err := s.Commit(tx); err != nil {
		t.Fatalf("foreign rejection closed the owner's transaction: %v", err)
	}
	if err := s.Commit(tx); !errors.Is(err, config.ErrClosed) {
		t.Fatalf("second ownership transfer: %v", err)
	}
	if len(s.Data().Addresses) != 1 || c.Evidence()[0].State != fm.Parsed {
		t.Fatal("owner did not transfer data and evidence exactly once")
	}
}

func TestInvalidTransactionCannotCommit(t *testing.T) {
	for _, tx := range []*config.Transaction{nil, new(config.Transaction)} {
		var dst fm.Data
		if err := tx.Commit(&dst); !errors.Is(err, config.ErrClaim) {
			t.Fatalf("invalid transaction: %v", err)
		}
		if len(dst.Addresses) != 0 {
			t.Fatal("invalid transaction changed destination")
		}
	}
}

func TestInvalidSessionCannotRunOrCommit(t *testing.T) {
	for _, s := range []*config.Session{nil, new(config.Session)} {
		if err := s.Commit(nil); !errors.Is(err, config.ErrInvalid) {
			t.Fatalf("invalid session commit: %v", err)
		}
		called := false
		err := s.Run(context.Background(), []config.Stage{{Name: "unused", Run: func(context.Context, *config.Session) error {
			called = true
			return nil
		}}})
		if !errors.Is(err, config.ErrInvalid) || called {
			t.Fatalf("invalid session run: called=%v error=%v", called, err)
		}
	}
}
