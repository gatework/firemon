package config_test

import (
	"context"
	"errors"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
)

func TestNewBuilderRejectsNilContent(t *testing.T) {
	s, err := config.NewBuilder(nil, fm.Metadata{})
	if s != nil || !errors.Is(err, config.ErrInvalid) {
		t.Fatalf("nil cursor: session=%v, error=%v", s, err)
	}
}

func TestBuilderRejectsForeignTransactionWithoutClosingItsOwner(t *testing.T) {
	c := source(t, "owner\n")
	s, err := config.NewBuilder(c, fm.Metadata{})
	if err != nil {
		t.Fatal(err)
	}
	other, err := config.NewBuilder(source(t, "other\n"), fm.Metadata{})
	if err != nil {
		t.Fatal(err)
	}
	tx := s.Begin()
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
	b, _ := config.NewBuilder(source(t, "pending\n"), fm.Metadata{})
	for _, tx := range []*config.Transaction{nil, new(config.Transaction)} {
		if err := b.Commit(tx); !errors.Is(err, config.ErrClaim) {
			t.Fatal(err)
		}
		if len(b.Addresses()) != 0 || b.Content().Evidence()[0].State != fm.Pending {
			t.Fatal("invalid transaction changed builder")
		}
	}
}
func TestInvalidBuilderCannotRunOrCommit(t *testing.T) {
	for _, b := range []*config.Builder{nil, new(config.Builder)} {
		if err := b.Commit(nil); !errors.Is(err, config.ErrInvalid) {
			t.Fatal(err)
		}
		called := false
		err := b.Phase(context.Background(), "unused", func(context.Context, *config.Builder) error { called = true; return nil })
		if !errors.Is(err, config.ErrInvalid) || called {
			t.Fatalf("invalid builder run: called=%v error=%v", called, err)
		}
	}
}
