package inventory_test

import (
	"context"
	"errors"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/inventory"
	"github.com/gatework/firemon/snapshot"
)

type brokenLoader struct {
	calls int
	graph *fm.Firewall
}

func (s *brokenLoader) Load(context.Context, string) (*fm.Firewall, error) {
	s.calls++
	return s.graph, nil
}
func TestInventoryDependencyAndCancellationBoundaries(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := inventory.Locate(ctx, nil, flow.AddressSet{}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := inventory.LoadBatch(ctx, nil, inventory.Result{}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	var loader *brokenLoader
	var manifest *snapshot.Store
	for _, store := range []inventory.ManifestReader{nil, manifest} {
		if _, err := inventory.Locate(context.Background(), store, flow.AddressSet{}); !errors.Is(err, inventory.ErrInvalid) || errors.Is(err, snapshot.ErrFormat) {
			t.Fatal("invalid manifest dependency classification", err)
		}
	}
	for _, store := range []inventory.RevisionLoader{nil, loader} {
		if _, err := inventory.LoadBatch(context.Background(), store, inventory.Result{}); !errors.Is(err, inventory.ErrInvalid) || errors.Is(err, snapshot.ErrFormat) {
			t.Fatal("invalid revision dependency classification", err)
		}
	}
	live := &brokenLoader{}
	if _, err := inventory.LoadBatch(context.Background(), live, inventory.Result{Hits: []inventory.Hit{{Device: "fw", Revision: "revision"}}}); !errors.Is(err, snapshot.ErrFormat) || live.calls != 1 {
		t.Fatal("nil graph accepted", err)
	}
}

func TestInventoryMismatchedGraphRemainsFormatError(t *testing.T) {
	graph, err := fm.Seal(fm.Data{Metadata: fm.Metadata{Device: "another-device", Vendor: "test"}})
	if err != nil {
		t.Fatal(err)
	}
	store := &brokenLoader{graph: graph}
	_, err = inventory.LoadBatch(context.Background(), store, inventory.Result{Hits: []inventory.Hit{{Device: "fw", Revision: "revision"}}})
	if !errors.Is(err, snapshot.ErrFormat) || errors.Is(err, inventory.ErrInvalid) {
		t.Fatal("malformed graph classification changed", err)
	}
}
