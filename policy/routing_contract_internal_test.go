package policy

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
)

type cancellationCheckpoint struct {
	context.Context
	checks, limit int
}

func (c *cancellationCheckpoint) Err() error {
	c.checks++
	if c.checks >= c.limit {
		return context.Canceled
	}
	return nil
}

func TestRouteCancellationDuringFinalEqualPrefixGroup(t *testing.T) {
	const count = 128
	d := fm.Data{Metadata: fm.Metadata{Device: "test", Vendor: "huawei"}}
	for i := range count {
		d.Routes = append(d.Routes, fm.RouteRecord{Object: fm.Object{ID: fm.ID(fmt.Sprintf("route-%d", i))}, Destination: netip.MustParsePrefix("192.0.2.0/24")})
	}
	fw, err := fm.Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	interval, _ := flow.PrefixRange(netip.MustParsePrefix("192.0.2.0/24"))
	addresses, _ := flow.NewSet(interval)
	// Entry, collection and post-sort checks used to finish before this point;
	// the final same-prefix scans then returned a successful result.
	ctx := &cancellationCheckpoint{Context: context.Background(), limit: count + 10}
	if _, err := (Engine{}).ResolveRoutes(ctx, fw, "", addresses); !errors.Is(err, context.Canceled) {
		t.Fatalf("final group ignored cancellation: %v (checks %d)", err, ctx.checks)
	}
}

func TestRouteSortCancellationAndStableOrder(t *testing.T) {
	var routes []routeCandidate
	for i := range 513 {
		routes = append(routes, routeCandidate{route: &fm.Route{}, destination: netip.MustParsePrefix("192.0.2.0/24"), metric: uint32((513 - i) % 7), key: "192.0.2.0/24"})
	}
	want := slices.Clone(routes)
	slices.SortStableFunc(want, compareRoutes)
	canceled := &cancellationCheckpoint{Context: context.Background(), limit: 2}
	if err := sortRoutes(canceled, slices.Clone(routes)); !errors.Is(err, context.Canceled) {
		t.Fatal("sort did not stop between chunks", err)
	}
	merging := &cancellationCheckpoint{Context: context.Background(), limit: 12}
	if err := sortRoutes(merging, slices.Clone(routes)); !errors.Is(err, context.Canceled) {
		t.Fatal("merge did not stop", err)
	}
	if err := sortRoutes(context.Background(), routes); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(routes, want) {
		t.Fatal("stable ordering differs from standard library")
	}
}
