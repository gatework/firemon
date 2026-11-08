package inventory_test

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/inventory"
)

func TestCacheIndexDoesNotReplaceVerifiedRevision(t *testing.T) {
	verified := cacheGraph(t, "lab", "synthetic verified revision")
	data := verified.Export()
	address := netip.MustParseAddr("198.51.100.20")
	data.Addresses[0].Ranges = []flow.AddressRange{{First: address, Last: address}}
	other, err := fm.Seal(data)
	if err != nil {
		t.Fatal(err)
	}
	loads := 0
	source := &cacheSource{load: func(context.Context, string) (*fm.Firewall, error) {
		loads++
		return verified, nil
	}}
	cache, err := inventory.NewCache(source, inventory.CacheLimits{})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name     string
		revision string
		load     bool
	}{
		{"retained graph", strings.Repeat("a", 64), true},
		{"unloaded revision", strings.Repeat("b", 64), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.load {
				if _, err := cache.Load(t.Context(), test.revision); err != nil {
					t.Fatal(err)
				}
			}
			before := loads
			index, err := cache.Index(t.Context(), test.revision, other)
			if err != nil || loads != before {
				t.Fatal("deriving an index performed a backing load", loads, before, err)
			}
			if candidates, err := index.Candidates(t.Context(), indexSet("198.51.100.20/32"), 1); err != nil || len(candidates) != 1 {
				t.Fatal("index did not describe the supplied immutable graph", candidates, err)
			}
			loaded, err := cache.Load(t.Context(), test.revision)
			wantLoads := before
			if !test.load {
				wantLoads++
			}
			if err != nil || loaded != verified || loads != wantLoads {
				t.Fatal("supplied index graph replaced persistence authority", loaded, loads, err)
			}
			index, err = cache.Index(t.Context(), test.revision, verified)
			if err != nil {
				t.Fatal(err)
			}
			if candidates, err := index.Candidates(t.Context(), indexSet("192.0.2.10/32"), 1); err != nil || len(candidates) != 1 {
				t.Fatal("another graph's index polluted a verified revision", candidates, err)
			}
		})
	}
}
