package inventory_test

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/inventory"
)

func BenchmarkIndex(b *testing.B) {
	data := fm.Data{Addresses: []fm.AddressRecord{{Object: fm.Object{ID: "network"}, Ranges: []flow.AddressRange{indexRange("10.0.0.0/8")}}}}
	for i := range 10_000 {
		addr := netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)})
		data.Addresses = append(data.Addresses, fm.AddressRecord{
			Object: fm.Object{ID: fm.ID(fmt.Sprint("host-", i))},
			Ranges: []flow.AddressRange{{First: addr, Last: addr}},
		})
	}
	fw := indexGraph(b, data)
	source := &cacheSource{load: func(context.Context, string) (*fm.Firewall, error) { return fw, nil }}
	revision := strings.Repeat("a", 64)
	cache, err := inventory.NewCache(source, inventory.CacheLimits{})
	if err != nil {
		b.Fatal(err)
	}
	if _, err := cache.Load(b.Context(), revision); err != nil {
		b.Fatal(err)
	}
	index, err := cache.Index(b.Context(), revision, fw)
	if err != nil {
		b.Fatal(err)
	}
	query := indexSet("10.0.39.15/32")
	b.Run("build", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			cache, err := inventory.NewCache(source, inventory.CacheLimits{})
			if err != nil {
				b.Fatal(err)
			}
			if _, err := cache.Load(b.Context(), revision); err != nil {
				b.Fatal(err)
			}
			if _, err := cache.Index(b.Context(), revision, fw); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("hot", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if got, err := cache.Index(b.Context(), revision, fw); err != nil || got != index {
				b.Fatal(got, err)
			}
		}
	})
	b.Run("candidates", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if got, err := index.Candidates(b.Context(), query, 32); err != nil || len(got) != 2 {
				b.Fatal(got, err)
			}
		}
	})
}
