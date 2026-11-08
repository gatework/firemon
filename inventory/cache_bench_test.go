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
	"github.com/gatework/firemon/snapshot"
)

func BenchmarkCacheLoad(b *testing.B) {
	data := fm.Data{
		Metadata: fm.Metadata{Device: "lab", Vendor: "hillstone"},
		Raw:      strings.Repeat("# synthetic configuration\n", 1000),
	}
	for i := range 1000 {
		addr := netip.AddrFrom4([4]byte{192, 0, byte(i >> 8), byte(i)})
		data.Addresses = append(data.Addresses, fm.AddressRecord{
			Object: fm.Object{ID: fm.ID(fmt.Sprint("address-", i))},
			Ranges: []flow.AddressRange{{First: addr, Last: addr}},
		})
	}
	fw, err := fm.Seal(data)
	if err != nil {
		b.Fatal(err)
	}
	store, err := snapshot.Open(b.TempDir())
	if err != nil {
		b.Fatal(err)
	}
	published, err := store.Publish(b.Context(), fw, snapshot.PublishOptions{PublicationID: "benchmark"})
	if err != nil {
		b.Fatal(err)
	}
	for _, mode := range []string{"uncached", "cold", "hot"} {
		b.Run(mode, func(b *testing.B) {
			cache, err := inventory.NewCache(store, inventory.CacheLimits{})
			if err != nil {
				b.Fatal(err)
			}
			if _, err := cache.Load(b.Context(), published.Revision); err != nil {
				b.Fatal(err)
			}
			var load func(context.Context, string) (*fm.Firewall, error)
			switch mode {
			case "uncached":
				load = store.Load
			case "cold":
				load = func(ctx context.Context, revision string) (*fm.Firewall, error) {
					cache, err := inventory.NewCache(store, inventory.CacheLimits{})
					if err != nil {
						return nil, err
					}
					return cache.Load(ctx, revision)
				}
			case "hot":
				load = cache.Load
			}
			b.ReportAllocs()
			for b.Loop() {
				got, err := load(b.Context(), published.Revision)
				if err != nil || got == nil || got.DeclarationSize() != fw.DeclarationSize() {
					b.Fatal(got, err)
				}
			}
		})
	}
}
