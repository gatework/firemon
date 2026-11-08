package plan_test

import (
	"fmt"
	"net/netip"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/policy"
)

// The same fixture and observable outputs run against both implementations.
func BenchmarkCatalogExactReuse(b *testing.B) {
	for _, count := range []int{10, 100, 1000} {
		b.Run(fmt.Sprintf("objects=%d", count), func(b *testing.B) {
			data := baseline(b).Export()
			data.Rules = nil
			address := netip.MustParseAddr("203.0.113.0")
			for n := range count {
				id := fm.ID(fmt.Sprintf("existing-%d", n))
				data.Addresses = append(data.Addresses, fm.AddressRecord{Object: fm.Object{ID: id}, Ranges: []flow.AddressRange{{First: address, Last: address}}})
				service := data.Services[0]
				service.ID = id
				service.Terms = append([]fm.ServiceTerm(nil), service.Terms...)
				service.Terms[0].DestinationPort = flow.Interval{Low: uint16(1000 + n), High: uint16(1000 + n)}
				data.Services = append(data.Services, service)
				address = address.Next()
			}
			// Reuse requires native declarations with names, independently of IDs.
			for i := range data.Addresses {
				data.Addresses[i].Name = string(data.Addresses[i].ID)
			}
			for i := range data.Services {
				data.Services[i].Name = string(data.Services[i].ID)
			}
			fw, err := fm.Seal(data)
			if err != nil {
				b.Fatal(err)
			}
			q := request(b, "192.0.2.1/32")
			planner := plan.Planner{Renderer: renderer{}}
			b.ReportAllocs()
			for b.Loop() {
				p, err := planner.Plan(b.Context(), fw, []policy.Request{q})
				if err != nil || p.Cost().NewObjects != 0 || len(p.Changes()) != 1 || p.Changes()[0].Sources[0] != (fm.AddressRef{Kind: fm.AddressObject, ID: "src"}) || p.Changes()[0].Services[0] != (fm.ServiceRef{Kind: fm.ServiceObject, ID: "https"}) {
					b.Fatal("exact object reuse changed", err)
				}
			}
		})
	}
}
