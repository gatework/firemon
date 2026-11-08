package benchmarks_test

import (
	"context"
	"fmt"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/policy"
)

// Sparse source/destination sets exercise mostly nonmatching combinations while
// retaining one exact source/destination/service tuple in the result.
func BenchmarkMatch(b *testing.B) {
	data := benchmarkFirewall(b, 32).Export()
	service := fm.ServiceRecord{Object: fm.Object{ID: "ports"}}
	for _, port := range []uint16{80, 443, 8443, 9443} {
		service.Terms = append(service.Terms, fm.ServiceTerm{
			Protocol: flow.Interval{Low: 6, High: 6}, SourcePort: flow.Interval{High: 65535},
			DestinationPort: flow.Interval{Low: port, High: port},
			ICMPType:        flow.Interval{High: 255}, ICMPCode: flow.Interval{High: 255},
		})
	}
	data.Services = append(data.Services, service)
	fw, err := fm.Seal(data)
	if err != nil {
		b.Fatal(err)
	}
	m := fm.Match{AnyFromZone: true, AnyToZone: true, Services: []fm.ServiceRef{{Kind: fm.ServiceObject, ID: "ports"}}}
	for i := range 16 {
		m.Sources = append(m.Sources, fm.AddressRef{Kind: fm.AddressObject, ID: fm.ID(fmt.Sprintf("host-%d", 2*i))})
		m.Destinations = append(m.Destinations, fm.AddressRef{Kind: fm.AddressObject, ID: fm.ID(fmt.Sprintf("host-%d", 2*i+1))})
	}
	q := request(b, 30, 443)
	box := q.Traffic.Regions()[0]
	box.Destination = flow.AddressRange{First: host(31), Last: host(31)}
	q.Traffic = traffic(b, box)
	ctx := context.Background()
	b.ReportAllocs()
	for b.Loop() {
		got, known, err := (policy.Engine{}).Match(ctx, fw, m, q, q.Traffic)
		if err != nil || !known || got.RegionCount() != 1 || got.Regions()[0] != box {
			b.Fatalf("exact match = %v, known %v, err %v", got, known, err)
		}
	}
}
