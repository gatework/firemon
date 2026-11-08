package analysis_test

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/gatework/firemon/analysis"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/policy"
)

// Context indexing and exact sparse boxes exercise the optimizer's two indexes.
// Existing benchmarks/BenchmarkOptimize covers coalescing adjacent declarations.
func BenchmarkRequestOptimizerIndexes(b *testing.B) {
	for _, contexts := range []int{1, 100} {
		b.Run(fmt.Sprintf("contexts=%d", contexts), func(b *testing.B) {
			requests := make([]policy.Request, 100)
			address := netip.MustParseAddr("192.0.2.0")
			for n := range requests {
				region := flow.TrafficRegion{Source: flow.AddressRange{First: address, Last: address}, Destination: flow.AddressRange{First: address, Last: address}, Protocol: flow.Interval{Low: 6, High: 6}, DestinationPort: flow.Interval{Low: 443, High: 443}}
				traffic, err := flow.NewTraffic(1, region)
				if err != nil {
					b.Fatal(err)
				}
				requests[n] = policy.Request{Traffic: traffic, Scope: fmt.Sprintf("scope-%d", n%contexts)}
				address = address.Next()
			}
			b.ReportAllocs()
			for b.Loop() {
				groups, err := (analysis.RequestOptimizer{}).Optimize(b.Context(), requests)
				if err != nil || len(groups) != contexts {
					b.Fatal("context index changed output", err)
				}
				for _, group := range groups {
					if len(group.Inputs) != 100/contexts || group.Request.Traffic.RegionCount() != 100/contexts {
						b.Fatal("sparse associations changed")
					}
				}
			}
		})
	}
}
