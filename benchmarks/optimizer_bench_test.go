package benchmarks_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/gatework/firemon/analysis"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/policy"
)

func BenchmarkOptimize(b *testing.B) {
	for _, kind := range []string{"adjacent", "paired"} {
		for _, n := range []int{10, 100} {
			b.Run(fmt.Sprintf("%s/requests=%d", kind, n), func(b *testing.B) {
				requests := make([]policy.Request, n)
				for i := range n {
					requests[i] = request(b, i, 443)
					if kind == "paired" {
						box := requests[i].Traffic.Boxes()[0]
						box.Destination = flow.Range{First: host(i + 1024), Last: host(i + 1024)}
						requests[i].Traffic = traffic(b, box)
					}
				}
				ctx := context.Background()
				want := 1
				if kind == "paired" {
					want = n
				}
				b.ReportAllocs()
				for b.Loop() {
					got, err := (analysis.Optimizer{}).Optimize(ctx, requests)
					if err != nil || len(got) != 1 || len(got[0].Request.Traffic.Boxes()) != want {
						b.Fatalf("exact optimizer: %v", err)
					}
				}
			})
		}
	}
}
