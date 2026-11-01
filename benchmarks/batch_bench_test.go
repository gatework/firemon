package benchmarks_test

import (
	"context"
	"fmt"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/policy"
	"github.com/gatework/firemon/vendors/huawei"
)

// New API baseline only: independently planned scripts have different proof and
// naming semantics and are not a valid "before" for a joint PlanBatch.
func BenchmarkBusinessPlanBatch(b *testing.B) {
	for _, n := range []int{1000, 10000} {
		for _, count := range []int{1, 8} {
			b.Run(fmt.Sprintf("rules=%d/requests=%d", n, count), func(b *testing.B) {
				fw := businessCandidateGraph(b, n, false)
				requests := make([]policy.Request, count)
				for i := range requests {
					requests[i] = request(b, 0, 443)
					box := requests[i].Traffic.Regions()[0]
					box.SourcePort.Low += uint16(i)
					box.SourcePort.High += uint16(i)
					requests[i].Traffic = traffic(b, box)
				}
				p := plan.Planner{Renderer: huawei.Renderer{}, Engine: policy.Engine{Limits: policy.Limits{MaxVisits: 10000000, MaxCombinations: 1000000}}}
				b.ReportAllocs()
				for b.Loop() {
					result, err := p.PlanBatch(context.Background(), fw, requests)
					if err != nil || result.Plan == nil || len(result.Plan.Commands()) != 0 || len(result.Inputs) != count {
						b.Fatal(result, err)
					}
					for _, input := range result.Inputs {
						if input.Disposition != plan.BatchCovered {
							b.Fatal("covered batch changed")
						}
					}
				}
			})
		}
	}
}

// Additions extend one compatible rule with nonadjacent source hosts. Every
// request retains the rule's complete service/destination domain so an append
// can be proven without widening its business intent. Only the first explicit
// rule permits; remaining explicit denies are not append candidates.
func BenchmarkBusinessPlanBatchAddition(b *testing.B) {
	for _, n := range []int{1000, 10000} {
		for _, count := range []int{1, 8} {
			b.Run(fmt.Sprintf("rules=%d/requests=%d", n, count), func(b *testing.B) {
				fw := businessCandidateGraph(b, n, false)
				data := fw.Export()
				first := true
				for i := range data.Rules {
					if data.Rules[i].Builtin {
						continue
					}
					if first {
						first = false
					} else {
						data.Rules[i].Action = fm.Deny
					}
				}
				var err error
				fw, err = fm.Seal(data)
				if err != nil {
					b.Fatal(err)
				}
				q := request(b, 0, 443)
				all, _ := flow.AllTraffic(4096)
				q.Traffic = all
				var matched flow.Traffic
				for r := range fw.OrderedRules() {
					if !r.Builtin() {
						var known bool
						var err error
						matched, known, err = (policy.Engine{}).Match(context.Background(), fw, r.Record().Match, q, all)
						if err != nil || !known {
							b.Fatal(err)
						}
						break
					}
				}
				requests := make([]policy.Request, count)
				for i := range requests {
					boxes := matched.Regions()
					for j := range boxes {
						addr := host(n + 2*i)
						boxes[j].Source = flow.AddressRange{First: addr, Last: addr}
					}
					var err error
					requests[i] = q
					requests[i].Traffic, err = flow.NewTraffic(4096, boxes...)
					if err != nil {
						b.Fatal(err)
					}
				}
				p := plan.Planner{Renderer: huawei.Renderer{}, Engine: policy.Engine{Limits: policy.Limits{MaxVisits: 10000000, MaxCombinations: 1000000}}}
				b.ReportAllocs()
				for b.Loop() {
					r, err := p.PlanBatch(context.Background(), fw, requests)
					if err != nil || r.Plan == nil || len(r.Plan.Commands()) == 0 || !r.Plan.Proof().OutsidePreserved {
						b.Fatal("addition batch", err)
					}
					for _, input := range r.Inputs {
						if input.Disposition != plan.BatchAccepted {
							b.Fatal(input.Disposition)
						}
					}
				}
			})
		}
	}
}
