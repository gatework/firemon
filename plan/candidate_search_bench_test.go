package plan_test

import (
	"context"
	"fmt"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/policy"
)

func manyAppendCandidates(tb testing.TB, count int) *fm.Firewall {
	tb.Helper()
	data := baseline(tb).Export()
	rule := data.Rules[0]
	data.Rules = nil
	for i := range count {
		rule.ID = fm.ID(fmt.Sprintf("rule-%04d", count-i-1))
		rule.Position = count - i - 1
		data.Rules = append(data.Rules, rule)
	}
	fw, err := fm.Seal(data)
	if err != nil {
		tb.Fatal(err)
	}
	return fw
}

// Every rule can safely accept the source. Selection must scan all candidates,
// keep bounded alternatives and prove only the cheapest renderable one.
func BenchmarkPlanCandidates(b *testing.B) {
	for _, count := range []int{10, 100} {
		for _, attempts := range []int{1, 8} {
			b.Run(fmt.Sprintf("rules=%d/attempts=%d", count, attempts), func(b *testing.B) {
				fw := manyAppendCandidates(b, count)
				requests := []policy.Request{request(b, "192.0.2.2/32")}
				planner := plan.Planner{Renderer: renderer{}, MaxCandidates: attempts, Engine: policy.Engine{Limits: policy.Limits{MaxVisits: 2_000_000}}}
				b.ReportAllocs()
				for b.Loop() {
					result, err := planner.Plan(context.Background(), fw, requests)
					if err != nil {
						b.Fatal(err)
					}
					if result.Cost().ID != "rule-0000" || !result.Proof().OutsidePreserved {
						b.Fatal("cheapest proven candidate lost")
					}
				}
			})
		}
	}
}
