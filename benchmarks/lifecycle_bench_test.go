package benchmarks_test

import (
	"context"
	"fmt"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/analysis"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/vendors/huawei"
)

func BenchmarkConvergence(b *testing.B) {
	for _, n := range []int{4, 10} {
		b.Run(fmt.Sprintf("rules=%d", n), func(b *testing.B) {
			fw := benchmarkFirewall(b, n)
			c := analysis.Converger{Planner: plan.Planner{Renderer: huawei.Renderer{}}}
			b.ReportAllocs()
			for b.Loop() {
				rows, err := c.Candidates(context.Background(), fw)
				if err != nil || len(rows) != n*(n-1)/2 {
					b.Fatalf("candidates=%d: %v", len(rows), err)
				}
				for _, row := range rows {
					if row.Plan == nil || row.Rejection != nil {
						b.Fatalf("unproven candidate: %v", row.Rejection)
					}
				}
			}
		})
	}
}

func BenchmarkRisk(b *testing.B) {
	for _, n := range []int{10, 100} {
		for _, mode := range []analysis.RiskMode{analysis.Declared, analysis.Effective} {
			b.Run(fmt.Sprintf("rules=%d/mode=%d", n, mode), func(b *testing.B) {
				fw, q := benchmarkFirewall(b, n), request(b, n-1, 443)
				definition := analysis.RiskDefinition{ID: "exposure", Version: "1", Mode: mode, Relation: analysis.Intersects, Traffic: q.Traffic}
				b.ReportAllocs()
				for b.Loop() {
					rows, err := (analysis.RiskAnalyzer{}).Assess(context.Background(), fw, q, definition)
					if err != nil || len(rows) < n {
						b.Fatalf("findings=%d: %v", len(rows), err)
					}
				}
			})
		}
	}
}

func sharedGroupFirewall(tb testing.TB, n int) *fm.Firewall {
	tb.Helper()
	d := benchmarkFirewall(tb, n).Export()
	var members []fm.AddressRef
	for _, rule := range d.Rules {
		if !rule.Builtin {
			members = append(members, rule.Match.Sources...)
		}
	}
	d.AddressGroups = append(d.AddressGroups, fm.AddressGroupRecord{Object: fm.Object{ID: "shared-benchmark-group", Name: "shared-benchmark-group"}, Members: members})
	for i := range d.Rules {
		if !d.Rules[i].Builtin {
			d.Rules[i].Match.Sources = []fm.AddressRef{{Kind: fm.AddressGroupObject, ID: "shared-benchmark-group"}}
		}
	}
	fw, err := fm.Seal(d)
	if err != nil {
		tb.Fatal(err)
	}
	return fw
}

func BenchmarkSharedGroupMemberUsage(b *testing.B) {
	for _, n := range []int{10, 100} {
		b.Run(fmt.Sprintf("rules=%d/members=%d", n, n), func(b *testing.B) {
			fw := sharedGroupFirewall(b, n)
			b.ReportAllocs()
			for b.Loop() {
				rows, err := (analysis.Reclaimer{}).AnalyzeMembers(context.Background(), fw)
				if err != nil || len(rows) < n*(n+1) {
					b.Fatalf("members=%d: %v", len(rows), err)
				}
				for _, row := range rows {
					if row.Unused != analysis.Unknown || row.Removable {
						b.Fatal("missing evidence became actionable")
					}
				}
			}
		})
	}
}

func TestLifecycleBenchmarkFixtures(t *testing.T) {
	fw := benchmarkFirewall(t, 4)
	rows, err := (analysis.Converger{Planner: plan.Planner{Renderer: huawei.Renderer{}}}).Candidates(context.Background(), fw)
	if err != nil || len(rows) != 6 {
		t.Fatalf("convergence fixture: %d %v", len(rows), err)
	}
	for _, row := range rows {
		if row.Plan == nil || row.Rejection != nil {
			t.Fatalf("convergence fixture rejected: %v", row.Rejection)
		}
	}
	members, err := (analysis.Reclaimer{}).AnalyzeMembers(context.Background(), sharedGroupFirewall(t, 4))
	if err != nil || len(members) < 20 {
		t.Fatalf("shared group fixture: %d %v", len(members), err)
	}
}
