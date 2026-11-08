package benchmarks_test

import (
	"fmt"
	"testing"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/analysis"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/policy"
)

const riskBatchMaxVisits = 1000000

// Multiple standards inspect the same effective partition in each context.
// Native parsing and request construction are excluded from timing.
func BenchmarkRiskBatch(b *testing.B) {
	for _, contexts := range []int{1, 4} {
		for _, definitions := range []int{1, 10, 30} {
			b.Run(fmt.Sprintf("rules=100/contexts=%d/definitions=%d", contexts, definitions), func(b *testing.B) {
				fw, requests, standards := riskBatchFixture(b, contexts, definitions)
				analyzer := analysis.RiskAnalyzer{Engine: policy.Engine{Limits: policy.Limits{MaxVisits: riskBatchMaxVisits}}}
				b.ReportAllocs()
				for b.Loop() {
					rows, err := analyzer.AnalyzeBatch(b.Context(), fw, requests, standards)
					if err != nil || len(rows) != contexts*definitions {
						b.Fatalf("context findings=%d: %v", len(rows), err)
					}
				}
			})
		}
	}
}

func riskBatchFixture(tb testing.TB, contexts, definitions int) (*fm.Firewall, []policy.Request, []analysis.RiskDefinition) {
	tb.Helper()
	fw := benchmarkFirewall(tb, 100)
	requests := make([]policy.Request, contexts)
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	var standard flow.Traffic
	for i := range requests {
		requests[i] = request(tb, 99-i, 443)
		requests[i].At = at.Add(time.Duration(i) * time.Hour)
		var err error
		standard, err = standard.Union(requests[i].Traffic, 4096)
		if err != nil {
			tb.Fatal(err)
		}
	}
	standards := make([]analysis.RiskDefinition, definitions)
	for i := range standards {
		standards[i] = analysis.RiskDefinition{ID: fmt.Sprintf("exposure-%d", i), Version: "1", Mode: analysis.Effective, Relation: analysis.Intersects, Traffic: standard}
	}
	return fw, requests, standards
}

func TestRiskBatchBenchmarkFixture(t *testing.T) {
	fw, requests, standards := riskBatchFixture(t, 4, 30)
	rows, err := (analysis.RiskAnalyzer{Engine: policy.Engine{Limits: policy.Limits{MaxVisits: riskBatchMaxVisits}}}).AnalyzeBatch(t.Context(), fw, requests, standards)
	if err != nil || len(rows) != len(requests)*len(standards) {
		t.Fatalf("context findings=%d: %v", len(rows), err)
	}
	for i, row := range rows {
		if row.Context != i/len(standards) || row.Definition != i%len(standards) || len(row.Findings) != fw.RuleCount() {
			t.Fatalf("context=%d definition=%d findings=%d", row.Context, row.Definition, len(row.Findings))
		}
		matched := 0
		for _, finding := range row.Findings {
			if finding.Value == analysis.Unknown {
				t.Fatal("complete benchmark fixture produced unknown risk")
			}
			if finding.Value == analysis.True {
				matched++
			}
		}
		if matched != 1 {
			t.Fatalf("context=%d definition=%d matched=%d", row.Context, row.Definition, matched)
		}
	}
}
