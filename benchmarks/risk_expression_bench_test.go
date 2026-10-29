package benchmarks_test

import (
	"context"
	"fmt"
	"net/netip"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/analysis"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/policy"
)

func BenchmarkRiskExpression(b *testing.B) {
	for _, n := range []int{10, 100, 1000} {
		for _, leaves := range []int{1, 4, 16} {
			for _, mode := range []analysis.RiskMode{analysis.Declared, analysis.Effective} {
				b.Run(fmt.Sprintf("rules=%d/leaves=%d/mode=%d", n, leaves, mode), func(b *testing.B) {
					fw, q := benchmarkFirewall(b, n), request(b, 0, 443)
					box := q.Traffic.Regions()[0]
					box.Source, _ = flow.PrefixRange(netip.MustParsePrefix("198.18.0.0/15"))
					q.Traffic, _ = flow.NewTraffic(4096, box)
					sources, _ := flow.NewAddressSet(box.Source)
					destinations, _ := flow.NewAddressSet(box.Destination)
					terms := []fm.ServiceTerm{{Protocol: box.Protocol, SourcePort: box.SourcePort, DestinationPort: box.DestinationPort, ICMPType: box.ICMPType, ICMPCode: box.ICMPCode}}
					predicates := []analysis.RiskPredicate{{Dimension: analysis.Source, Relation: analysis.Within, Addresses: sources}, {Dimension: analysis.Destination, Relation: analysis.Within, Addresses: destinations}, {Dimension: analysis.Service, Relation: analysis.Within, Services: terms}}
					expression := analysis.RiskExpression{}
					for i := range leaves {
						expression.All = append(expression.All, analysis.RiskExpression{Predicate: &predicates[i%len(predicates)]})
					}
					definition := analysis.RiskDefinition{ID: "compound", Version: "1", Mode: mode, Expression: &expression}
					analyzer := analysis.RiskAnalyzer{Engine: policy.Engine{Limits: policy.Limits{MaxCombinations: 100000}}}
					b.ReportAllocs()
					for b.Loop() {
						rows, err := analyzer.Analyze(context.Background(), fw, q, definition)
						if err != nil || len(rows) < n {
							b.Fatalf("findings=%d: %v", len(rows), err)
						}
						for _, row := range rows[:n] {
							if row.Value != analysis.True {
								b.Fatal("fixture does not evaluate every leaf")
							}
						}
					}
				})
			}
		}
	}
}
