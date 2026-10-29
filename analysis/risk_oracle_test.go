package analysis_test

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"sync"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/analysis"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/policy"
)

// The oracle uses three-bit sets, independently of traffic interval algebra.
// The third service is TCP/53: neither observed TCP/443 nor UDP/53 implies it.
func TestRiskExpressionsMatchFiniteSetOracle(t *testing.T) {
	d := graph(t, [][2]string{{"192.0.2.1", "198.51.100.1"}, {"192.0.2.2", "198.51.100.1"}}).Export()
	d.Rules[0].Action = fm.Drop
	d.Rules[1].Match.Sources = append(d.Rules[1].Match.Sources, d.Rules[0].Match.Sources...)
	terms := []fm.ServiceTerm{
		{Protocol: flow.Interval{Low: 6, High: 6}, DestinationPort: flow.Interval{Low: 443, High: 443}},
		{Protocol: flow.Interval{Low: 17, High: 17}, DestinationPort: flow.Interval{Low: 53, High: 53}},
		{Protocol: flow.Interval{Low: 6, High: 6}, DestinationPort: flow.Interval{Low: 53, High: 53}},
	}
	d.Services = []fm.ServiceRecord{{Object: fm.Object{ID: "paired"}, Terms: terms[:2]}}
	for i := range d.Rules {
		d.Rules[i].Match.AnyService = false
		d.Rules[i].Match.Services = []fm.ServiceRef{{Kind: fm.ServiceObject, ID: "paired"}}
	}
	fw, err := fm.Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	q := request(t, "192.0.2.1", "198.51.100.1")
	var boxes []flow.TrafficRegion
	for _, source := range []string{"192.0.2.1", "192.0.2.2"} {
		for _, term := range terms[:2] {
			b := q.Traffic.Regions()[0]
			address := netip.MustParseAddr(source)
			b.Source = flow.AddressRange{First: address, Last: address}
			b.Protocol, b.SourcePort, b.DestinationPort, b.ICMPType, b.ICMPCode = term.Protocol, term.SourcePort, term.DestinationPort, term.ICMPType, term.ICMPCode
			boxes = append(boxes, b)
		}
	}
	q.Traffic, err = flow.NewTraffic(32, boxes...)
	if err != nil {
		t.Fatal(err)
	}
	compare := func(actual, standard uint8, relation analysis.Relation) bool {
		switch relation {
		case analysis.Intersects:
			return actual&standard != 0
		case analysis.Contains:
			return standard&^actual == 0
		case analysis.Within:
			return actual&^standard == 0
		case analysis.Equal:
			return actual == standard
		case analysis.NotEqual:
			return actual != standard
		}
		panic("oracle relation")
	}
	rng := rand.New(rand.NewPCG(17, 29))
	for trial := range 256 {
		masks := [3]uint8{}
		relations := [3]analysis.Relation{}
		leaves := make([]analysis.RiskExpression, 3)
		for dimension := range 3 {
			mask, relation := uint8(1+rng.IntN(7)), analysis.Relation(1+rng.IntN(5))
			masks[dimension], relations[dimension] = mask, relation
			p := analysis.RiskPredicate{Dimension: analysis.Dimension(dimension + 1), Relation: relation}
			var ranges []flow.AddressRange
			for bit := range 3 {
				if mask&(1<<bit) == 0 {
					continue
				}
				if p.Dimension == analysis.Service {
					p.Services = append(p.Services, terms[bit])
					continue
				}
				prefix := "192.0.2"
				if p.Dimension == analysis.Destination {
					prefix = "198.51.100"
				}
				address := netip.MustParseAddr(fmt.Sprintf("%s.%d", prefix, bit+1))
				ranges = append(ranges, flow.AddressRange{First: address, Last: address})
			}
			if len(ranges) > 0 {
				p.Addresses, _ = flow.NewAddressSet(ranges...)
			}
			leaves[dimension] = analysis.RiskExpression{Predicate: &p}
		}
		expression := analysis.RiskExpression{All: []analysis.RiskExpression{leaves[0], {Any: leaves[1:]}}}
		for _, mode := range []analysis.RiskMode{analysis.Declared, analysis.Effective} {
			rows, err := (analysis.RiskAnalyzer{}).Analyze(context.Background(), fw, q, analysis.RiskDefinition{ID: "oracle", Version: "1", Mode: mode, Actions: []fm.Action{fm.Drop, fm.Permit}, Expression: &expression})
			if err != nil || len(rows) != 2 {
				t.Fatalf("trial %d: %v", trial, err)
			}
			for i, row := range rows {
				sources := uint8(1)
				if i == 1 {
					sources = 3
					if mode == analysis.Effective {
						sources = 2
					}
				}
				want := compare(sources, masks[0], relations[0]) && (compare(1, masks[1], relations[1]) || compare(3, masks[2], relations[2]))
				if (row.Value == analysis.True) != want || row.Value == analysis.Unknown {
					t.Fatalf("trial=%d mode=%v rule=%v masks=%v relations=%v got=%v want=%v", trial, mode, row.Rule, masks, relations, row.Value, want)
				}
			}
		}
	}
}

func TestRiskPreparationIsRequestLocalAndConcurrent(t *testing.T) {
	fw := graph(t, [][2]string{{"192.0.2.1", "198.51.100.1"}})
	q := request(t, "192.0.2.1", "198.51.100.1")
	expression := riskAddress(t, analysis.Source, analysis.Equal, "192.0.2.1")
	definition := analysis.RiskDefinition{ID: "reuse", Version: "1", Mode: analysis.Declared, Expression: &expression}
	analyzer := analysis.RiskAnalyzer{Engine: policy.Engine{}}
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			rows, err := analyzer.Analyze(context.Background(), fw, q, definition)
			if err != nil || len(rows) != 1 || rows[0].Value != analysis.True {
				t.Errorf("concurrent analysis: %v, %v", rows, err)
			}
		})
	}
	workers.Wait()
	if definition.Expression.Predicate.Relation != analysis.Equal {
		t.Fatal("caller expression changed")
	}
	expression.Predicate.Relation = analysis.NotEqual
	rows, err := analyzer.Analyze(context.Background(), fw, q, definition)
	if err != nil || len(rows) != 1 || rows[0].Value != analysis.False {
		t.Fatalf("prior preparation retained across calls: %v, %v", rows, err)
	}
}
