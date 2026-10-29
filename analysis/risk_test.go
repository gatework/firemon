package analysis_test

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/analysis"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/policy"
)

func TestRiskSeparatesDeclaredExposureFromEffectiveDenyShadowing(t *testing.T) {
	fw := graph(t, [][2]string{{"192.0.2.1", "198.51.100.1"}, {"192.0.2.1", "198.51.100.1"}})
	d := fw.Export()
	d.Rules[0].Action = fm.Deny
	var err error
	fw, err = fm.Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	q := request(t, "192.0.2.1", "198.51.100.1")
	definition := analysis.RiskDefinition{ID: "management", Version: "1", Mode: analysis.Declared, Relation: analysis.Intersects, Traffic: q.Traffic}
	rows, err := (analysis.RiskAnalyzer{}).Assess(context.Background(), fw, q, definition)
	if err != nil || len(rows) != 2 || rows[0].Value != analysis.False || rows[1].Value != analysis.True {
		t.Fatal(rows, err)
	}
	definition.Mode = analysis.Effective
	rows, err = (analysis.RiskAnalyzer{}).Assess(context.Background(), fw, q, definition)
	if err != nil || rows[1].Value != analysis.False || !rows[1].Traffic.Empty() || rows[1].GraphDigest != fw.SemanticDigest() {
		t.Fatal(rows, err)
	}
	d.Diagnostics = []fm.Diagnostic{{Code: "unparsed", Message: "missing policy evidence"}}
	fw, err = fm.Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	rows, err = (analysis.RiskAnalyzer{}).Assess(context.Background(), fw, q, definition)
	if err != nil || rows[0].Value != analysis.Unknown || rows[1].Value != analysis.Unknown {
		t.Fatal("incomplete source became a clean risk result", rows, err)
	}
}

func riskAddress(t *testing.T, dimension analysis.Dimension, relation analysis.Relation, address string) analysis.RiskExpression {
	t.Helper()
	a := netip.MustParseAddr(address)
	set, err := flow.NewSet(flow.Range{First: a, Last: a})
	if err != nil {
		t.Fatal(err)
	}
	return analysis.RiskExpression{Predicate: &analysis.RiskPredicate{Dimension: dimension, Relation: relation, Addresses: set}}
}

func TestCompoundRiskPreservesAndOrAndTypedServiceTuples(t *testing.T) {
	fw := graph(t, [][2]string{{"192.0.2.1", "198.51.100.1"}})
	q := request(t, "192.0.2.1", "198.51.100.1")
	term := fm.ServiceTerm{Protocol: flow.Interval{Low: 6, High: 6}, SourcePort: flow.Interval{High: 65535}, DestinationPort: flow.Interval{Low: 443, High: 443}, ICMPType: flow.Interval{High: 255}, ICMPCode: flow.Interval{High: 255}}
	service := analysis.RiskExpression{Predicate: &analysis.RiskPredicate{Dimension: analysis.Service, Relation: analysis.Equal, Services: []fm.ServiceTerm{term}}}
	source := riskAddress(t, analysis.Source, analysis.Contains, "192.0.2.1")
	missing := riskAddress(t, analysis.Destination, analysis.Intersects, "198.51.100.2")
	for _, tc := range []struct {
		name       string
		expression analysis.RiskExpression
		want       analysis.Truth
	}{
		{"and", analysis.RiskExpression{All: []analysis.RiskExpression{source, service}}, analysis.True},
		{"and-false", analysis.RiskExpression{All: []analysis.RiskExpression{source, missing}}, analysis.False},
		{"or", analysis.RiskExpression{Any: []analysis.RiskExpression{missing, service}}, analysis.True},
		{"or-empty-intersection", analysis.RiskExpression{Any: []analysis.RiskExpression{missing}}, analysis.False},
		{"nested", analysis.RiskExpression{All: []analysis.RiskExpression{source, {Any: []analysis.RiskExpression{missing, service}}}}, analysis.True},
	} {
		t.Run(tc.name, func(t *testing.T) {
			definition := analysis.RiskDefinition{ID: "compliance", Version: "2", Mode: analysis.Declared, Expression: &tc.expression}
			rows, err := (analysis.RiskAnalyzer{}).Assess(context.Background(), fw, q, definition)
			if err != nil || len(rows) != 1 || rows[0].Value != tc.want || rows[0].PolicyVersion != "2" {
				t.Fatalf("compound result %v, %v", rows, err)
			}
		})
	}
}

func TestCompoundRiskRelationsAndUnknownComposition(t *testing.T) {
	fw := graph(t, [][2]string{{"192.0.2.1", "198.51.100.1"}})
	q := request(t, "192.0.2.1", "198.51.100.1")
	for _, relation := range []analysis.Relation{analysis.Equal, analysis.NotEqual, analysis.Contains, analysis.Within, analysis.Intersects} {
		expression := riskAddress(t, analysis.Source, relation, "192.0.2.1")
		rows, err := (analysis.RiskAnalyzer{}).Assess(context.Background(), fw, q, analysis.RiskDefinition{ID: "risk", Version: "1", Mode: analysis.Declared, Expression: &expression})
		want := analysis.True
		if relation == analysis.NotEqual {
			want = analysis.False
		}
		if err != nil || rows[0].Value != want {
			t.Fatalf("relation %v: %v, %v", relation, rows, err)
		}
	}
	d := fw.Export()
	d.Addresses[1].FQDN = "unresolved.invalid"
	fw, err := fm.Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	unknown := riskAddress(t, analysis.Destination, analysis.Equal, "198.51.100.1")
	knownTrue := riskAddress(t, analysis.Source, analysis.Equal, "192.0.2.1")
	knownFalse := riskAddress(t, analysis.Source, analysis.Equal, "192.0.2.2")
	for _, tc := range []struct {
		name       string
		expression analysis.RiskExpression
		want       analysis.Truth
	}{
		{"unknown", unknown, analysis.Unknown},
		{"unknown-and-false", analysis.RiskExpression{All: []analysis.RiskExpression{unknown, knownFalse}}, analysis.False},
		{"unknown-and-true", analysis.RiskExpression{All: []analysis.RiskExpression{unknown, knownTrue}}, analysis.Unknown},
		{"unknown-or-true", analysis.RiskExpression{Any: []analysis.RiskExpression{unknown, knownTrue}}, analysis.True},
		{"unknown-or-false", analysis.RiskExpression{Any: []analysis.RiskExpression{unknown, knownFalse}}, analysis.Unknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rows, err := (analysis.RiskAnalyzer{}).Assess(context.Background(), fw, q, analysis.RiskDefinition{ID: "risk", Version: "1", Mode: analysis.Declared, Expression: &tc.expression})
			if err != nil || rows[0].Value != tc.want {
				t.Fatal(rows, err)
			}
		})
	}
	expression := analysis.RiskExpression{All: []analysis.RiskExpression{knownTrue, knownFalse}}
	_, err = (analysis.RiskAnalyzer{Engine: policy.Engine{Limits: policy.Limits{Combinations: 2}}}).Assess(context.Background(), fw, q, analysis.RiskDefinition{ID: "risk", Version: "1", Mode: analysis.Declared, Expression: &expression})
	if !errors.Is(err, policy.ErrBudget) {
		t.Fatalf("expression budget ignored: %v", err)
	}
}

func TestCompoundRiskKeepsServicePairsAndEffectiveOwnership(t *testing.T) {
	d := graph(t, [][2]string{{"192.0.2.1", "198.51.100.1"}, {"192.0.2.1", "198.51.100.1"}}).Export()
	tcp := fm.ServiceTerm{Protocol: flow.Interval{Low: 6, High: 6}, SourcePort: flow.Interval{Low: 1000, High: 1000}, DestinationPort: flow.Interval{Low: 443, High: 443}, ICMPType: flow.Interval{High: 255}, ICMPCode: flow.Interval{High: 255}}
	udp := tcp
	udp.Protocol, udp.SourcePort, udp.DestinationPort = flow.Interval{Low: 17, High: 17}, flow.Interval{Low: 2000, High: 2000}, flow.Interval{Low: 53, High: 53}
	d.Services = []fm.ServiceRecord{{Object: fm.Object{ID: "paired"}, Terms: []fm.ServiceTerm{tcp, udp}}}
	d.Rules[0].Action = fm.Drop
	for i := range d.Rules {
		d.Rules[i].Match.AnyService = false
		d.Rules[i].Match.Services = []fm.ServiceRef{{Kind: fm.ServiceObject, ID: "paired"}}
	}
	fw, err := fm.Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	q := request(t, "192.0.2.1", "198.51.100.1")
	box := q.Traffic.Boxes()[0]
	box.Protocol, box.DestinationPort = flow.Interval{High: 255}, flow.Interval{High: 65535}
	q.Traffic, err = flow.NewTraffic(32, box)
	if err != nil {
		t.Fatal(err)
	}
	cross := tcp
	cross.DestinationPort = udp.DestinationPort
	expression := analysis.RiskExpression{Predicate: &analysis.RiskPredicate{Dimension: analysis.Service, Relation: analysis.Intersects, Services: []fm.ServiceTerm{cross}}}
	definition := analysis.RiskDefinition{ID: "services", Version: "1", Mode: analysis.Declared, Expression: &expression}
	rows, err := (analysis.RiskAnalyzer{}).Assess(context.Background(), fw, q, definition)
	if err != nil || rows[1].Value != analysis.False {
		t.Fatalf("service cross-pair invented: %v, %v", rows, err)
	}
	expression.Predicate.Relation, expression.Predicate.Services = analysis.Equal, []fm.ServiceTerm{tcp, udp}
	rows, err = (analysis.RiskAnalyzer{}).Assess(context.Background(), fw, q, definition)
	if err != nil || rows[1].Value != analysis.True {
		t.Fatal(rows, err)
	}
	definition.Mode = analysis.Effective
	rows, err = (analysis.RiskAnalyzer{}).Assess(context.Background(), fw, q, definition)
	if err != nil || rows[1].Value != analysis.False {
		t.Fatalf("shadowed compound exposure: %v, %v", rows, err)
	}
}

func TestCompoundRiskRejectsAmbiguousOrUntypedStandards(t *testing.T) {
	fw := graph(t, [][2]string{{"192.0.2.1", "198.51.100.1"}})
	q := request(t, "192.0.2.1", "198.51.100.1")
	valid := riskAddress(t, analysis.Source, analysis.Equal, "192.0.2.1")
	for _, tc := range []struct {
		name       string
		expression analysis.RiskExpression
	}{
		{"empty", analysis.RiskExpression{}},
		{"mixed-composition", analysis.RiskExpression{All: []analysis.RiskExpression{valid}, Any: []analysis.RiskExpression{valid}}},
		{"mixed-leaf", analysis.RiskExpression{Predicate: valid.Predicate, All: []analysis.RiskExpression{valid}}},
		{"wrong-dimension", analysis.RiskExpression{Predicate: &analysis.RiskPredicate{Dimension: analysis.Service, Relation: analysis.Equal, Addresses: valid.Predicate.Addresses}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := (analysis.RiskAnalyzer{}).Assess(context.Background(), fw, q, analysis.RiskDefinition{ID: "risk", Version: "1", Mode: analysis.Declared, Expression: &tc.expression})
			if !errors.Is(err, analysis.ErrInvalid) {
				t.Fatal(err)
			}
		})
	}
	_, err := (analysis.RiskAnalyzer{}).Assess(context.Background(), fw, q, analysis.RiskDefinition{ID: "risk", Version: "1", Mode: analysis.Declared, Relation: analysis.Equal, Traffic: q.Traffic, Expression: &valid})
	if !errors.Is(err, analysis.ErrInvalid) {
		t.Fatal("mixed old/new definition accepted", err)
	}
	d := fw.Export()
	d.Diagnostics = []fm.Diagnostic{{Code: "unparsed", Message: "missing capture"}}
	fw, err = fm.Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := (analysis.RiskAnalyzer{}).Assess(context.Background(), fw, q, analysis.RiskDefinition{ID: "risk", Version: "1", Mode: analysis.Declared, Expression: &valid})
	if err != nil || rows[0].Value != analysis.Unknown {
		t.Fatal("incomplete capture became a field finding", rows, err)
	}
}

func TestRiskUsesPairedTrafficAndExplicitDefinition(t *testing.T) {
	fw := graph(t, [][2]string{{"192.0.2.1", "198.51.100.1"}})
	q := request(t, "192.0.2.1", "198.51.100.1")
	cross := request(t, "192.0.2.1", "198.51.100.2")
	definition := analysis.RiskDefinition{ID: "pairs", Version: "1", Mode: analysis.Declared, Relation: analysis.Intersects, Traffic: cross.Traffic}
	rows, err := (analysis.RiskAnalyzer{}).Assess(context.Background(), fw, q, definition)
	if err != nil || rows[0].Value != analysis.False {
		t.Fatal(rows, err)
	}
	definition.Version = ""
	if _, err := (analysis.RiskAnalyzer{}).Assess(context.Background(), fw, q, definition); err == nil {
		t.Fatal("unversioned risk definition accepted")
	}
}
