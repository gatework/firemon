package analysis_test

import (
	"context"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/analysis"
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
