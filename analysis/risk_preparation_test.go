package analysis_test

import (
	"context"
	"errors"
	"testing"

	"github.com/gatework/firemon/analysis"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/policy"
)

func TestRiskBoundsTotalPreparedStandardRegions(t *testing.T) {
	fw := graph(t, [][2]string{{"192.0.2.1", "198.51.100.1"}})
	leaf := riskAddress(t, analysis.Source, analysis.Equal, "192.0.2.1")
	expression := analysis.RiskExpression{All: []analysis.RiskExpression{leaf, leaf, leaf}}
	a := analysis.RiskAnalyzer{Engine: policy.Engine{Limits: policy.Limits{MaxRegions: 2}}}
	rows, err := a.Analyze(context.Background(), fw, request(t, "192.0.2.1", "198.51.100.1"), analysis.RiskDefinition{ID: "risk", Version: "1", Mode: analysis.Declared, Expression: &expression})
	if rows != nil || !errors.Is(err, flow.ErrBudget) {
		t.Fatalf("unbounded prepared standards: %v, %v", rows, err)
	}
}

func TestRiskCountsCachedNodesAcrossRules(t *testing.T) {
	fw := graph(t, [][2]string{{"192.0.2.1", "198.51.100.1"}, {"192.0.2.1", "198.51.100.1"}})
	leaf := riskAddress(t, analysis.Source, analysis.Equal, "192.0.2.1")
	expression := analysis.RiskExpression{All: []analysis.RiskExpression{leaf, leaf}}
	definition := analysis.RiskDefinition{ID: "risk", Version: "1", Mode: analysis.Declared, Expression: &expression}
	q := request(t, "192.0.2.1", "198.51.100.1")
	for _, limit := range []int{5, 6} {
		a := analysis.RiskAnalyzer{Engine: policy.Engine{Limits: policy.Limits{MaxCombinations: limit}}}
		rows, err := a.Analyze(context.Background(), fw, q, definition)
		if limit == 5 {
			if rows != nil || !errors.Is(err, policy.ErrBudget) {
				t.Fatalf("cached nodes bypassed cumulative budget: %v, %v", rows, err)
			}
		} else if err != nil || len(rows) != 2 || rows[0].Value != analysis.True || rows[1].Value != analysis.True {
			t.Fatalf("exact evaluation budget: %v, %v", rows, err)
		}
	}
	// Both validation and evaluation have a budget of six nodes. OR short
	// circuits after its first true leaf on each rule (two nodes per rule).
	fw = graph(t, [][2]string{{"192.0.2.1", "198.51.100.1"}, {"192.0.2.1", "198.51.100.1"}, {"192.0.2.1", "198.51.100.1"}})
	expression = analysis.RiskExpression{Any: []analysis.RiskExpression{leaf, leaf, leaf, leaf, leaf}}
	a := analysis.RiskAnalyzer{Engine: policy.Engine{Limits: policy.Limits{MaxCombinations: 6}}}
	rows, err := a.Analyze(context.Background(), fw, q, definition)
	if err != nil || len(rows) != 3 || rows[2].Value != analysis.True {
		t.Fatalf("short circuit or independent preparation budget changed: %v, %v", rows, err)
	}
}
