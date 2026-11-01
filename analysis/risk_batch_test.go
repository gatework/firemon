package analysis_test

import (
	"context"
	"errors"
	"testing"

	"github.com/gatework/firemon/analysis"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/policy"
)

func TestRiskBatchSharesPreparationAndEvaluationBudgets(t *testing.T) {
	fw := graph(t, [][2]string{{"192.0.2.1", "198.51.100.1"}})
	q := request(t, "192.0.2.1", "198.51.100.1")
	leaf := riskAddress(t, analysis.Source, analysis.Equal, "192.0.2.1")
	expression := analysis.RiskExpression{All: []analysis.RiskExpression{leaf, leaf}}
	definition := analysis.RiskDefinition{ID: "risk", Version: "1", Mode: analysis.Declared, Expression: &expression}
	for _, limit := range []int{5, 6} {
		a := analysis.RiskAnalyzer{Engine: policy.Engine{Limits: policy.Limits{MaxCombinations: limit, MaxRegions: 2}}}
		rows, err := a.AnalyzeBatch(context.Background(), fw, []policy.Request{q, q}, []analysis.RiskDefinition{definition})
		if limit == 5 {
			if rows != nil || !errors.Is(err, policy.ErrBudget) {
				t.Fatal(rows, err)
			}
		} else if err != nil || len(rows) != 2 || rows[0].Findings[0].Value != analysis.True || rows[1].Context != 1 {
			t.Fatal(rows, err)
		}
	}
	a := analysis.RiskAnalyzer{Engine: policy.Engine{Limits: policy.Limits{MaxVisits: 3}}}
	rows, err := a.AnalyzeBatch(context.Background(), fw, []policy.Request{q, q}, []analysis.RiskDefinition{definition})
	if rows != nil || !errors.Is(err, policy.ErrBudget) {
		t.Fatal("context reset visit budget", rows, err)
	}
}

func TestRiskBatchBoundsRetainedTrafficAcrossContexts(t *testing.T) {
	fw := graph(t, [][2]string{{"192.0.2.1", "198.51.100.1"}})
	q := request(t, "192.0.2.1", "198.51.100.1")
	def := analysis.RiskDefinition{ID: "risk", Version: "1", Mode: analysis.Declared, Relation: analysis.Intersects, Traffic: q.Traffic}
	a := analysis.RiskAnalyzer{Engine: policy.Engine{Limits: policy.Limits{MaxRegions: 1}}}
	rows, err := a.AnalyzeBatch(context.Background(), fw, []policy.Request{q, q}, []analysis.RiskDefinition{def})
	if rows != nil || !errors.Is(err, flow.ErrBudget) {
		t.Fatal("unbounded retained traffic", rows, err)
	}
}
