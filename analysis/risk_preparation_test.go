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
