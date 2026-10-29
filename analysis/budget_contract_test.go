package analysis_test

import (
	"context"
	"errors"
	"testing"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/analysis"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/policy"
	"github.com/gatework/firemon/vendors/hillstone"
	"github.com/gatework/firemon/vendors/paloalto"
)

func TestRiskBudgetsIncompleteRowsBeforeReturningUnknown(t *testing.T) {
	d := graph(t, [][2]string{{"192.0.2.1", "198.51.100.1"}, {"192.0.2.2", "198.51.100.1"}}).Export()
	d.Diagnostics = []fm.Diagnostic{{Code: "unknown", Message: "unparsed source"}}
	fw, err := fm.Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	q := request(t, "192.0.2.1", "198.51.100.1")
	definition := analysis.RiskDefinition{ID: "risk", Version: "1", Mode: analysis.Declared, Relation: analysis.Intersects, Traffic: q.Traffic}
	for _, limit := range []int{1, 2} {
		rows, err := (analysis.RiskAnalyzer{Engine: policy.Engine{Limits: policy.Limits{MaxVisits: limit}}}).Analyze(context.Background(), fw, q, definition)
		if limit == 1 {
			if rows != nil || !errors.Is(err, policy.ErrBudget) {
				t.Fatalf("partial over-budget findings: %v, %v", rows, err)
			}
		} else if err != nil || len(rows) != 2 || rows[0].Value != analysis.Unknown {
			t.Fatalf("exact-budget unknown rows: %v, %v", rows, err)
		}
	}
}

func TestConvergenceSharesVisitsAcrossCandidateProofPreparation(t *testing.T) {
	fw := graph(t, [][2]string{{"192.0.2.1", "198.51.100.1"}, {"192.0.2.1", "198.51.100.1"}, {"192.0.2.1", "198.51.100.1"}})
	c := analysis.Converger{Planner: plan.Planner{Renderer: hillstone.Renderer{}, Engine: policy.Engine{Limits: policy.Limits{MaxVisits: 8}}}}
	rows, err := c.Candidates(context.Background(), fw, time.Time{})
	if rows != nil || !errors.Is(err, policy.ErrBudget) {
		t.Fatalf("candidate visits reset: %v, %v", rows, err)
	}
}

func TestMigrationAccumulatesMappingAndPartitionVisits(t *testing.T) {
	source, target := translationGraphs(t)
	m := analysis.PolicyMigrator{Planner: plan.Planner{Renderer: paloalto.Renderer{}, Engine: policy.Engine{Limits: policy.Limits{MaxVisits: 16}}}}
	p, err := m.Plan(context.Background(), source, target, analysis.MigrationRequest{Chains: map[fm.PolicyChain]fm.PolicyChain{{RuleSet: "security"}: {RuleSet: "security"}}, Zones: map[fm.ID]fm.ID{"inside": "trust", "outside": "untrust"}, Pairs: []analysis.ZonePair{{From: "inside", To: "outside"}}})
	if p != nil || !errors.Is(err, policy.ErrBudget) {
		t.Fatalf("migration visits reset: %v, %v", p, err)
	}
}
