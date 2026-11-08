package analysis_test

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	fm "github.com/gatework/firemon"
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

func TestRiskBatchChargesRepeatedEvidenceCopies(t *testing.T) {
	d := graph(t, [][2]string{{"192.0.2.1", "198.51.100.1"}}).Export()
	d.Rules[0].Spans = make([]fm.Span, 128)
	for i := range d.Rules[0].Spans {
		d.Rules[0].Spans[i] = fm.Span{First: i + 1, Last: i + 1}
	}
	d.Diagnostics = []fm.Diagnostic{{Code: "unknown", Message: "unparsed source"}}
	fw, err := fm.Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	q := request(t, "192.0.2.1", "198.51.100.1")
	definitions := []analysis.RiskDefinition{
		{ID: "first", Version: "1", Mode: analysis.Effective, Relation: analysis.Intersects, Traffic: q.Traffic},
		{ID: "second", Version: "1", Mode: analysis.Effective, Relation: analysis.Intersects, Traffic: q.Traffic},
	}
	for _, allowance := range []struct {
		name   string
		visits int
	}{{"one-copy-only", 256}, {"adequate", 1024}} {
		t.Run(allowance.name, func(t *testing.T) {
			analyzer := analysis.RiskAnalyzer{Engine: policy.Engine{Limits: policy.Limits{MaxVisits: allowance.visits}}}
			one, err := analyzer.Analyze(t.Context(), fw, q, definitions[0])
			if err != nil || len(one) != 1 || one[0].Value != analysis.Unknown || len(one[0].Evidence.Spans) != 128 {
				t.Fatalf("one bounded unknown finding: count=%d err=%v", len(one), err)
			}
			rows, err := analyzer.AnalyzeBatch(t.Context(), fw, []policy.Request{q}, definitions)
			if allowance.name == "one-copy-only" {
				if rows != nil || !errors.Is(err, policy.ErrBudget) {
					t.Fatalf("repeated evidence escaped cumulative budget: count=%d err=%v", len(rows), err)
				}
			} else if err != nil || len(rows) != 2 || rows[0].Findings[0].Value != analysis.Unknown || rows[1].Findings[0].Value != analysis.Unknown {
				t.Fatalf("adequate evidence budget: count=%d err=%v", len(rows), err)
			}
		})
	}
}

func TestRiskBatchKeepsEffectiveContextsAndEvidenceIndependent(t *testing.T) {
	at := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	d := graph(t, [][2]string{{"192.0.2.1", "198.51.100.1"}, {"192.0.2.1", "198.51.100.1"}}).Export()
	d.Schedules = []fm.ScheduleRecord{{Object: fm.Object{ID: "maintenance"}, Timezone: "UTC", Windows: []fm.TimeWindow{{Start: at, End: at.Add(time.Hour)}}}}
	d.Rules[0].Match.Schedule = "maintenance"
	d.Rules[0].Spans = []fm.Span{{First: 3, Last: 5}}
	d.Rules[1].Action = fm.Deny
	fw, err := fm.Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	q := request(t, "192.0.2.1", "198.51.100.1")
	contexts := []policy.Request{q, q, q}
	contexts[0].At, contexts[1].At = at, at.Add(2*time.Hour)
	definitions := []analysis.RiskDefinition{
		{ID: "permit", Version: "1", Mode: analysis.Effective, Relation: analysis.Intersects, Traffic: q.Traffic},
		{ID: "permit-again", Version: "2", Mode: analysis.Effective, Relation: analysis.Equal, Traffic: q.Traffic},
		{ID: "deny", Version: "1", Mode: analysis.Effective, Relation: analysis.Intersects, Traffic: q.Traffic, Actions: []fm.Action{fm.Deny}},
	}
	analyzer := analysis.RiskAnalyzer{}
	rows, err := analyzer.AnalyzeBatch(t.Context(), fw, contexts, definitions)
	if err != nil || len(rows) != 9 {
		t.Fatalf("context findings=%d: %v", len(rows), err)
	}
	want := [][2]analysis.Truth{
		{analysis.True, analysis.False}, {analysis.True, analysis.False}, {analysis.False, analysis.False},
		{analysis.False, analysis.False}, {analysis.False, analysis.False}, {analysis.False, analysis.True},
		{analysis.Unknown, analysis.Unknown}, {analysis.Unknown, analysis.Unknown}, {analysis.Unknown, analysis.Unknown},
	}
	for i, row := range rows {
		if row.Context != i/len(definitions) || row.Definition != i%len(definitions) || len(row.Findings) != 2 {
			t.Fatalf("wrong row coordinates or count: %+v", row)
		}
		for j, finding := range row.Findings {
			if finding.Value != want[i][j] {
				t.Fatalf("context=%d definition=%d rule=%s: value=%v want=%v", row.Context, row.Definition, finding.Rule, finding.Value, want[i][j])
			}
		}
	}
	rows[0].Findings[0].Evidence.Spans[0].First = 99
	if rows[1].Findings[0].Evidence.Spans[0].First != 3 || fw.Rule("1").Record().Spans[0].First != 3 {
		t.Fatal("definition evidence shares mutable spans")
	}
	if !slices.Contains(rows[3].Findings[0].Evidence.Reasons, "schedule-inactive") {
		t.Fatal("inactive context lost its evidence")
	}
	rows[3].Findings[0].Evidence.Reasons[0] = "changed"
	if slices.Contains(rows[4].Findings[0].Evidence.Reasons, "changed") {
		t.Fatal("definition evidence shares mutable reasons")
	}
	// Reusing the analyzer for another immutable graph must query that graph.
	d.Rules[0].Action = fm.Deny
	other, err := fm.Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	again, err := analyzer.AnalyzeBatch(t.Context(), other, contexts[:1], definitions)
	if err != nil || len(again) != 3 || again[0].Findings[0].Value != analysis.False || again[2].Findings[0].Value != analysis.True {
		t.Fatalf("effective partition leaked across graphs: %v", err)
	}
}
