package analysis_test

import (
	"context"
	"errors"
	"math/rand"
	"reflect"
	"slices"
	"testing"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/analysis"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/policy"
)

func TestReclaimerChargesRuleObservationsBeforeAnalysis(t *testing.T) {
	fw := graph(t, [][2]string{{"192.0.2.1", "198.51.100.1"}})
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	req := analysis.ReclamationRequest{At: at, Revision: "current", Window: fm.TimeWindow{Start: at.Add(-time.Hour), End: at}, Observations: make([]analysis.UsageObservation, 65)}
	r := analysis.Reclaimer{Planner: plan.Planner{Engine: policy.Engine{Limits: policy.Limits{Rules: 64}}}}
	rows, err := r.Analyze(context.Background(), fw, req)
	if !errors.Is(err, policy.ErrBudget) || rows != nil {
		t.Fatalf("unbounded evidence: %v %v", rows, err)
	}
}
func TestReclamationRequestValidationIsShared(t *testing.T) {
	fw := graph(t, [][2]string{{"192.0.2.1", "198.51.100.1"}})
	r := analysis.Reclaimer{}
	if _, err := r.Analyze(context.Background(), fw, analysis.ReclamationRequest{MemberObservations: []analysis.MemberUsageObservation{{}}}); !errors.Is(err, analysis.ErrInvalid) {
		t.Fatalf("member evidence without window: %v", err)
	}
	if _, err := r.AnalyzeMembers(context.Background(), fw, analysis.ReclamationRequest{Observations: []analysis.UsageObservation{{}}}); !errors.Is(err, analysis.ErrInvalid) {
		t.Fatalf("rule evidence without window: %v", err)
	}
}

// The oracle enumerates unit cells instead of sorting/merging intervals.
func TestUsageIndexMatchesDiscreteCoverageOracle(t *testing.T) {
	fw := graph(t, [][2]string{{"192.0.2.1", "198.51.100.1"}})
	identity, _ := analysis.IdentifyRule(fw, "1")
	digest, _ := analysis.RuleDigest(fw, "1")
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	start := at.Add(-4 * time.Hour)
	rng := rand.New(rand.NewSource(17))
	for trial := 0; trial < 250; trial++ {
		req := analysis.ReclamationRequest{At: at, Revision: "current", Window: fm.TimeWindow{Start: start, End: at}}
		var covered [4]bool
		positive, uncertain := false, false
		for j := 0; j < 12; j++ {
			lo, hi := rng.Intn(8)-2, rng.Intn(8)-2
			hits := uint64(rng.Intn(4) / 3)
			reset := rng.Intn(10) == 0
			complete := rng.Intn(10) != 0
			stale := rng.Intn(10) == 0
			o := analysis.UsageObservation{Identity: identity, Revision: "current", RuleDigest: digest, Source: "counter", Start: start.Add(time.Duration(lo) * time.Hour), End: start.Add(time.Duration(hi) * time.Hour), Hits: hits, CounterReset: reset, Complete: complete}
			if stale {
				o.Revision = "stale"
			}
			req.Observations = append(req.Observations, o)
			if stale {
				continue
			}
			if lo >= hi {
				uncertain = true
				continue
			}
			if hi <= 0 || lo >= 4 {
				continue
			}
			if hits > 0 {
				if lo >= 0 && hi <= 4 {
					positive = true
				} else {
					uncertain = true
				}
				continue
			}
			if reset || !complete {
				uncertain = true
				continue
			}
			for cell := 0; cell < 4; cell++ {
				if lo <= cell && hi >= cell+1 {
					covered[cell] = true
				}
			}
		}
		want := analysis.Unknown
		if positive {
			want = analysis.False
		} else if !uncertain && covered == [4]bool{true, true, true, true} {
			want = analysis.True
		}
		saved := slices.Clone(req.Observations)
		rows, err := (analysis.Reclaimer{}).Analyze(context.Background(), fw, req)
		if err != nil || len(rows) != 1 || rows[0].Unused != want {
			t.Fatalf("trial %d want %v: %v %v", trial, want, rows, err)
		}
		if !reflect.DeepEqual(saved, req.Observations) {
			t.Fatal("observations mutated")
		}
	}
}
