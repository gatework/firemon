package analysis_test

import (
	"context"
	"testing"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/analysis"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/vendors/hillstone"
)

func TestUsageEvidenceRequiresRevisionGraphAndContiguousWindow(t *testing.T) {
	fw := graph(t, [][2]string{{"192.0.2.1", "198.51.100.1"}})
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	window := fm.TimeWindow{Start: at.Add(-24 * time.Hour), End: at}
	digest, err := analysis.RuleDigest(fw, "1")
	if err != nil {
		t.Fatal(err)
	}
	identity, err := analysis.IdentifyRule(fw, "1")
	if err != nil {
		t.Fatal(err)
	}
	base := analysis.UsageObservation{Identity: identity, Revision: "current", RuleDigest: digest, Source: "counter-collector", Start: window.Start, End: window.End, Complete: true}
	for _, tc := range []struct {
		name string
		edit func(*analysis.UsageObservation)
		want analysis.Truth
	}{
		{"complete-zero", func(*analysis.UsageObservation) {}, analysis.True},
		{"reset", func(o *analysis.UsageObservation) { o.CounterReset = true }, analysis.Unknown},
		{"incomplete", func(o *analysis.UsageObservation) { o.Complete = false }, analysis.Unknown},
		{"stale-revision", func(o *analysis.UsageObservation) { o.Revision = "old" }, analysis.Unknown},
		{"stale-rule", func(o *analysis.UsageObservation) { o.RuleDigest = "old" }, analysis.Unknown},
		{"missing-source", func(o *analysis.UsageObservation) { o.Source = "" }, analysis.Unknown},
		{"hits", func(o *analysis.UsageObservation) { o.Hits = 1 }, analysis.False},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := base
			tc.edit(&o)
			rows, err := (analysis.Reclaimer{At: at, Window: window, Revision: "current", Observations: []analysis.UsageObservation{o}}).Analyze(context.Background(), fw)
			if err != nil || len(rows) != 1 || rows[0].Unused != tc.want {
				t.Fatal(rows, err)
			}
		})
	}
	left, right := base, base
	left.End = at.Add(-12 * time.Hour)
	right.Start = left.End
	r := analysis.Reclaimer{At: at, Window: window, Revision: "current", Observations: []analysis.UsageObservation{left, right}}
	rows, err := r.Analyze(context.Background(), fw)
	if err != nil || rows[0].Unused != analysis.True {
		t.Fatal(rows, err)
	}
	r.Observations[1].Start = right.Start.Add(time.Nanosecond)
	rows, err = r.Analyze(context.Background(), fw)
	if err != nil || rows[0].Unused != analysis.Unknown {
		t.Fatal("gap treated as contiguous", rows, err)
	}
}

func TestUnusedDoesNotAuthorizeDeletionAndRedundantBatchKeepsObjects(t *testing.T) {
	fw := graph(t, [][2]string{{"192.0.2.1", "198.51.100.1"}, {"192.0.2.1", "198.51.100.1"}})
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	window := fm.TimeWindow{Start: at.Add(-time.Hour), End: at}
	id, _ := analysis.IdentifyRule(fw, "1")
	digest, _ := analysis.RuleDigest(fw, "1")
	r := analysis.Reclaimer{Planner: plan.Planner{Renderer: hillstone.Renderer{}}, At: at, Window: window, Revision: "current", Observations: []analysis.UsageObservation{{Identity: id, Revision: "current", RuleDigest: digest, Source: "counter", Start: window.Start, End: at, Complete: true}}}
	rows, err := r.Analyze(context.Background(), fw)
	if err != nil || rows[0].Unused != analysis.True || rows[0].Removable || rows[1].Redundant != analysis.True {
		t.Fatal(rows, err)
	}
	if _, err := r.Plan(context.Background(), fw, []fm.ID{"1"}); err == nil {
		t.Fatal("unused granted deletion authority")
	}
	p, err := r.Plan(context.Background(), fw, []fm.ID{"2"})
	if err != nil {
		t.Fatal(err)
	}
	if p.After().Rule("2") != nil || len(p.After().Addresses()) != len(fw.Addresses()) {
		t.Fatal("shared objects removed")
	}
	if _, err := p.Verify(context.Background(), p.After()); err != nil {
		t.Fatal(err)
	}
	changed := fw.Export()
	changed.Addresses[0].FQDN = "changed.invalid"
	other, err := fm.Seal(changed)
	if err != nil {
		t.Fatal(err)
	}
	otherDigest, err := analysis.RuleDigest(other, "1")
	if err != nil || otherDigest == digest {
		t.Fatal("referenced declaration excluded from rule digest")
	}
}
