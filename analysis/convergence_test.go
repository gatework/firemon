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
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/policy"
	"github.com/gatework/firemon/vendors/hillstone"
)

func graph(t *testing.T, pairs [][2]string) *fm.Firewall {
	t.Helper()
	d := fm.Data{Metadata: fm.Metadata{Device: "fw", Vendor: "hillstone"}}
	seen := make(map[fm.ID]bool)
	for i, pair := range pairs {
		q := request(t, pair[0], pair[1])
		box := q.Traffic.Regions()[0]
		for _, r := range []flow.AddressRange{box.Source, box.Destination} {
			id := fm.ID(r.First.String())
			if !seen[id] {
				d.Addresses = append(d.Addresses, fm.AddressRecord{Object: fm.Object{ID: id, Name: string(id)}, Ranges: []flow.AddressRange{r}})
				seen[id] = true
			}
		}
		id := fm.ID(string(rune('1' + i)))
		d.Rules = append(d.Rules, fm.RuleRecord{Object: fm.Object{ID: id}, Position: i, RuleSet: "security", Action: fm.Permit, Log: fm.Irrelevant, LogStart: fm.Irrelevant, LogEnd: fm.Irrelevant, Match: fm.Match{AnyFromZone: true, AnyToZone: true, AnyService: true, Sources: []fm.AddressRef{{Kind: fm.AddressObject, ID: fm.ID(pair[0])}}, Destinations: []fm.AddressRef{{Kind: fm.AddressObject, ID: fm.ID(pair[1])}}}})
	}
	fw, err := fm.Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	return fw
}

func TestConvergenceCandidatesDiscoverContainAndCombineDeterministically(t *testing.T) {
	fw := graph(t, [][2]string{{"192.0.2.1", "198.51.100.1"}, {"192.0.2.1", "198.51.100.1"}, {"192.0.2.2", "198.51.100.1"}})
	c := analysis.Converger{Planner: plan.Planner{Renderer: hillstone.Renderer{}}}
	candidates, err := c.Candidates(context.Background(), fw, time.Time{})
	if err != nil || len(candidates) != 3 {
		t.Fatalf("candidate discovery: %v, %v", candidates, err)
	}
	for i, candidate := range candidates {
		want := [][]fm.ID{{"1", "2"}, {"1", "3"}, {"2", "3"}}[i]
		if !slices.Equal(candidate.Rules, want) || candidate.Plan == nil || candidate.Rejection != nil || candidate.Reason == "" {
			t.Fatalf("candidate %d: %+v", i, candidate)
		}
		if i == 0 && candidate.Kind != analysis.ContainRules || i > 0 && candidate.Kind != analysis.CombineRules {
			t.Fatalf("candidate kind %d: %+v", i, candidate)
		}
		if _, ok := candidate.Plan.Preservation(); !ok {
			t.Fatal("candidate lacks whole-plan proof")
		}
		if _, err := candidate.Plan.Verify(context.Background(), candidate.Plan.After()); err != nil {
			t.Fatal(err)
		}
		if len(candidate.Plan.After().Addresses()) != len(fw.Addresses()) {
			t.Fatal("candidate removed shared objects")
		}
	}
	d := fw.Export()
	slices.Reverse(d.Rules)
	reordered, err := fm.Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	again, err := c.Candidates(context.Background(), reordered, time.Time{})
	if err != nil || len(again) != len(candidates) {
		t.Fatal(again, err)
	}
	for i := range again {
		if !slices.Equal(again[i].Rules, candidates[i].Rules) {
			t.Fatal("storage order changed discovery")
		}
	}
	if len(fw.Rules()) != 3 {
		t.Fatal("discovery applied a plan")
	}
	c.MaxComparisons = 1
	if partial, err := c.Candidates(context.Background(), fw, time.Time{}); !errors.Is(err, policy.ErrBudget) || len(partial) != 0 {
		t.Fatalf("budget returned partial success: %v, %v", partial, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Candidates(ctx, fw, time.Time{}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestConvergenceCandidatesRetainUnsafePairRejections(t *testing.T) {
	for _, tc := range []struct {
		name  string
		pairs [][2]string
		deny  bool
	}{
		{"cross-pairs", [][2]string{{"192.0.2.1", "198.51.100.1"}, {"192.0.2.2", "198.51.100.2"}}, false},
		{"deny-shadowing", [][2]string{{"192.0.2.1", "198.51.100.1"}, {"192.0.2.2", "198.51.100.1"}, {"192.0.2.2", "198.51.100.1"}}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fw := graph(t, tc.pairs)
			if tc.deny {
				d := fw.Export()
				d.Rules[1].Action = fm.Deny
				var err error
				fw, err = fm.Seal(d)
				if err != nil {
					t.Fatal(err)
				}
			}
			rows, err := (analysis.Converger{Planner: plan.Planner{Renderer: hillstone.Renderer{}}}).Candidates(context.Background(), fw, time.Time{})
			if err != nil || len(rows) != 1 || rows[0].Plan != nil || rows[0].Rejection == nil || rows[0].Reason == "" {
				t.Fatalf("unsafe candidate should be explained: %+v, %v", rows, err)
			}
		})
	}
}

func TestConvergenceCandidateFindsStrictContainment(t *testing.T) {
	d := graph(t, [][2]string{{"192.0.2.1", "198.51.100.1"}, {"192.0.2.2", "198.51.100.1"}}).Export()
	d.Rules[0].Match.Sources = append(d.Rules[0].Match.Sources, d.Rules[1].Match.Sources...)
	fw, err := fm.Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := (analysis.Converger{Planner: plan.Planner{Renderer: hillstone.Renderer{}}}).Candidates(context.Background(), fw, time.Time{})
	if err != nil || len(rows) != 1 || rows[0].Kind != analysis.ContainRules || rows[0].Plan == nil || rows[0].Rejection != nil {
		t.Fatal(rows, err)
	}
	if rows[0].Plan.After().Rule("2") != nil || len(rows[0].Plan.After().Rule("1").Record().Match.Sources) != 2 {
		t.Fatal("contained rule was not removed without widening")
	}
}

func TestConvergenceProvesWholePlanAndKeepsSharedObjects(t *testing.T) {
	fw := graph(t, [][2]string{{"192.0.2.1", "198.51.100.1"}, {"192.0.2.2", "198.51.100.1"}})
	p, err := (analysis.Converger{Planner: plan.Planner{Renderer: hillstone.Renderer{}}}).Plan(context.Background(), fw, []fm.ID{"2", "1"}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.After().Rules()) != 1 || p.After().Rule("1") == nil || len(p.After().Addresses()) != len(fw.Addresses()) || len(fw.Rules()) != 2 {
		t.Fatal("wrong survivor/shared object ownership")
	}
	if _, err := p.Verify(context.Background(), p.After()); err != nil {
		t.Fatal(err)
	}
	if _, ok := p.Preservation(); !ok {
		t.Fatal("missing whole plan proof")
	}
}

func TestConvergenceRejectsCrossPairsAndInterveningDeny(t *testing.T) {
	for _, tc := range []struct {
		name  string
		pairs [][2]string
		deny  bool
		ids   []fm.ID
	}{
		{"cross-pairs", [][2]string{{"192.0.2.1", "198.51.100.1"}, {"192.0.2.2", "198.51.100.2"}}, false, []fm.ID{"1", "2"}},
		{"deny-between", [][2]string{{"192.0.2.1", "198.51.100.1"}, {"192.0.2.2", "198.51.100.1"}, {"192.0.2.2", "198.51.100.1"}}, true, []fm.ID{"1", "3"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fw := graph(t, tc.pairs)
			if tc.deny {
				d := fw.Export()
				d.Rules[1].Action = fm.Deny
				var err error
				fw, err = fm.Seal(d)
				if err != nil {
					t.Fatal(err)
				}
			}
			if _, err := (analysis.Converger{Planner: plan.Planner{Renderer: hillstone.Renderer{}}}).Plan(context.Background(), fw, tc.ids, time.Time{}); err == nil {
				t.Fatal("unsafe convergence accepted")
			}
		})
	}
}

func TestConvergenceChargesIncompatiblePairsBeforeFiltering(t *testing.T) {
	d := graph(t, [][2]string{{"192.0.2.1", "198.51.100.1"}, {"192.0.2.2", "198.51.100.1"}, {"192.0.2.3", "198.51.100.1"}}).Export()
	for i := range d.Rules {
		d.Rules[i].Description = string(rune('a' + i))
	}
	fw, err := fm.Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	c := analysis.Converger{MaxComparisons: 2}
	if rows, err := c.Candidates(context.Background(), fw, time.Time{}); !errors.Is(err, policy.ErrBudget) || rows != nil {
		t.Fatalf("incompatible pairs escaped budget: %v %v", rows, err)
	}
	c.MaxComparisons = 3
	if rows, err := c.Candidates(context.Background(), fw, time.Time{}); err != nil || len(rows) != 0 {
		t.Fatalf("exact pair budget: %v %v", rows, err)
	}
}
