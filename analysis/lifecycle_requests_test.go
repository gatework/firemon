package analysis_test

import (
	"context"
	"maps"
	"reflect"
	"slices"
	"testing"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/analysis"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/policy"
	"github.com/gatework/firemon/vendors/hillstone"
	"github.com/gatework/firemon/vendors/paloalto"
)

func TestReclaimerRequestsAreIndependent(t *testing.T) {
	fw := memberGraph(t)
	r := analysis.Reclaimer{}
	identity, _ := analysis.IdentifyRule(fw, "1")
	digest, _ := analysis.RuleDigest(fw, "1")
	member := analysis.MemberIdentity{Rule: identity, Role: analysis.Source, Kind: fm.AddressObject, ID: "192.0.2.1"}
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	requests := make([]analysis.ReclamationRequest, 2)
	for i, revision := range []string{"first", "second"} {
		end := at.Add(time.Duration(i) * time.Hour)
		window := fm.TimeWindow{Start: end.Add(-time.Hour), End: end}
		requests[i] = analysis.ReclamationRequest{At: end, Revision: revision, Window: window,
			Observations:       []analysis.UsageObservation{{Identity: identity, Revision: revision, RuleDigest: digest, Source: "counter", Start: window.Start, End: end, Complete: true, Hits: uint64(i)}},
			MemberObservations: []analysis.MemberUsageObservation{{Identity: member, Revision: revision, GraphDigest: fw.SemanticDigest(), Source: "counter", Start: window.Start, End: end, Complete: true, Hits: uint64(i)}}}
	}
	check := func(t *testing.T, request analysis.ReclamationRequest, want analysis.Truth) {
		t.Helper()
		before := request
		before.Observations = slices.Clone(request.Observations)
		before.MemberObservations = slices.Clone(request.MemberObservations)
		rows, err := r.Analyze(context.Background(), fw, request)
		if err != nil || len(rows) != 1 || rows[0].Unused != want || rows[0].RemovalCandidate {
			t.Fatalf("rule evidence crossed requests: %+v, %v", rows, err)
		}
		members, err := r.AnalyzeMembers(context.Background(), fw, request)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, row := range members {
			if row.Revision != request.Revision {
				t.Fatalf("member evidence crossed requests: %+v", row)
			}
			if row.Identity == member {
				found = true
				if row.Unused != want {
					t.Fatalf("wrong member usage: %+v", row)
				}
			}
		}
		if !found || !reflect.DeepEqual(request, before) {
			t.Fatal("request changed or member evidence missing")
		}
	}
	for i, want := range []analysis.Truth{analysis.True, analysis.False} {
		check(t, requests[i], want)
		t.Run(requests[i].Revision, func(t *testing.T) {
			t.Parallel()
			check(t, requests[i], want)
		})
	}
	// Reusing a service after both calls must still use the first revision.
	check(t, requests[0], analysis.True)
}

func TestLifecyclePreservationUsesEachCallTime(t *testing.T) {
	fw := graph(t, [][2]string{{"192.0.2.1", "198.51.100.1"}, {"192.0.2.1", "198.51.100.1"}})
	planner := plan.Planner{Renderer: hillstone.Renderer{}}
	r, c := analysis.Reclaimer{Planner: planner}, analysis.Converger{Planner: planner}
	check := func(t *testing.T, at time.Time) {
		t.Helper()
		ids := []fm.ID{"2"}
		p, err := r.Plan(context.Background(), fw, analysis.ReclamationRequest{At: at}, ids)
		if err != nil {
			t.Fatal(err)
		}
		plans := []*plan.Plan{p}
		convergeIDs := []fm.ID{"2", "1"}
		p, err = c.Plan(context.Background(), fw, convergeIDs, at)
		if err != nil {
			t.Fatal(err)
		}
		plans = append(plans, p)
		rows, err := c.Candidates(context.Background(), fw, at)
		if err != nil || len(rows) != 1 || rows[0].Rejection != nil || rows[0].Plan == nil {
			t.Fatalf("candidate proof: %+v, %v", rows, err)
		}
		plans = append(plans, rows[0].Plan)
		for _, p := range plans {
			proof, ok := p.Preservation()
			if !ok || !proof.From.Equal(at) {
				t.Fatalf("call time lost: %+v", proof)
			}
			if _, err := p.Verify(context.Background(), p.After()); err != nil {
				t.Fatal(err)
			}
		}
		if !slices.Equal(ids, []fm.ID{"2"}) || !slices.Equal(convergeIDs, []fm.ID{"2", "1"}) || fw.Rule("2") == nil {
			t.Fatal("selection or graph changed")
		}
	}
	for _, at := range []time.Time{time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)} {
		check(t, at)
		t.Run(at.Format("2006-01"), func(t *testing.T) {
			t.Parallel()
			check(t, at)
		})
	}
}

func TestMigrationRequestsAreIndependent(t *testing.T) {
	source, target := translationGraphs(t)
	d := target.Export()
	d.Zones = append(d.Zones, fm.ZoneRecord{Object: fm.Object{ID: "other-in"}}, fm.ZoneRecord{Object: fm.Object{ID: "other-out"}})
	var err error
	target, err = fm.Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	x := analysis.PolicyMigrator{Planner: plan.Planner{Renderer: paloalto.Renderer{}}}
	check := func(t *testing.T, from, to fm.ID, at time.Time) {
		t.Helper()
		migration := analysis.MigrationRequest{At: at, Zones: map[fm.ID]fm.ID{"inside": from, "outside": to}, Chains: map[fm.PolicyChain]fm.PolicyChain{{RuleSet: "security"}: {RuleSet: "security"}}, Pairs: []analysis.ZonePair{{From: "inside", To: "outside"}}, Rules: []fm.ID{"2"}}
		before := migration
		before.Zones, before.Chains = maps.Clone(migration.Zones), maps.Clone(migration.Chains)
		before.Pairs, before.Rules = slices.Clone(migration.Pairs), slices.Clone(migration.Rules)
		p, err := x.Plan(context.Background(), source, target, migration)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(migration, before) {
			t.Fatal("migration modified request inputs")
		}
		// The returned plan owns its proof independently of mutable request data.
		migration.Zones["inside"] = "invalid"
		clear(migration.Chains)
		migration.Pairs[0].From, migration.Rules[0] = "invalid", "invalid"
		if _, err := p.Verify(context.Background(), p.After()); err != nil {
			t.Fatalf("plan retained request inputs: %v", err)
		}
		for _, pair := range []analysis.ZonePair{{From: "trust", To: "untrust"}, {From: "other-in", To: "other-out"}} {
			q := request(t, "192.0.2.2", "198.51.100.1")
			q.FromZone, q.ToZone, q.At = pair.From, pair.To, at
			result, err := (policy.Engine{}).Query(context.Background(), p.After(), q)
			if err != nil || !result.Complete || (!result.Allowed.Empty()) != (pair.From == from) {
				t.Fatalf("zone mapping crossed requests: %+v, %v", result, err)
			}
		}
	}
	for i, pair := range []analysis.ZonePair{{From: "trust", To: "untrust"}, {From: "other-in", To: "other-out"}} {
		at := time.Date(2026, time.Month(i+1), 1, 0, 0, 0, 0, time.UTC)
		check(t, pair.From, pair.To, at)
		t.Run(string(pair.From), func(t *testing.T) {
			t.Parallel()
			check(t, pair.From, pair.To, at)
		})
	}
}

func TestReclaimerExpiryUsesRequestTimeAndPreservesFutureProof(t *testing.T) {
	end := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	d := graph(t, [][2]string{{"192.0.2.1", "198.51.100.1"}}).Export()
	d.Schedules = []fm.ScheduleRecord{{Object: fm.Object{ID: "window"}, Windows: []fm.TimeWindow{{Start: end.Add(-time.Hour), End: end}}}}
	d.Rules[0].Match.Schedule = "window"
	fw, err := fm.Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	r := analysis.Reclaimer{Planner: plan.Planner{Renderer: hillstone.Renderer{}}}
	for _, tc := range []struct {
		at      time.Time
		expired analysis.Truth
	}{{end.Add(-time.Nanosecond), analysis.False}, {end, analysis.True}, {end.Add(time.Hour), analysis.True}} {
		request := analysis.ReclamationRequest{At: tc.at}
		rows, err := r.Analyze(context.Background(), fw, request)
		if err != nil || len(rows) != 1 || rows[0].Expired != tc.expired || rows[0].RemovalCandidate != (tc.expired == analysis.True) {
			t.Fatalf("expiry at %v: %+v, %v", tc.at, rows, err)
		}
		p, err := r.Plan(context.Background(), fw, request, []fm.ID{"1"})
		if tc.expired != analysis.True {
			if err == nil {
				t.Fatal("active schedule authorized deletion")
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		proof, ok := p.Preservation()
		if !ok || !proof.From.Equal(tc.at) {
			t.Fatal("expiry plan lost future preservation boundary")
		}
		if _, err := p.Verify(context.Background(), p.After()); err != nil {
			t.Fatal(err)
		}
	}
}
