package analysis_test

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/analysis"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/policy"
)

func memberGraph(t *testing.T) *fm.Firewall {
	t.Helper()
	d := graph(t, [][2]string{{"192.0.2.1", "198.51.100.1"}}).Export()
	leaf := fm.AddressRef{Kind: fm.AddressObject, ID: "192.0.2.1"}
	d.AddressGroups = []fm.AddressGroupRecord{
		{Object: fm.Object{ID: "inner"}, Members: []fm.AddressRef{leaf}},
		{Object: fm.Object{ID: "outer"}, Members: []fm.AddressRef{{Kind: fm.AddressGroupObject, ID: "inner"}, leaf}},
	}
	d.Rules[0].Match.Sources = []fm.AddressRef{{Kind: fm.AddressGroupObject, ID: "outer"}}
	// Same object in another role must not inherit source observations.
	d.Rules[0].Match.Destinations = []fm.AddressRef{leaf}
	term := request(t, "192.0.2.1", "192.0.2.1").Traffic.Boxes()[0]
	d.Services = []fm.ServiceRecord{{Object: fm.Object{ID: "web"}, Terms: []fm.ServiceTerm{{Protocol: term.Protocol, SourcePort: term.SourcePort, DestinationPort: term.DestinationPort, ICMPType: term.ICMPType, ICMPCode: term.ICMPCode}}}}
	d.ServiceGroups = []fm.ServiceGroupRecord{{Object: fm.Object{ID: "services"}, Members: []fm.ServiceRef{{Kind: fm.ServiceObject, ID: "web"}}}}
	d.Rules[0].Match.AnyService = false
	d.Rules[0].Match.Services = []fm.ServiceRef{{Kind: fm.ServiceGroupObject, ID: "services"}}
	fw, err := fm.Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	return fw
}

func TestMemberUsageBindsRolesAndKeepsEveryNestedReferencePath(t *testing.T) {
	fw := memberGraph(t)
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	window := fm.TimeWindow{Start: at.Add(-time.Hour), End: at}
	rule, _ := analysis.IdentifyRule(fw, "1")
	identity := analysis.MemberIdentity{Rule: rule, Role: analysis.Source, Kind: fm.AddressObject, ID: "192.0.2.1"}
	o := analysis.MemberUsageObservation{Identity: identity, Revision: "v1", GraphDigest: fw.SemanticDigest(), Source: "log-collector", Start: window.Start, End: window.End, Complete: true}
	r := analysis.Reclaimer{At: at, Window: window, Revision: "v1", MemberObservations: []analysis.MemberUsageObservation{o}}
	rows, err := r.AnalyzeMembers(context.Background(), fw)
	if err != nil {
		t.Fatal(err)
	}
	found := make(map[analysis.MemberIdentity]analysis.MemberUsage)
	for _, row := range rows {
		found[row.Identity] = row
		if row.Removable {
			t.Fatal("member counters authorized deletion", row)
		}
	}
	row, ok := found[identity]
	if !ok || row.Unused != analysis.True || row.Revision != "v1" || row.GraphDigest != fw.SemanticDigest() || len(row.Paths) != 2 {
		t.Fatalf("nested member evidence missing: %v", rows)
	}
	deep := []analysis.MemberReference{{Kind: fm.AddressGroupObject, ID: "outer"}, {Kind: fm.AddressGroupObject, ID: "inner"}, {Kind: fm.AddressObject, ID: "192.0.2.1"}}
	if !slices.ContainsFunc(row.Paths, func(path []analysis.MemberReference) bool { return slices.Equal(path, deep) }) {
		t.Fatalf("nested provenance lost: %v", row.Paths)
	}
	identity.Role = analysis.Destination
	if found[identity].Unused != analysis.Unknown {
		t.Fatal("source evidence reused for destination", found[identity])
	}
	service := analysis.MemberIdentity{Rule: rule, Role: analysis.Service, Kind: fm.ServiceObject, ID: "web"}
	if len(found[service].Paths) != 1 || len(found[service].Paths[0]) != 2 || found[service].Unused != analysis.Unknown {
		t.Fatal("nested service provenance lost", rows)
	}
	if _, err := r.Plan(context.Background(), fw, []fm.ID{"1"}); err == nil {
		t.Fatal("member absence authorized whole-rule deletion")
	}
}

func TestMemberUsageRequiresCompleteBoundContiguousObservations(t *testing.T) {
	fw := memberGraph(t)
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	window := fm.TimeWindow{Start: at.Add(-time.Hour), End: at}
	rule, _ := analysis.IdentifyRule(fw, "1")
	id := analysis.MemberIdentity{Rule: rule, Role: analysis.Source, Kind: fm.AddressObject, ID: "192.0.2.1"}
	base := analysis.MemberUsageObservation{Identity: id, Revision: "v1", GraphDigest: fw.SemanticDigest(), Source: "counter", Start: window.Start, End: window.End, Complete: true}
	for _, tc := range []struct {
		name string
		edit func(*analysis.MemberUsageObservation)
		want analysis.Truth
	}{
		{"zero", func(*analysis.MemberUsageObservation) {}, analysis.True},
		{"hit", func(o *analysis.MemberUsageObservation) { o.Hits = 1 }, analysis.False},
		{"hit-time-not-localized", func(o *analysis.MemberUsageObservation) { o.Hits = 1; o.Start = o.Start.Add(-time.Hour) }, analysis.Unknown},
		{"zero-over-larger-window", func(o *analysis.MemberUsageObservation) { o.Start = o.Start.Add(-time.Hour) }, analysis.True},
		{"reset", func(o *analysis.MemberUsageObservation) { o.CounterReset = true }, analysis.Unknown},
		{"incomplete", func(o *analysis.MemberUsageObservation) { o.Complete = false }, analysis.Unknown},
		{"revision", func(o *analysis.MemberUsageObservation) { o.Revision = "old" }, analysis.Unknown},
		{"digest", func(o *analysis.MemberUsageObservation) { o.GraphDigest = "old" }, analysis.Unknown},
		{"source", func(o *analysis.MemberUsageObservation) { o.Source = "" }, analysis.Unknown},
		{"role", func(o *analysis.MemberUsageObservation) { o.Identity.Role = analysis.Destination }, analysis.Unknown},
		{"member", func(o *analysis.MemberUsageObservation) { o.Identity.ID = "inner" }, analysis.Unknown},
		{"kind", func(o *analysis.MemberUsageObservation) { o.Identity.Kind = fm.AddressGroupObject }, analysis.Unknown},
		{"rule", func(o *analysis.MemberUsageObservation) { o.Identity.Rule.ID = "other" }, analysis.Unknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := base
			tc.edit(&o)
			rows, err := (analysis.Reclaimer{At: at, Window: window, Revision: "v1", MemberObservations: []analysis.MemberUsageObservation{o}}).AnalyzeMembers(context.Background(), fw)
			if err != nil {
				t.Fatal(err)
			}
			for _, row := range rows {
				if row.Identity == id && row.Unused != tc.want {
					t.Fatal(row)
				}
			}
		})
	}
	left, right := base, base
	left.End = window.Start.Add(30 * time.Minute)
	right.Start = left.End
	r := analysis.Reclaimer{At: at, Window: window, Revision: "v1", MemberObservations: []analysis.MemberUsageObservation{right, left}}
	check := func(want analysis.Truth) {
		t.Helper()
		rows, err := r.AnalyzeMembers(context.Background(), fw)
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range rows {
			if row.Identity == id && row.Unused != want {
				t.Fatal(row)
			}
		}
	}
	check(analysis.True)
	r.MemberObservations[0].Start = right.Start.Add(time.Nanosecond)
	check(analysis.Unknown)
	r.Planner = plan.Planner{Engine: policy.Engine{Limits: policy.Limits{Rules: 2}}}
	if _, err := r.AnalyzeMembers(context.Background(), fw); !errors.Is(err, policy.ErrBudget) {
		t.Fatalf("member expansion budget ignored: %v", err)
	}
}
