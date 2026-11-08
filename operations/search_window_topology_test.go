package operations_test

import (
	"errors"
	"testing"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/inventory"
	"github.com/gatework/firemon/operations"
	"github.com/gatework/firemon/policy"
)

func searchWindowTopologyRequest(t *testing.T, revision string, view inventory.View, window fm.TimeWindow) operations.BatchRequest {
	t.Helper()
	return operations.BatchRequest{
		Version: 1,
		Topology: &inventory.Topology{Version: 1, Bindings: []inventory.Binding{
			{Device: "edge", Revision: revision, Zone: "outside", Role: inventory.Protection, View: view, Networks: []flow.AddressRange{searchTimeRange(t, "192.0.2.0/24")}},
			{Device: "edge", Revision: revision, Zone: "inside", Role: inventory.Protection, View: view, Networks: []flow.AddressRange{searchTimeRange(t, "10.0.0.0/24")}},
			{Device: "edge", Revision: revision, Zone: "outside", Role: inventory.Ingress, View: view, Networks: []flow.AddressRange{searchTimeRange(t, "192.0.2.0/24")}},
		}},
		Requests: []operations.AccessRequest{{
			Traffic: searchNATTraffic(t, "192.0.2.20/32", "10.0.0.10/32", flow.Interval{Low: 1443, High: 1443}),
			View:    view, Window: &window,
		}},
	}
}

func searchWindowTopologyData(t *testing.T, active fm.TimeWindow) fm.Data {
	t.Helper()
	data := searchNATData(t, "edge", "203.0.113.10/32", "10.0.0.10/32", flow.Interval{Low: 443, High: 443})
	data.Schedules = []fm.ScheduleRecord{{Object: fm.Object{ID: "publish-time"}, Windows: []fm.TimeWindow{active}}}
	data.StaticNATs[0].Match.Schedule = "publish-time"
	return data
}

func TestSearcherTopologyAliasesFollowNATWindow(t *testing.T) {
	start := time.Date(2026, 11, 9, 0, 0, 0, 0, time.UTC)
	active := fm.TimeWindow{Start: start.Add(time.Hour), End: start.Add(2 * time.Hour)}
	window := fm.TimeWindow{Start: start, End: start.Add(3 * time.Hour)}
	for _, view := range []inventory.View{inventory.Real, inventory.Translated} {
		t.Run(string(view), func(t *testing.T) {
			store, revision := publishSearchTime(t, searchWindowTopologyData(t, active))
			searcher, err := operations.NewSearcher(operations.SearcherOptions{Store: store})
			if err != nil {
				t.Fatal(err)
			}
			request := searchWindowTopologyRequest(t, revision, view, window)
			report, err := searcher.Query(t.Context(), request)
			if err != nil || len(report.Inputs) != 1 {
				t.Fatal(report, err)
			}
			if len(report.Inputs[0].Outcomes) != 1 {
				t.Fatalf("scheduled topology alias missing: outcomes=%d issues=%+v", len(report.Inputs[0].Outcomes), report.Issues)
			}
			outcome := report.Inputs[0].Outcomes[0]
			if !publishedNAT(outcome) || outcome.Window == nil || *outcome.Window != active || !outcome.At.Equal(active.Start) {
				t.Fatal("alias did not retain its exact active segment", outcome)
			}
			if outcome.Conditional || !outcome.NAT.Exact || outcome.NAT.PossibleAllocation || !outcome.Policy.Complete {
				t.Fatal("pinned topology lost its exact packet proof", outcome)
			}
			wire := searchNATTraffic(t, "192.0.2.20/32", "203.0.113.10/32", flow.Interval{Low: 443, High: 443})
			assertSearchTraffic(t, outcome.Wire, wire)
			assertSearchTraffic(t, outcome.Real, request.Requests[0].Traffic)
			assertSearchTraffic(t, outcome.NAT.Translated, request.Requests[0].Traffic)
			match := searchRule(t, outcome, "permit")
			original, err := flow.NewTraffic(16, match.Original...)
			if err != nil || !match.EffectiveKnown {
				t.Fatal("alias rule lost original traffic evidence", match, err)
			}
			assertSearchTraffic(t, original, wire)
			if *request.Requests[0].Window != window || !request.Requests[0].At.IsZero() {
				t.Fatal("query mutated the caller's requested lifetime", request)
			}
		})
	}
}

func TestSearcherTopologyAliasesPreserveUnknownCalendar(t *testing.T) {
	start := time.Date(2026, 11, 9, 0, 0, 0, 0, time.UTC)
	window := fm.TimeWindow{Start: start, End: start.Add(3 * time.Hour)}
	data := searchWindowTopologyData(t, window)
	data.Schedules[0].Windows = nil
	data.Schedules[0].Weekly = []fm.WeeklyPeriod{{Windows: []fm.WeeklyWindow{{Day: time.Monday, Start: time.Hour, End: 2 * time.Hour}}}}
	store, revision := publishSearchTime(t, data)
	searcher, err := operations.NewSearcher(operations.SearcherOptions{Store: store})
	if err != nil {
		t.Fatal(err)
	}
	request := searchWindowTopologyRequest(t, revision, inventory.Real, window)
	report, err := searcher.Query(t.Context(), request)
	if err != nil || len(report.Inputs) != 1 || len(report.Inputs[0].Outcomes) != 0 {
		t.Fatal("unknown calendar created an established alias", report, err)
	}
	for _, issue := range report.Issues {
		if issue.Code == "unknown_alias" && issue.TrafficView == string(inventory.Real) {
			assertSearchTraffic(t, issue.Traffic, request.Requests[0].Traffic)
			return
		}
	}
	t.Fatal("unknown alias evidence was discarded", report)
}

func TestSearcherTopologyAliasWindowBudgets(t *testing.T) {
	start := time.Date(2026, 11, 9, 0, 0, 0, 0, time.UTC)
	active := fm.TimeWindow{Start: start.Add(time.Hour), End: start.Add(2 * time.Hour)}
	window := fm.TimeWindow{Start: start, End: start.Add(3 * time.Hour)}
	for _, tc := range []struct {
		name   string
		limits policy.Limits
		spans  int
	}{
		{name: "time partitions", limits: policy.Limits{MaxCombinations: 2}},
		{name: "nested copy", limits: policy.Limits{MaxVisits: 128}, spans: 256},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := searchWindowTopologyData(t, active)
			for range tc.spans {
				data.StaticNATs[0].Spans = append(data.StaticNATs[0].Spans, fm.Span{First: 1, Last: 1})
			}
			store, revision := publishSearchTime(t, data)
			searcher, err := operations.NewSearcher(operations.SearcherOptions{Store: store, Engine: policy.Engine{Limits: tc.limits}})
			if err != nil {
				t.Fatal(err)
			}
			report, err := searcher.Query(t.Context(), searchWindowTopologyRequest(t, revision, inventory.Real, window))
			if !errors.Is(err, policy.ErrBudget) {
				t.Fatal("topology alias escaped the window work budget", report, err)
			}
			for _, input := range report.Inputs {
				if len(input.Outcomes) != 0 {
					t.Fatal("failed time partition retained a successful alias", report)
				}
			}
		})
	}
}
