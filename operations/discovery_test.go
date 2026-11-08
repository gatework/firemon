package operations_test

import (
	"slices"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/inventory"
	"github.com/gatework/firemon/operations"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/snapshot"
)

func TestSearcherLoadsEachRevisionOncePerBatchWithoutRetention(t *testing.T) {
	for _, test := range []struct {
		name   string
		limits inventory.CacheLimits
	}{
		{"source too large", inventory.CacheLimits{MaxSourceBytes: 1}},
		{"one retained revision", inventory.CacheLimits{MaxEntries: 1}},
	} {
		t.Run(test.name, func(t *testing.T) {
			store, err := snapshot.Open(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			publishSearch(t, store, searchGraph(t, "source", "192.0.2.1/24", "203.0.113.1/24", fm.Permit), "", "source")
			publishSearch(t, store, searchGraph(t, "destination", "203.0.113.2/24", "198.51.100.1/24", fm.Permit), "", "destination")
			counted := &countedBatchStore{Store: store}
			cache, err := inventory.NewCache(counted, test.limits)
			if err != nil {
				t.Fatal(err)
			}
			searcher, err := operations.NewSearcher(operations.SearcherOptions{Store: cache})
			if err != nil {
				t.Fatal(err)
			}
			request := operations.AccessRequest{Src: "192.0.2.10", Dst: "198.51.100.10", Service: "443"}
			report, err := searcher.Query(t.Context(), operations.BatchRequest{Version: 1, Requests: []operations.AccessRequest{request, request}})
			if err != nil || len(report.Inputs) != 2 {
				t.Fatal(report, err)
			}
			for _, input := range report.Inputs {
				for _, device := range []string{"source", "destination"} {
					if !slices.ContainsFunc(input.Outcomes, func(outcome operations.TargetOutcome) bool {
						return outcome.Device == device && len(outcome.Matches) != 0
					}) {
						t.Fatal("cache eviction hid a matching device", device, input)
					}
				}
			}
			if counted.loads != 2 || counted.manifests != 1 {
				t.Fatal("one batch reloaded an immutable revision", counted.loads, counted.manifests)
			}
		})
	}
}

func TestSearcherMissingInterfacesKeepsConditionalDeclarations(t *testing.T) {
	for _, test := range []struct {
		name    string
		unknown bool
		partial bool
	}{
		{"known declaration", false, false},
		{"unknown declaration", true, false},
		{"partial interfaces", false, true},
		{"partial interfaces with unknown declaration", true, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			data := searchGraph(t, "fw", "192.0.2.1/24", "198.51.100.1/24", fm.Permit).Export()
			if test.partial {
				data.Interfaces, data.Routes = data.Interfaces[1:], data.Routes[1:]
			} else {
				data.Interfaces, data.Routes = nil, nil
			}
			data.Zones[0].Networks = []flow.AddressRange{searchTimeRange(t, "192.0.2.0/24")}
			data.Rules[0].Match.AnyFromZone = false
			data.Rules[0].Match.FromZones = []fm.ID{"inside"}
			if test.unknown {
				data.Rules[0].Unsupported = []string{"synthetic unknown policy condition"}
			}
			store, _ := publishSearchTime(t, data)
			searcher, err := operations.NewSearcher(operations.SearcherOptions{Store: store})
			if err != nil {
				t.Fatal(err)
			}
			request := operations.BatchRequest{Version: 1, Requests: []operations.AccessRequest{{Src: "192.0.2.10", Dst: "198.51.100.10", Service: "443"}}}
			report, err := searcher.Query(t.Context(), request)
			if err != nil || len(report.Inputs) != 1 || len(report.Inputs[0].Outcomes) == 0 {
				t.Fatal("missing interfaces concealed native declarations", report, err)
			}
			found := false
			for _, outcome := range report.Inputs[0].Outcomes {
				if !outcome.Conditional || outcome.Disposition == plan.BatchCovered {
					t.Fatal("unestablished ingress was marked covered", outcome)
				}
				for _, match := range outcome.Matches {
					if match.Rule != "access" || len(match.Declared) == 0 {
						continue
					}
					found = true
					if outcome.TrafficView != "policy" || len(outcome.NAT.Steps) != 0 {
						t.Fatal("declaration query invented a packet path", outcome)
					}
					if match.DeclaredKnown == test.unknown || test.unknown && (match.EffectiveKnown || !outcome.Policy.Allowed.Empty()) {
						t.Fatal("declaration certainty changed without evidence", match, outcome.Policy)
					}
				}
			}
			if !found {
				t.Fatal("native rule was omitted", report)
			}
			designer, err := operations.NewBatchDesigner(operations.BatchDesignerOptions{Store: store})
			if err != nil {
				t.Fatal(err)
			}
			if design, err := designer.Design(t.Context(), request); err != nil || len(design.Devices) != 0 {
				t.Fatal("unestablished ingress authorized a change", design, err)
			}
		})
	}
}

func TestSearcherKeepsDeclarationsWithoutZones(t *testing.T) {
	for _, test := range []struct {
		name       string
		referenced bool
		keepInside bool
	}{
		{"any zone without a zone table", false, false},
		{"missing native zone references", true, false},
		{"missing destination zone", true, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			data := searchGraph(t, "fw", "192.0.2.1/24", "198.51.100.1/24", fm.Permit).Export()
			data.Interfaces, data.Routes = nil, nil
			if test.keepInside {
				data.Zones = data.Zones[:1]
			} else {
				data.Zones = nil
			}
			data.Addresses = append(data.Addresses, fm.AddressRecord{Object: fm.Object{ID: "association"}, Ranges: []flow.AddressRange{searchTimeRange(t, "192.0.2.0/24")}})
			if test.referenced {
				data.Rules[0].Match.AnyFromZone, data.Rules[0].Match.AnyToZone = false, false
				data.Rules[0].Match.FromZones, data.Rules[0].Match.ToZones = []fm.ID{"inside"}, []fm.ID{"outside"}
			}
			store, _ := publishSearchTime(t, data)
			searcher, err := operations.NewSearcher(operations.SearcherOptions{Store: store})
			if err != nil {
				t.Fatal(err)
			}
			request := operations.BatchRequest{Version: 1, Requests: []operations.AccessRequest{{Src: "192.0.2.10", Dst: "198.51.100.10", Service: "443"}}}
			report, err := searcher.Query(t.Context(), request)
			if err != nil || len(report.Inputs) != 1 || len(report.Inputs[0].Outcomes) == 0 {
				t.Fatal("missing zone table concealed native declarations", report, err)
			}
			found := false
			for _, outcome := range report.Inputs[0].Outcomes {
				if !outcome.Conditional || outcome.Disposition == plan.BatchCovered || outcome.TrafficView != "policy" || outcome.Policy.Complete || !outcome.Policy.Allowed.Empty() || outcome.Policy.Unknown.Empty() {
					t.Fatal("unbound zones became established policy permission", outcome)
				}
				for _, match := range outcome.Matches {
					if match.Rule != "access" || len(match.Declared) == 0 {
						continue
					}
					found = true
					if match.EffectiveKnown || len(match.Effective) != 0 || match.DeclaredKnown == test.referenced {
						t.Fatal("unknown native context changed declaration or effective certainty", match)
					}
				}
			}
			if !found {
				t.Fatal("no conditional native rule evidence", report)
			}
			designer, err := operations.NewBatchDesigner(operations.BatchDesignerOptions{Store: store})
			if err != nil {
				t.Fatal(err)
			}
			if design, err := designer.Design(t.Context(), request); err != nil || len(design.Devices) != 0 {
				t.Fatal("unbound zones authorized a change", design, err)
			}
		})
	}
}

func TestSearcherValidatesExplicitNativeAddressView(t *testing.T) {
	for _, view := range []inventory.View{inventory.Real, inventory.Translated} {
		t.Run(string(view), func(t *testing.T) {
			for _, test := range []struct {
				name        string
				destination string
				port        uint16
				unknown     bool
				wantMatch   bool
			}{
				{"business coordinates", "10.0.0.10/32", 1443, false, true},
				{"wire coordinates are not this view", "203.0.113.10/32", 443, false, false},
				{"unknown mapping", "10.0.0.10/32", 1443, true, false},
			} {
				t.Run(test.name, func(t *testing.T) {
					data := searchNATData(t, "edge", "203.0.113.10/32", "10.0.0.10/32", flow.Interval{Low: 443, High: 443})
					if test.unknown {
						data.StaticNATs[0].Unsupported = []string{"synthetic unknown NAT condition"}
					}
					store, _ := publishSearchTime(t, data)
					searcher, err := operations.NewSearcher(operations.SearcherOptions{Store: store})
					if err != nil {
						t.Fatal(err)
					}
					traffic := searchNATTraffic(t, "192.0.2.20/32", test.destination, flow.Interval{Low: test.port, High: test.port})
					report, err := searcher.Query(t.Context(), operations.BatchRequest{Version: 1, Requests: []operations.AccessRequest{{Traffic: traffic, View: view}}})
					if err != nil || len(report.Inputs) != 1 {
						t.Fatal(report, err)
					}
					outcomes := report.Inputs[0].Outcomes
					if (len(outcomes) != 0) != test.wantMatch {
						t.Fatal("explicit view was treated as original wire traffic", report)
					}
					for _, outcome := range outcomes {
						if !outcome.Conditional || !publishedNAT(outcome) || !outcome.NAT.Exact {
							t.Fatal("alias lacked a conditional native proof", outcome)
						}
						actual := outcome.NAT.Translated
						if view == inventory.Real {
							actual = outcome.Real
						}
						assertSearchTraffic(t, actual, traffic)
					}
					if !test.wantMatch && !slices.ContainsFunc(report.Issues, func(issue operations.Issue) bool {
						return issue.TrafficView == string(view) && (issue.Code == "unknown_alias" || issue.Code == "unlocated_alias")
					}) {
						t.Fatal("unvalidated view lost its unresolved evidence", report)
					}
				})
			}
		})
	}
}
