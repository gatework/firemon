package operations_test

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/operations"
	"github.com/gatework/firemon/snapshot"
)

func searchNATData(t *testing.T, device, public, private string, ports flow.Interval) fm.Data {
	t.Helper()
	original, translated := searchTimeRange(t, public), searchTimeRange(t, private)
	outside := netip.PrefixFrom(original.First, 24)
	inside := netip.PrefixFrom(translated.First, 24)
	match := searchTimeMatch("")
	match.AnyFromZone, match.AnyDestination, match.AnyService = false, false, false
	match.FromZones = []fm.ID{"outside"}
	match.Destinations = []fm.AddressRef{{Kind: fm.AddressObject, ID: "public"}}
	match.Services = []fm.ServiceRef{{Kind: fm.ServiceObject, ID: "published-service"}}
	return fm.Data{
		Metadata: fm.Metadata{Device: device, Vendor: "srx"},
		Zones:    []fm.ZoneRecord{{Object: fm.Object{ID: "inside"}}, {Object: fm.Object{ID: "outside"}}},
		Interfaces: []fm.InterfaceRecord{
			{Object: fm.Object{ID: "outside-if"}, Zone: "outside", Addresses: []netip.Prefix{outside}},
			{Object: fm.Object{ID: "inside-if"}, Zone: "inside", Addresses: []netip.Prefix{inside}},
		},
		Routes: []fm.RouteRecord{
			{Object: fm.Object{ID: "internal"}, Destination: inside.Masked(), Interface: "inside-if"},
			{Object: fm.Object{ID: "default"}, Destination: netip.MustParsePrefix("0.0.0.0/0"), Interface: "outside-if"},
		},
		Addresses: []fm.AddressRecord{{Object: fm.Object{ID: "public"}, Ranges: []flow.AddressRange{original}}},
		Services: []fm.ServiceRecord{{Object: fm.Object{ID: "published-service"}, Terms: []fm.ServiceTerm{{
			Protocol: flow.Interval{Low: 6, High: 6}, SourcePort: flow.Interval{High: 65535}, DestinationPort: ports,
			ICMPType: flow.Interval{High: 255}, ICMPCode: flow.Interval{High: 255},
		}}}},
		Rules: []fm.RuleRecord{{Object: fm.Object{ID: "permit"}, RuleSet: "security", Action: fm.Permit, Match: searchTimeMatch("")}},
		StaticNATs: []fm.StaticNATRecord{{Object: fm.Object{ID: "publish"}, Match: match,
			Order: fm.NATOrder{Section: "static:published"}, Bidirectional: true,
			Destination: []fm.Mapping{{Original: original, Translated: translated, Mode: fm.Offset}},
			DestinationPorts: []fm.PortMapping{{Original: ports,
				Translated: flow.Interval{Low: ports.Low + 1000, High: ports.High + 1000}, Mode: fm.Offset}},
		}},
	}
}

func publishSearchNAT(t *testing.T, store *snapshot.Store, data fm.Data) {
	t.Helper()
	fw, err := fm.Seal(data)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Publish(t.Context(), fw, snapshot.PublishOptions{PublicationID: data.Metadata.Device, Live: true}); err != nil {
		t.Fatal(err)
	}
}

func searchNATTraffic(t *testing.T, source, destination string, ports flow.Interval) flow.Traffic {
	t.Helper()
	traffic, err := flow.NewTraffic(16, flow.TrafficRegion{
		Source: searchTimeRange(t, source), Destination: searchTimeRange(t, destination),
		Protocol: flow.Interval{Low: 6, High: 6}, SourcePort: flow.Interval{High: 65535}, DestinationPort: ports,
		ICMPType: flow.Interval{High: 255}, ICMPCode: flow.Interval{High: 255},
	})
	if err != nil {
		t.Fatal(err)
	}
	return traffic
}

func assertSearchTraffic(t *testing.T, got, want flow.Traffic) {
	t.Helper()
	if same, err := got.Equal(want, 4096); err != nil || !same {
		t.Fatalf("traffic differs: got=%v want=%v err=%v", got.Regions(), want.Regions(), err)
	}
}

func publishedNAT(outcome operations.TargetOutcome) bool {
	for _, step := range outcome.NAT.Steps {
		if step.ID == "publish" && !step.Reverse {
			return true
		}
	}
	return false
}

func TestSearcherDiscoversPortAliasAndOriginalRuleTraffic(t *testing.T) {
	store, err := snapshot.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	data := searchNATData(t, "edge", "203.0.113.10/31", "10.0.0.10/31", flow.Interval{Low: 443, High: 444})
	data.Addresses = append(data.Addresses, fm.AddressRecord{Object: fm.Object{ID: "allowed-host"}, Ranges: []flow.AddressRange{searchTimeRange(t, "10.0.0.10/32")}})
	permit := data.Rules[0]
	permit.Match.AnyDestination = false
	permit.Match.Destinations = []fm.AddressRef{{Kind: fm.AddressObject, ID: "allowed-host"}}
	data.Rules = []fm.RuleRecord{permit, {Object: fm.Object{ID: "deny"}, RuleSet: "security", Position: 1, Action: fm.Deny, Match: searchTimeMatch("")}}
	publishSearchNAT(t, store, data)
	searcher, err := operations.NewSearcher(operations.SearcherOptions{Store: store})
	if err != nil {
		t.Fatal(err)
	}
	report, err := searcher.Query(t.Context(), operations.BatchRequest{Version: 1, Requests: []operations.AccessRequest{{
		Src: "192.0.2.20", Dst: "10.0.0.10/31", Service: "1443-1444",
	}}})
	if err != nil || len(report.Inputs) != 1 {
		t.Fatal(report, err)
	}
	found := map[fm.ID]bool{}
	for _, outcome := range report.Inputs[0].Outcomes {
		if !publishedNAT(outcome) {
			continue
		}
		if !outcome.Conditional || !outcome.NAT.Exact || outcome.NAT.PossibleAllocation {
			t.Fatal("inferred alias was treated as established ingress", outcome)
		}
		for _, m := range outcome.Matches {
			if len(m.Effective) == 0 {
				continue
			}
			public, private := "203.0.113.10/32", "10.0.0.10/32"
			if m.Rule == "deny" {
				public, private = "203.0.113.11/32", "10.0.0.11/32"
			}
			effective, err := flow.NewTraffic(16, m.Effective...)
			if err != nil {
				t.Fatal(err)
			}
			original, err := flow.NewTraffic(16, m.Original...)
			if err != nil {
				t.Fatal(err)
			}
			assertSearchTraffic(t, effective, searchNATTraffic(t, "192.0.2.20/32", private, flow.Interval{Low: 1443, High: 1444}))
			assertSearchTraffic(t, original, searchNATTraffic(t, "192.0.2.20/32", public, flow.Interval{Low: 443, High: 444}))
			if !m.EffectiveKnown {
				t.Fatal("exact policy pullback lost its proof", m)
			}
			found[m.Rule] = true
		}
	}
	if !found["permit"] || !found["deny"] {
		t.Fatal("automatic business input did not reveal both public policy owners", found, report)
	}
}

func TestSearcherPropagatesStaticAssociationsOnlyWithinNATLifetime(t *testing.T) {
	start := time.Date(2026, 11, 9, 0, 0, 0, 0, time.UTC)
	active := fm.TimeWindow{Start: start.Add(time.Hour), End: start.Add(2 * time.Hour)}
	for _, unknown := range []bool{false, true} {
		name := "bounded translation"
		if unknown {
			name = "unknown calendar"
		}
		t.Run(name, func(t *testing.T) {
			store, err := snapshot.Open(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			edge := searchNATData(t, "edge", "203.0.113.10/32", "10.0.0.10/32", flow.Interval{Low: 443, High: 443})
			edge.Schedules = []fm.ScheduleRecord{{Object: fm.Object{ID: "publish-time"}, Windows: []fm.TimeWindow{active}}}
			if unknown {
				edge.Schedules[0].Windows = nil
				edge.Schedules[0].Weekly = []fm.WeeklyPeriod{{Windows: []fm.WeeklyWindow{{Day: time.Monday, Start: time.Hour, End: 2 * time.Hour}}}}
			}
			edge.StaticNATs[0].Match.Schedule = "publish-time"
			core := searchNATData(t, "core", "10.0.0.10/32", "172.16.0.10/32", flow.Interval{Low: 1443, High: 1443})
			publishSearchNAT(t, store, edge)
			publishSearchNAT(t, store, core)
			searcher, err := operations.NewSearcher(operations.SearcherOptions{Store: store})
			if err != nil {
				t.Fatal(err)
			}
			report, err := searcher.Query(t.Context(), operations.BatchRequest{Version: 1, Requests: []operations.AccessRequest{{
				Src: "192.0.2.20", Dst: "203.0.113.10", Service: "443",
				Window: &fm.TimeWindow{Start: start, End: start.Add(3 * time.Hour)},
			}}})
			if err != nil || len(report.Inputs) != 1 {
				t.Fatal(report, err)
			}
			foundEdge, foundCore := false, false
			for _, outcome := range report.Inputs[0].Outcomes {
				if !outcome.Conditional {
					t.Fatal("configuration association asserted a physical path", outcome)
				}
				if outcome.Device == "edge" && publishedNAT(outcome) {
					foundEdge = true
				}
				if outcome.Device != "core" {
					continue
				}
				if unknown {
					t.Fatal("unknown translation was propagated as an exact peer binding", outcome)
				}
				if outcome.Window == nil || *outcome.Window != active {
					t.Fatal("derived association escaped its causal time interval", outcome)
				}
				if !publishedNAT(outcome) {
					continue
				}
				assertSearchTraffic(t, outcome.Wire, searchNATTraffic(t, "192.0.2.20/32", "10.0.0.10/32", flow.Interval{Low: 1443, High: 1443}))
				assertSearchTraffic(t, outcome.NAT.Translated, searchNATTraffic(t, "192.0.2.20/32", "172.16.0.10/32", flow.Interval{Low: 2443, High: 2443}))
				if !outcome.NAT.Exact || outcome.NAT.PossibleAllocation {
					t.Fatal("static association lost exact port and address mapping", outcome)
				}
				fromEdge := false
				for _, source := range outcome.Sources {
					fromEdge = fromEdge || strings.HasPrefix(source, "edge:")
				}
				if !fromEdge {
					t.Fatal("derived endpoint lost the upstream configuration evidence", outcome.Sources)
				}
				foundCore = true
			}
			if !unknown && (!foundEdge || !foundCore) {
				t.Fatal("chained static translation did not reveal both firewall endpoints", foundEdge, foundCore, report)
			}
			if unknown {
				uncertain := false
				for _, issue := range report.Issues {
					uncertain = uncertain || issue.Code == "unknown_path" || issue.Code == "unknown_alias"
				}
				if !uncertain || foundEdge {
					t.Fatal("unknown calendar evidence disappeared or became exact", report)
				}
			}
		})
	}
}

func TestSearcherDoesNotPropagateDynamicPoolAsSessionBinding(t *testing.T) {
	store, err := snapshot.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	edge := searchNATData(t, "edge", "203.0.113.10/32", "10.0.1.10/32", flow.Interval{Low: 443, High: 443})
	edge.StaticNATs, edge.Addresses, edge.Services = nil, nil, nil
	match := searchTimeMatch("")
	match.AnyFromZone, match.AnyToZone = false, false
	match.FromZones, match.ToZones = []fm.ID{"inside"}, []fm.ID{"outside"}
	edge.NATPools = []fm.NATPoolRecord{{Object: fm.Object{ID: "pool"}, Ranges: []flow.AddressRange{searchTimeRange(t, "172.16.1.10/31")}, Ports: flow.Interval{High: 65535}}}
	edge.DynamicNATs = []fm.DynamicNATRecord{{Object: fm.Object{ID: "hide"}, Match: match,
		Order: fm.NATOrder{Stage: 2, Section: "source:hide"}, SourceMode: fm.DynamicIP, DestinationMode: fm.NoTranslation, SourcePool: "pool"}}
	peer := searchNATData(t, "pool-peer", "172.16.1.10/32", "192.168.0.10/32", flow.Interval{Low: 443, High: 443})
	peer.StaticNATs, peer.Addresses, peer.Services = nil, nil, nil
	publishSearchNAT(t, store, edge)
	publishSearchNAT(t, store, peer)
	searcher, err := operations.NewSearcher(operations.SearcherOptions{Store: store})
	if err != nil {
		t.Fatal(err)
	}
	report, err := searcher.Query(t.Context(), operations.BatchRequest{Version: 1, Requests: []operations.AccessRequest{{
		Src: "10.0.1.10", Dst: "203.0.113.10", Service: "443",
	}}})
	if err != nil || len(report.Inputs) != 1 {
		t.Fatal(report, err)
	}
	possible := false
	for _, outcome := range report.Inputs[0].Outcomes {
		if outcome.Device == "pool-peer" {
			t.Fatal("a possible pool allocation was propagated as a selected session binding", outcome)
		}
		if outcome.NAT.PossibleAllocation {
			possible = true
			if outcome.NAT.Exact || !outcome.Conditional {
				t.Fatal("dynamic allocation was reported as exact", outcome)
			}
		}
	}
	if !possible {
		t.Fatal("query hid dynamic allocation evidence", report)
	}
}
