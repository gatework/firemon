package operations_test

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"testing"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/inventory"
	"github.com/gatework/firemon/operations"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/policy"
	"github.com/gatework/firemon/snapshot"
)

func searchGraph(t *testing.T, device, left, right string, action fm.Action) *fm.Firewall {
	t.Helper()
	in, out := netip.MustParsePrefix(left), netip.MustParsePrefix(right)
	fw, err := fm.Seal(fm.Data{
		Metadata: fm.Metadata{Device: device, Vendor: "paloalto", Context: "policy"},
		Raw:      "synthetic search fixture " + device,
		Zones:    []fm.ZoneRecord{{Object: fm.Object{ID: "inside", Scope: "policy"}}, {Object: fm.Object{ID: "outside", Scope: "policy"}}},
		Interfaces: []fm.InterfaceRecord{
			{Object: fm.Object{ID: "in", Scope: "vr"}, Zone: "inside", Addresses: []netip.Prefix{in}},
			{Object: fm.Object{ID: "out", Scope: "vr"}, Zone: "outside", Addresses: []netip.Prefix{out}},
		},
		Routes: []fm.RouteRecord{
			{Object: fm.Object{ID: "left", Scope: "vr"}, Destination: in.Masked(), Interface: "in", Direct: true},
			{Object: fm.Object{ID: "right", Scope: "vr"}, Destination: out.Masked(), Interface: "out", Direct: true},
			{Object: fm.Object{ID: "default", Scope: "vr"}, Destination: netip.MustParsePrefix("0.0.0.0/0"), Interface: "out"},
		},
		Rules: []fm.RuleRecord{{
			Object: fm.Object{ID: "access", Name: "application access", Scope: "policy"}, RuleSet: "security", Action: action,
			Match: fm.Match{AnySource: true, AnyDestination: true, AnyService: true, AnyFromZone: true, AnyToZone: true},
		}},
	})
	if err != nil || !fw.Complete() {
		t.Fatal("invalid synthetic search graph", fw, err)
	}
	return fw
}

func publishSearch(t *testing.T, store *snapshot.Store, fw *fm.Firewall, expected, publication string) snapshot.PublishResult {
	t.Helper()
	result, err := store.Publish(t.Context(), fw, snapshot.PublishOptions{Expected: expected, PublicationID: publication})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestSearcherAssociatesBothEndpointsWithoutInventingIngress(t *testing.T) {
	for _, split := range []bool{false, true} {
		name := "same firewall"
		if split {
			name = "different firewalls"
		}
		t.Run(name, func(t *testing.T) {
			store, err := snapshot.Open(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			want := map[string][]string{"both": {"both:interface:in", "both:interface:out"}}
			if split {
				publishSearch(t, store, searchGraph(t, "source", "192.0.2.1/24", "203.0.113.1/24", fm.Permit), "", "source")
				publishSearch(t, store, searchGraph(t, "destination", "203.0.113.2/24", "198.51.100.1/24", fm.Permit), "", "destination")
				want = map[string][]string{"source": {"source:interface:in"}, "destination": {"destination:interface:out"}}
			} else {
				publishSearch(t, store, searchGraph(t, "both", "192.0.2.1/24", "198.51.100.1/24", fm.Permit), "", "both")
			}
			counted := &countedBatchStore{Store: store}
			at := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
			searcher, err := operations.NewSearcher(operations.SearcherOptions{Store: counted, Now: func() time.Time { return at }})
			if err != nil {
				t.Fatal(err)
			}
			request := operations.AccessRequest{Src: "\ufeff'１９２．０．２．１０'；192.0.2.10", Dst: "198.51.100.10", Service: "４４３, tcp / 443"}
			report, err := searcher.Query(t.Context(), operations.BatchRequest{Version: 1, Requests: []operations.AccessRequest{request}})
			if err != nil || len(report.Inputs) != 1 || len(report.Devices) != 0 {
				t.Fatal(report, err)
			}
			input := report.Inputs[0]
			if input.Error != nil || input.Normalized == nil || len(input.Normalized.Sources) != 1 || len(input.Normalized.Services) != 1 || input.Request.Src != request.Src {
				t.Fatal("simple input was not normalized while retaining its original evidence", input)
			}
			found := make(map[string]bool)
			for _, outcome := range input.Outcomes {
				found[outcome.Device] = true
				if !outcome.Conditional || outcome.Disposition == plan.BatchCovered || !outcome.At.Equal(at) {
					t.Fatal("configuration association became an established ingress", outcome)
				}
				if len(outcome.NativeRequests) != 1 || outcome.NativeRequests[0].Scope != "policy" {
					t.Fatal("policy scope was replaced by routing context", outcome.NativeRequests)
				}
				for _, source := range want[outcome.Device] {
					if !slices.Contains(outcome.Sources, source) {
						t.Fatal("source or destination candidate provenance was lost", source, outcome.Sources)
					}
				}
				for _, region := range outcome.Wire.Regions() {
					if region.Source.First.String() != "192.0.2.10" || region.Destination.First.String() != "198.51.100.10" || region.DestinationPort != (flow.Interval{Low: 443, High: 443}) {
						t.Fatal("association rewrote the source/destination pair", region)
					}
				}
				if len(outcome.Matches) == 0 || outcome.Matches[0].Rule != "access" || outcome.Policy.Allowed.Empty() {
					t.Fatal("conditional ingress concealed useful policy matches", outcome)
				}
			}
			if len(found) != len(want) || counted.loads != len(want) || counted.manifests != 1 {
				t.Fatal("endpoint discovery missed a device or loaded a revision repeatedly", found, counted.loads, counted.manifests)
			}
		})
	}
}

func TestSearcherUsesFreshManifestWithCachedImmutableGraphs(t *testing.T) {
	store, err := snapshot.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	fw := searchGraph(t, "fw", "192.0.2.1/24", "198.51.100.1/24", fm.Permit)
	first := publishSearch(t, store, fw, "", "before")
	counted := &countedBatchStore{Store: store}
	searcher, err := operations.NewSearcher(operations.SearcherOptions{Store: counted})
	if err != nil {
		t.Fatal(err)
	}
	query := operations.BatchRequest{Version: 1, Requests: []operations.AccessRequest{{Src: "192.0.2.10", Dst: "198.51.100.10", Service: "443"}}}
	before, err := searcher.Query(t.Context(), query)
	if err != nil || len(before.Inputs[0].Outcomes) == 0 || before.Inputs[0].Outcomes[0].Policy.Allowed.Empty() {
		t.Fatal(before, err)
	}
	if _, err := searcher.Query(t.Context(), query); err != nil || counted.loads != 1 || counted.manifests != 2 {
		t.Fatal("query did not reuse its immutable graph", err, counted.loads, counted.manifests)
	}
	changed := fw.Export()
	changed.Rules[0].Action = fm.Deny
	denied, err := fm.Seal(changed)
	if err != nil {
		t.Fatal(err)
	}
	second := publishSearch(t, store, denied, first.Revision, "after")
	after, err := searcher.Query(t.Context(), query)
	if err != nil || after.Generation <= before.Generation || counted.loads != 2 || counted.manifests != 3 || len(after.Inputs[0].Outcomes) == 0 {
		t.Fatal("new publication was concealed by cache", after, err, counted.loads, counted.manifests)
	}
	for _, outcome := range after.Inputs[0].Outcomes {
		if outcome.Revision != second.Revision || outcome.Policy.Denied.Empty() || !outcome.Policy.Allowed.Empty() {
			t.Fatal("policy decision was cached across revisions", outcome)
		}
	}
	if before.Inputs[0].Outcomes[0].Revision != first.Revision || before.Inputs[0].Outcomes[0].Policy.Allowed.Empty() {
		t.Fatal("new current graph mutated an earlier result")
	}
	if err := store.Reserve(t.Context(), "fw", second.Revision, "pending-operation"); err != nil {
		t.Fatal(err)
	}
	reserved, err := searcher.Query(t.Context(), query)
	if err != nil || len(reserved.Inputs[0].Outcomes) != 0 || counted.loads != 2 || counted.manifests != 4 || !slices.ContainsFunc(reserved.Issues, func(issue operations.Issue) bool { return issue.Code == "snapshot_reserved" }) {
		t.Fatal("warm cache bypassed a persisted reservation", reserved, err)
	}
}

func TestSearcherRequiresRevisionBoundIngressAndOwnership(t *testing.T) {
	store, err := snapshot.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	pub := publishSearch(t, store, searchGraph(t, "fw", "192.0.2.1/24", "198.51.100.1/24", fm.Permit), "", "current")
	src, _ := flow.PrefixRange(netip.MustParsePrefix("192.0.2.0/24"))
	base := inventory.Topology{Version: 1, Bindings: []inventory.Binding{
		{Device: "fw", Revision: pub.Revision, Scope: "policy", VRF: "vr", Zone: "inside", Role: inventory.Ingress, View: inventory.Original, Networks: []flow.AddressRange{src}},
		{Device: "fw", Revision: pub.Revision, Scope: "policy", VRF: "vr", Zone: "inside", Role: inventory.Protection, View: inventory.Original, Networks: []flow.AddressRange{src}},
	}}
	for _, mode := range []string{"complete", "stale", "ingress only", "ownership only", "ambiguous ingress"} {
		t.Run(mode, func(t *testing.T) {
			topology := base
			topology.Bindings = slices.Clone(base.Bindings)
			switch mode {
			case "stale":
				topology.Bindings[0].Revision = "old-revision"
			case "ingress only":
				topology.Bindings = topology.Bindings[:1]
			case "ownership only":
				topology.Bindings = topology.Bindings[1:]
			case "ambiguous ingress":
				other := topology.Bindings[0]
				other.Zone = "outside"
				topology.Bindings = append(topology.Bindings, other)
			}
			searcher, err := operations.NewSearcher(operations.SearcherOptions{Store: store, Topology: &topology})
			if err != nil {
				t.Fatal(err)
			}
			report, err := searcher.Query(t.Context(), operations.BatchRequest{Version: 1, Requests: []operations.AccessRequest{{Src: "192.0.2.10", Dst: "198.51.100.10", Service: "443"}}})
			if err != nil || len(report.Inputs[0].Outcomes) == 0 {
				t.Fatal(report, err)
			}
			established := 0
			for _, outcome := range report.Inputs[0].Outcomes {
				if !outcome.Conditional {
					established++
					if outcome.NativeRequests[0].FromZone != "inside" || outcome.Disposition != plan.BatchCovered {
						t.Fatal("topology proved the wrong ingress", outcome)
					}
				}
			}
			if (established > 0) != (mode == "complete") {
				t.Fatal("association bypassed independent current topology evidence", mode, established)
			}
		})
	}
}

func searchSourceTraffic(t *testing.T, source string) flow.Traffic {
	t.Helper()
	var regions []flow.TrafficRegion
	for _, destination := range []string{"198.51.100.10/32", "198.51.100.12/32"} {
		region := requestTraffic(t, source, destination, 0).Regions()[0]
		region.SourcePort = flow.Interval{High: 65535}
		regions = append(regions, region)
	}
	traffic, err := flow.NewTraffic(16, regions...)
	if err != nil {
		t.Fatal(err)
	}
	return traffic
}

func TestSearcherPartitionsTopologyEvidencePerSourceAndNativeContext(t *testing.T) {
	for _, complete := range []bool{false, true} {
		name := "one known ingress"
		if complete {
			name = "different ingress zones"
		}
		t.Run(name, func(t *testing.T) {
			store := emptySearchStore(t)
			fw := searchGraph(t, "fw", "192.0.2.1/24", "198.51.100.1/24", fm.Permit)
			pub := publishSearch(t, store.Store, fw, "", "partition")
			topology := inventory.Topology{Version: 1}
			for _, endpoint := range []struct{ ip, zone string }{{"192.0.2.10", "inside"}, {"198.51.100.20", "outside"}} {
				addr := netip.MustParseAddr(endpoint.ip)
				binding := inventory.Binding{
					Device: "fw", Revision: pub.Revision, Scope: "policy", VRF: "vr", Zone: fm.ID(endpoint.zone),
					View: inventory.Original, Networks: []flow.AddressRange{{First: addr, Last: addr}}, Role: inventory.Protection,
				}
				topology.Bindings = append(topology.Bindings, binding)
				if complete || endpoint.zone == "inside" {
					binding.Role = inventory.Ingress
					topology.Bindings = append(topology.Bindings, binding)
				}
			}
			request := operations.BatchRequest{Topology: &topology, Requests: []operations.AccessRequest{{
				Src: "192.0.2.10,198.51.100.20", Dst: "198.51.100.10,198.51.100.12", Service: "443",
			}}}
			searcher, err := operations.NewSearcher(operations.SearcherOptions{Store: store})
			if err != nil {
				t.Fatal(err)
			}
			report, err := searcher.Query(t.Context(), request)
			if err != nil || len(report.Inputs) != 1 || len(report.Inputs[0].Outcomes) == 0 {
				t.Fatal(report, err)
			}
			want := map[fm.ID]flow.Traffic{"inside": searchSourceTraffic(t, "192.0.2.10/32")}
			outside := searchSourceTraffic(t, "198.51.100.20/32")
			if complete {
				want["outside"] = outside
			}
			known := make(map[fm.ID]flow.Traffic)
			var conditional flow.Traffic
			for _, outcome := range report.Inputs[0].Outcomes {
				if len(outcome.NativeRequests) != 1 {
					t.Fatal(outcome)
				}
				if outcome.Conditional {
					if outcome.Disposition == plan.BatchCovered {
						t.Fatal("conditional ingress was marked covered", outcome)
					}
					conditional, err = conditional.Union(outcome.Wire, 32)
				} else {
					zone := outcome.NativeRequests[0].FromZone
					known[zone], err = known[zone].Union(outcome.Wire, 32)
					if outcome.Disposition != plan.BatchCovered {
						t.Fatal("a proved allowed fraction was withheld", outcome)
					}
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			for _, zone := range []fm.ID{"inside", "outside"} {
				if same, err := known[zone].Equal(want[zone], 32); err != nil || !same {
					t.Fatal("proof was applied to a whole row instead of its exact source fraction", zone, known[zone], want[zone], err)
				}
			}
			if !complete {
				if retained, err := conditional.Contains(outside, 32); err != nil || !retained {
					t.Fatal("unknown ingress fraction disappeared", conditional, err)
				}
			}

			// Remove the permit so planning must add exactly the proved fractions.
			data := fw.Export()
			data.Rules = nil
			data.Metadata.Context = ""
			for at := range data.Zones {
				data.Zones[at].Scope = ""
				data.Zones[at].Name = string(data.Zones[at].ID)
			}
			before, err := fm.Seal(data)
			if err != nil {
				t.Fatal(err)
			}
			current := publishSearch(t, store.Store, before, pub.Revision, "plan-partition")
			for at := range topology.Bindings {
				topology.Bindings[at].Revision = current.Revision
				topology.Bindings[at].Scope = ""
			}
			designer, err := operations.NewBatchDesigner(operations.BatchDesignerOptions{Store: store})
			if err != nil {
				t.Fatal(err)
			}
			design, err := designer.Design(t.Context(), request)
			if err != nil || len(design.Devices) != 1 || design.Devices[0].Batch.Plan == nil {
				t.Fatal("known topology fractions did not reach planning", design, err)
			}
			after := design.Devices[0].Batch.Plan.After()
			whole, err := want["inside"].Union(outside, 32)
			if err != nil {
				t.Fatal(err)
			}
			for _, zone := range []fm.ID{"inside", "outside"} {
				actual, err := (policy.Engine{}).Query(t.Context(), after, policy.Request{Traffic: whole, RuleSet: "security", FromZone: zone, ToZone: "outside"})
				if err != nil {
					t.Fatal(err)
				}
				if same, err := actual.Allowed.Equal(want[zone], 32); err != nil || !same {
					t.Fatal("planning widened permission across ingress contexts or unproven sources", zone, actual.Allowed, want[zone], err)
				}
			}
		})
	}
}

func TestSearcherMissingRouteStillFindsNamedACLDeclarations(t *testing.T) {
	const raw = "interface i\n nameif inside\n security-level 100\n ip address 192.0.2.1 255.255.255.0\n!\ninterface o\n nameif outside\n security-level 0\n ip address 203.0.113.1 255.255.255.0\n!\naccess-list IN extended permit tcp 192.0.2.0 255.255.255.0 host 198.51.100.10 eq 443\naccess-group IN in interface inside\n"
	fw := parseNative(t, raw, fm.Metadata{Device: "asa", Vendor: "asa", Software: "9.12"})
	store := emptySearchStore(t)
	publishSearch(t, store.Store, fw, "", "acl")
	searcher, err := operations.NewSearcher(operations.SearcherOptions{Store: store})
	if err != nil {
		t.Fatal(err)
	}
	request := operations.BatchRequest{Requests: []operations.AccessRequest{{Src: "192.0.2.10", Dst: "198.51.100.10", Service: "443"}}}
	report, err := searcher.Query(t.Context(), request)
	if err != nil || len(report.Inputs) != 1 {
		t.Fatal(report, err)
	}
	found := false
	for _, outcome := range report.Inputs[0].Outcomes {
		if !outcome.Conditional || outcome.Disposition == plan.BatchCovered {
			t.Fatal("declaration fallback asserted a packet path", outcome)
		}
		for _, native := range outcome.NativeRequests {
			for _, match := range outcome.Matches {
				found = found || native.RuleSet == "IN" && len(match.Declared) != 0
			}
		}
	}
	if !found {
		t.Fatal("missing route hid an existing named native ACL", report)
	}
	designer, err := operations.NewBatchDesigner(operations.BatchDesignerOptions{Store: store})
	if err != nil {
		t.Fatal(err)
	}
	design, err := designer.Design(t.Context(), request)
	if err != nil || len(design.Devices) != 0 {
		t.Fatal("conditional ACL fallback became a change plan", design, err)
	}
}

func TestSearcherBoundsWorkAndRejectsCancellation(t *testing.T) {
	store, err := snapshot.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	pub := publishSearch(t, store, searchGraph(t, "fw", "192.0.2.1/24", "198.51.100.1/24", fm.Permit), "", "current")
	query := operations.BatchRequest{Version: 1, Requests: []operations.AccessRequest{{Src: "192.0.2.10", Dst: "198.51.100.10", Service: "443"}}}
	searcher, err := operations.NewSearcher(operations.SearcherOptions{Store: store, Engine: policy.Engine{Limits: policy.Limits{MaxVisits: 1}}})
	if err != nil {
		t.Fatal(err)
	}
	report, err := searcher.Query(t.Context(), query)
	if !errors.Is(err, policy.ErrBudget) || len(report.Devices) != 0 {
		t.Fatal("search exceeded its visit budget", report, err)
	}
	for _, input := range report.Inputs {
		if len(input.Outcomes) != 0 {
			t.Fatal("budget failure yielded a proved outcome", input)
		}
	}
	counted := &countedBatchStore{Store: store}
	searcher, err = operations.NewSearcher(operations.SearcherOptions{Store: counted})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if report, err := searcher.Query(ctx, query); !errors.Is(err, context.Canceled) || len(report.Inputs) != 0 || counted.manifests != 0 || counted.loads != 0 {
		t.Fatal("canceled search reached persistence", report, err)
	}
	current, _, err := store.Current(t.Context(), "fw")
	if err != nil || current == nil || pub.Revision == "" {
		t.Fatal("search changed persisted state", err)
	}
}
