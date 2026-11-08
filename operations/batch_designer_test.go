package operations_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/inventory"
	"github.com/gatework/firemon/operations"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/policy"
	"github.com/gatework/firemon/snapshot"
	"github.com/gatework/firemon/vendors"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"
)

type countedBatchStore struct {
	*snapshot.Store
	manifests, loads int
}

func (s *countedBatchStore) Manifest(ctx context.Context) (snapshot.Manifest, error) {
	s.manifests++
	return s.Store.Manifest(ctx)
}
func (s *countedBatchStore) Load(ctx context.Context, r string) (*fm.Firewall, error) {
	s.loads++
	return s.Store.Load(ctx, r)
}
func TestBatchDesignerFrozenManifestJointPlanAndSiblingIssues(t *testing.T) {
	_, store, _, req := collectionFixture(t)
	counted := &countedBatchStore{Store: store}
	designer, err := operations.NewBatchDesigner(operations.BatchDesignerOptions{Store: counted})
	if err != nil {
		t.Fatal(err)
	}
	traffic := requestTraffic(t, "192.0.2.10/32", "198.51.100.10/32", 1024)
	batch := operations.BatchRequest{Version: 1, Requests: []operations.AccessRequest{
		{ID: "first", Traffic: traffic, Targets: []operations.AccessTarget{{Device: req.Device, Request: policy.Request{FromZone: "inside", ToZone: "outside"}}}},
		{ID: "second", Traffic: requestTraffic(t, "192.0.2.11/32", "198.51.100.11/32", 1024), Targets: []operations.AccessTarget{{Device: req.Device, Request: policy.Request{FromZone: "inside", ToZone: "outside"}}}},
		{ID: "missing", Traffic: traffic, Targets: []operations.AccessTarget{{Device: "absent", Request: policy.Request{FromZone: "inside", ToZone: "outside"}}}},
	}}
	result, err := designer.Design(context.Background(), batch)
	if err != nil || len(result.Devices) != 1 || result.Devices[0].Batch.Plan == nil || len(result.Issues) != 1 || result.Issues[0].Code != "snapshot_missing" {
		t.Fatal(result, err)
	}
	if counted.manifests != 1 || counted.loads != 1 || len(result.Inputs) != 3 {
		t.Fatal(counted, result)
	}
	p := result.Devices[0].Batch.Plan
	if len(p.InputRequests()) != 2 || len(result.Devices[0].Batch.Inputs) != 2 || result.Devices[0].Batch.Inputs[0].Disposition != plan.BatchAccepted {
		t.Fatal(result.Devices)
	}
	cross := policy.Request{Traffic: requestTraffic(t, "192.0.2.10/32", "198.51.100.11/32", 1024), FromZone: "inside", ToZone: "outside"}
	coverage, err := (policy.Engine{}).Query(context.Background(), p.After(), cross)
	if err != nil || !coverage.Allowed.Empty() {
		t.Fatal("cross pair widened", coverage, err)
	}
}
func TestBatchDesignerAutoUsesIngressNotReverseRouteAndReportsFractions(t *testing.T) {
	_, store, _, req := collectionFixture(t)
	r := func(s string) flow.AddressRange { v, _ := flow.PrefixRange(netip.MustParsePrefix(s)); return v }
	topology := inventory.Topology{Version: 1, Bindings: []inventory.Binding{
		{Device: req.Device, Revision: req.Expected, Zone: "outside", Role: inventory.Protection, View: inventory.Original, Networks: []flow.AddressRange{r("198.51.100.0/25")}},
		{Device: req.Device, Revision: req.Expected, Zone: "inside", Role: inventory.Ingress, View: inventory.Original, Networks: []flow.AddressRange{r("192.0.2.0/24")}},
	}}
	d, _ := operations.NewBatchDesigner(operations.BatchDesignerOptions{Store: store})
	batch := operations.BatchRequest{Version: 1, Topology: &topology, Requests: []operations.AccessRequest{{Traffic: requestTraffic(t, "192.0.2.10/32", "198.51.100.0/24", 1024)}}}
	result, err := d.Design(context.Background(), batch)
	if err != nil || len(result.Devices) != 1 || result.Devices[0].Batch.Plan == nil {
		t.Fatal(result, err)
	}
	targets := result.Devices[0].Batch.Plan.Targets()
	if len(targets) != 1 || targets[0].FromZone != "inside" || targets[0].Traffic.Regions()[0].Destination != r("198.51.100.0/25") {
		t.Fatal(targets)
	}
	found := false
	for _, issue := range result.Issues {
		if issue.Code == "unlocated_destination" && issue.Traffic.Regions()[0].Destination == r("198.51.100.128/25") {
			found = true
		}
	}
	if !found {
		t.Fatal("missing exact unlocated remainder", result.Issues)
	}
	topology.Bindings = topology.Bindings[:1]
	result, err = d.Design(context.Background(), batch)
	if err != nil || len(result.Devices) != 0 {
		t.Fatal("reverse route invented ingress", result, err)
	}
}
func TestBatchDesignerLocalizesUnavailableSnapshots(t *testing.T) {
	for _, state := range []string{"reserved", "stale", "incomplete"} {
		t.Run(state, func(t *testing.T) {
			_, store, _, req := collectionFixture(t)
			target := operations.AccessTarget{Device: req.Device, Request: policy.Request{FromZone: "inside", ToZone: "outside"}}
			want := "snapshot_reserved"
			switch state {
			case "reserved":
				if err := store.Reserve(context.Background(), req.Device, req.Expected, "pending"); err != nil {
					t.Fatal(err)
				}
			case "stale":
				target.Revision = "old"
				want = "stale_topology"
			case "incomplete":
				fw := parseNative(t, panBase+"unrecognized syntax\n", fm.Metadata{Device: req.Device, Vendor: "paloalto"})
				_, err := store.Publish(context.Background(), fw, snapshot.PublishOptions{Expected: req.Expected, PublicationID: "bad", Live: true})
				if err != nil {
					t.Fatal(err)
				}
				want = "snapshot_incomplete"
			}
			d, _ := operations.NewBatchDesigner(operations.BatchDesignerOptions{Store: store})
			result, err := d.Design(context.Background(), operations.BatchRequest{Version: 1, Requests: []operations.AccessRequest{{Traffic: requestTraffic(t, "192.0.2.10/32", "198.51.100.10/32", 1024), Targets: []operations.AccessTarget{target}}}})
			if err != nil || len(result.Devices) != 0 || len(result.Issues) != 1 || result.Issues[0].Code != want {
				t.Fatal(result, err)
			}
		})
	}
}

func TestBatchDesignerForwardValidatesTranslatedCandidate(t *testing.T) {
	ctx := context.Background()
	store, _ := snapshot.Open(t.TempDir())
	r := func(s string) flow.AddressRange { v, _ := flow.PrefixRange(netip.MustParsePrefix(s)); return v }
	match := fm.Match{AnySource: true, AnyDestination: true, AnyService: true, AnyFromZone: true, AnyToZone: true}
	natMatch := match
	natMatch.AnyDestination = false
	natMatch.Destinations = []fm.AddressRef{{Kind: fm.AddressObject, ID: "public"}}
	data := fm.Data{Metadata: fm.Metadata{Device: "pan", Vendor: "paloalto"}, Zones: []fm.ZoneRecord{{Object: fm.Object{ID: "outside"}}, {Object: fm.Object{ID: "inside"}}}, Interfaces: []fm.InterfaceRecord{{Object: fm.Object{ID: "out", Scope: "vr"}, Zone: "outside"}, {Object: fm.Object{ID: "in", Scope: "vr"}, Zone: "inside"}}, Routes: []fm.RouteRecord{{Object: fm.Object{ID: "default", Scope: "vr"}, Destination: netip.MustParsePrefix("0.0.0.0/0"), Interface: "out"}, {Object: fm.Object{ID: "internal", Scope: "vr"}, Destination: netip.MustParsePrefix("10.0.0.0/24"), Interface: "in"}}, Addresses: []fm.AddressRecord{{Object: fm.Object{ID: "public"}, Ranges: []flow.AddressRange{r("203.0.113.10/32")}}}, DynamicNATs: []fm.DynamicNATRecord{{Object: fm.Object{ID: "publish"}, Match: natMatch, SourceMode: fm.NoTranslation, DestinationMode: fm.StaticIP, Destination: []fm.Mapping{{Original: r("203.0.113.10/32"), Translated: r("10.0.0.10/32"), Mode: fm.Constant}}}}, Rules: []fm.RuleRecord{{Object: fm.Object{ID: "permit"}, RuleSet: "security", Action: fm.Permit, Match: match}}}
	fw, err := fm.Seal(data)
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.Publish(ctx, fw, snapshot.PublishOptions{PublicationID: "p"})
	if err != nil {
		t.Fatal(err)
	}
	d, _ := operations.NewBatchDesigner(operations.BatchDesignerOptions{Store: store})
	request := operations.AccessRequest{Traffic: requestTraffic(t, "198.51.100.1/32", "10.0.0.10/32", 1024), View: inventory.Translated, WireCandidates: []operations.WireCandidate{{Traffic: requestTraffic(t, "198.51.100.1/32", "203.0.113.10/32", 1024), Target: operations.AccessTarget{Device: "pan", VRF: "vr", Request: policy.Request{FromZone: "outside"}}}}}
	result, err := d.Query(ctx, operations.BatchRequest{Version: 1, Requests: []operations.AccessRequest{request}})
	if err != nil || len(result.Issues) != 0 || len(result.Inputs[0].Outcomes) != 1 || result.Inputs[0].Outcomes[0].NativeRequests[0].Traffic.Regions()[0].Destination != r("203.0.113.10/32") {
		t.Fatal(result, err)
	}
	request.WireCandidates[0].Traffic = requestTraffic(t, "198.51.100.1/32", "203.0.113.11/32", 1024)
	result, err = d.Design(ctx, operations.BatchRequest{Version: 1, Requests: []operations.AccessRequest{request}})
	if err != nil || len(result.Devices) != 0 || len(result.Issues) == 0 {
		t.Fatal("unproven reverse alias accepted", result, err)
	}
}

func TestBatchDesignerSourceDestinationAndSameDevicePaths(t *testing.T) {
	for _, same := range []bool{false, true} {
		t.Run(map[bool]string{false: "different", true: "same"}[same], func(t *testing.T) {
			ctx := context.Background()
			store, _ := snapshot.Open(t.TempDir())
			revisions := map[string]string{}
			for _, device := range []string{"source-fw", "destination-fw"} {
				fw := parseNative(t, panBase, fm.Metadata{Device: device, Vendor: "paloalto"})
				pub, err := store.Publish(ctx, fw, snapshot.PublishOptions{PublicationID: device})
				if err != nil {
					t.Fatal(err)
				}
				revisions[device] = pub.Revision
			}
			r := func(s string) flow.AddressRange { v, _ := flow.PrefixRange(netip.MustParsePrefix(s)); return v }
			destination := "destination-fw"
			if same {
				destination = "source-fw"
			}
			top := inventory.Topology{Version: 1, Bindings: []inventory.Binding{
				{Device: "source-fw", Revision: revisions["source-fw"], Zone: "inside", Role: inventory.Protection, View: inventory.Original, Networks: []flow.AddressRange{r("192.0.2.0/24")}},
				{Device: destination, Revision: revisions[destination], Zone: "outside", Role: inventory.Protection, View: inventory.Original, Networks: []flow.AddressRange{r("198.51.100.0/24")}},
				{Device: "source-fw", Revision: revisions["source-fw"], Zone: "inside", Role: inventory.Ingress, View: inventory.Original, Networks: []flow.AddressRange{r("192.0.2.0/24")}},
			}}
			if !same {
				top.Bindings = append(top.Bindings, inventory.Binding{Device: destination, Revision: revisions[destination], Zone: "inside", Role: inventory.Ingress, View: inventory.Original, Networks: []flow.AddressRange{r("192.0.2.0/24")}})
			}
			counted := &countedBatchStore{Store: store}
			d, _ := operations.NewBatchDesigner(operations.BatchDesignerOptions{Store: counted})
			result, err := d.Design(ctx, operations.BatchRequest{Version: 1, Topology: &top, Requests: []operations.AccessRequest{{Traffic: requestTraffic(t, "192.0.2.10/32", "198.51.100.10/32", 1024)}}})
			want := 2
			if same {
				want = 1
			}
			if err != nil || len(result.Devices) != want || len(result.Inputs[0].Outcomes) != want || len(result.Issues) != 0 || counted.loads != want || counted.manifests != 1 {
				t.Fatal(result, err, counted)
			}
			for _, device := range result.Devices {
				if device.Batch.Plan == nil {
					t.Fatal(device)
				}
			}
		})
	}
}
func TestBatchDesignerDefaultRouteDoesNotOwnTrafficAndAmbiguitySurvives(t *testing.T) {
	ctx := context.Background()
	store, _ := snapshot.Open(t.TempDir())
	r := func(s string) flow.AddressRange { v, _ := flow.PrefixRange(netip.MustParsePrefix(s)); return v }
	data := fm.Data{Metadata: fm.Metadata{Device: "fw", Vendor: "paloalto"}, Zones: []fm.ZoneRecord{{Object: fm.Object{ID: "in"}}, {Object: fm.Object{ID: "out"}}}, Interfaces: []fm.InterfaceRecord{{Object: fm.Object{ID: "a"}, Zone: "in"}, {Object: fm.Object{ID: "b"}, Zone: "out"}}, Routes: []fm.RouteRecord{{Object: fm.Object{ID: "default-a"}, Destination: netip.MustParsePrefix("0.0.0.0/0"), Interface: "a"}, {Object: fm.Object{ID: "default-b"}, Destination: netip.MustParsePrefix("0.0.0.0/0"), Interface: "b"}}}
	fw, err := fm.Seal(data)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := store.Publish(ctx, fw, snapshot.PublishOptions{PublicationID: "p"})
	if err != nil {
		t.Fatal(err)
	}
	top := inventory.Topology{Version: 1}
	d, _ := operations.NewBatchDesigner(operations.BatchDesignerOptions{Store: store})
	batch := operations.BatchRequest{Version: 1, Topology: &top, Requests: []operations.AccessRequest{{Traffic: requestTraffic(t, "192.0.2.10/32", "198.51.100.10/32", 1024)}}}
	result, err := d.Query(ctx, batch)
	if err != nil || len(result.Inputs[0].Outcomes) != 0 || len(result.Issues) != 2 {
		t.Fatal("default route became ownership", result, err)
	}
	top.Bindings = []inventory.Binding{{Device: "fw", Revision: pub.Revision, Zone: "out", Role: inventory.Protection, View: inventory.Original, Networks: []flow.AddressRange{r("198.51.100.0/24")}}, {Device: "fw", Revision: pub.Revision, Zone: "in", Role: inventory.Ingress, View: inventory.Original, Networks: []flow.AddressRange{r("192.0.2.0/24")}}}
	result, err = d.Design(ctx, batch)
	if err != nil || len(result.Devices) != 0 {
		t.Fatal(result, err)
	}
	found := false
	for _, issue := range result.Issues {
		found = found || issue.Code == "unknown_path"
	}
	if !found {
		t.Fatal("ambiguous route disappeared", result)
	}
}

func TestBatchDesignerExplicitTargetsDoNotReinterpretTranslatedAddresses(t *testing.T) {
	_, store, _, req := collectionFixture(t)
	d, _ := operations.NewBatchDesigner(operations.BatchDesignerOptions{Store: store})
	result, err := d.Design(context.Background(), operations.BatchRequest{Version: 1, Requests: []operations.AccessRequest{{View: inventory.Translated, Traffic: requestTraffic(t, "192.0.2.10/32", "198.51.100.10/32", 1024), Targets: []operations.AccessTarget{{Device: req.Device, Packet: true, Request: policy.Request{FromZone: "inside"}}}}}})
	if err != nil || len(result.Devices) != 0 || len(result.Issues) != 1 || result.Issues[0].Code != "wire_evidence_required" {
		t.Fatal("translated input treated as wire", result, err)
	}
}

func TestBatchDesignerRechecksForwardAliasAfterNewPermit(t *testing.T) {
	ctx := context.Background()
	store, _ := snapshot.Open(t.TempDir())
	raw, err := os.ReadFile("../vendors/srx/testdata/nat.set")
	if err != nil {
		t.Fatal(err)
	}
	fw := parseNative(t, string(raw), fm.Metadata{Device: "srx", Vendor: "srx"})
	if !fw.Complete() {
		t.Fatal(fw.Diagnostics())
	}
	_, err = store.Publish(ctx, fw, snapshot.PublishOptions{PublicationID: "s"})
	if err != nil {
		t.Fatal(err)
	}
	d, _ := operations.NewBatchDesigner(operations.BatchDesignerOptions{Store: store})
	traffic := requestTraffic(t, "192.0.2.20/32", "198.51.100.20/32", 1024)
	result, err := d.Design(ctx, operations.BatchRequest{Version: 1, Requests: []operations.AccessRequest{{Traffic: traffic, View: inventory.Translated, WireCandidates: []operations.WireCandidate{{Traffic: traffic, Target: operations.AccessTarget{Device: "srx", Request: policy.Request{FromZone: "inside"}}}}}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, device := range result.Devices {
		if device.Batch.Plan != nil {
			t.Fatal("identity on a denied path became a false post-permit NAT proof")
		}
	}
	found := false
	for _, issue := range result.Issues {
		found = found || issue.Code == "packet_recheck_failed"
	}
	if !found {
		t.Fatal(result)
	}
}

func TestBatchDesignerPreservesPossibleDynamicAllocation(t *testing.T) {
	ctx := context.Background()
	store, _ := snapshot.Open(t.TempDir())
	raw, err := os.ReadFile("../vendors/srx/testdata/nat.set")
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw) + "set security policies from-zone inside to-zone outside policy outbound match source-address any\nset security policies from-zone inside to-zone outside policy outbound match destination-address any\nset security policies from-zone inside to-zone outside policy outbound match application any\nset security policies from-zone inside to-zone outside policy outbound then permit\n"
	fw := parseNative(t, text, fm.Metadata{Device: "srx", Vendor: "srx"})
	_, err = store.Publish(ctx, fw, snapshot.PublishOptions{PublicationID: "s"})
	if err != nil {
		t.Fatal(err)
	}
	d, _ := operations.NewBatchDesigner(operations.BatchDesignerOptions{Store: store})
	result, err := d.Query(ctx, operations.BatchRequest{Version: 1, Requests: []operations.AccessRequest{{Traffic: requestTraffic(t, "192.0.2.20/32", "198.51.100.20/32", 1024), Targets: []operations.AccessTarget{{Device: "srx", Packet: true, Request: policy.Request{FromZone: "inside"}}}}}})
	if err != nil || len(result.Inputs[0].Outcomes) != 1 {
		t.Fatal(result, err)
	}
	out := result.Inputs[0].Outcomes[0]
	if !out.NAT.PossibleAllocation || out.NAT.Exact || out.Disposition != plan.BatchCovered || out.NativeRequests[0].Traffic.Regions()[0].Source.First.String() != "192.0.2.20" {
		t.Fatal(out)
	}
}
func TestBatchDesignerHillstoneExplicitPolicyAndUnsupportedPacketAreSeparate(t *testing.T) {
	ctx := context.Background()
	store, _ := snapshot.Open(t.TempDir())
	raw, err := os.ReadFile("../vendors/hillstone/testdata/basic.cfg")
	if err != nil {
		t.Fatal(err)
	}
	_ = raw
	fw := parseNative(t, "zone inside\nexit\nzone outside\nexit\n", fm.Metadata{Device: "stone", Vendor: "hillstone"})
	_, err = store.Publish(ctx, fw, snapshot.PublishOptions{PublicationID: "h"})
	if err != nil {
		t.Fatal(err)
	}
	d, _ := operations.NewBatchDesigner(operations.BatchDesignerOptions{Store: store})
	traffic := requestTraffic(t, "192.0.2.20/32", "198.51.100.20/32", 1024)
	result, err := d.Design(ctx, operations.BatchRequest{Version: 1, Requests: []operations.AccessRequest{{Traffic: traffic, Targets: []operations.AccessTarget{{Device: "stone", Request: policy.Request{FromZone: "inside", ToZone: "outside"}}, {Device: "stone", Packet: true, Request: policy.Request{FromZone: "inside"}}}}}})
	if err != nil || len(result.Devices) != 1 || result.Devices[0].Batch.Plan == nil || len(result.Issues) != 1 || result.Issues[0].Code != "unsupported_packet" {
		t.Fatal(result, err)
	}
}
func TestBatchDesignerASARecordsBothACLsWithoutGuessingDesignTarget(t *testing.T) {
	ctx := context.Background()
	store, _ := snapshot.Open(t.TempDir())
	raw := "interface i\n nameif inside\n security-level 100\n ip address 192.0.2.1 255.255.255.0\n!\ninterface o\n nameif outside\n security-level 0\n ip address 203.0.113.1 255.255.255.0\n!\naccess-list IN extended permit ip any4 any4\naccess-group IN in interface inside\naccess-list OUT extended deny ip any4 any4\naccess-group OUT out interface outside\n"
	fw := parseNative(t, raw, fm.Metadata{Device: "asa", Vendor: "asa", Software: "9.12"})
	_, err := store.Publish(ctx, fw, snapshot.PublishOptions{PublicationID: "a"})
	if err != nil {
		t.Fatal(err)
	}
	d, _ := operations.NewBatchDesigner(operations.BatchDesignerOptions{Store: store})
	result, err := d.Design(ctx, operations.BatchRequest{Version: 1, Requests: []operations.AccessRequest{{Traffic: requestTraffic(t, "192.0.2.10/32", "203.0.113.10/32", 1024), Targets: []operations.AccessTarget{{Device: "asa", Packet: true, Request: policy.Request{FromZone: "inside"}}}}}})
	if err != nil || len(result.Devices) != 0 || len(result.Inputs[0].Outcomes) != 1 || len(result.Issues) != 1 || result.Issues[0].Code != "unsupported_native_composition" {
		t.Fatal(result, err)
	}
	native := result.Inputs[0].Outcomes[0].NativeRequests
	if len(native) != 2 || native[0].RuleSet != "IN" || native[1].RuleSet != "OUT" {
		t.Fatal(native)
	}
	// An unplannable outcome still occupies its original position. Device-local
	// planning indexes must identify later outcomes, including across inputs.
	for _, device := range []string{"z-policy", "a-policy"} {
		fw := parseNative(t, strings.ReplaceAll(panBase, "198.51.100", "203.0.113"), fm.Metadata{Device: device, Vendor: "paloalto"})
		if _, err := store.Publish(ctx, fw, snapshot.PublishOptions{PublicationID: device}); err != nil {
			t.Fatal(err)
		}
	}
	policyTarget := func(device string) operations.AccessTarget {
		return operations.AccessTarget{Device: device, Request: policy.Request{FromZone: "inside", ToZone: "outside"}}
	}
	requests := []operations.AccessRequest{
		{
			ID: "same-ticket", Traffic: requestTraffic(t, "192.0.2.10/32", "203.0.113.10/32", 1024),
			Sources: []string{"ticket", "ticket", "note"},
			Targets: []operations.AccessTarget{
				{Device: "asa", Packet: true, Request: policy.Request{FromZone: "inside"}},
				policyTarget("z-policy"), policyTarget("a-policy"),
			},
		},
		{
			ID: "same-ticket", Traffic: requestTraffic(t, "192.0.2.11/32", "203.0.113.11/32", 1024),
			Sources: []string{"later"}, Targets: []operations.AccessTarget{policyTarget("z-policy")},
		},
	}
	result, err = d.Design(ctx, operations.BatchRequest{Version: 1, Requests: requests})
	if err != nil || len(result.Devices) != 2 || len(result.Inputs) != 2 || len(result.Inputs[0].Outcomes) != 3 || len(result.Inputs[1].Outcomes) != 1 {
		t.Fatal(result, err)
	}
	if result.Inputs[0].Outcomes[0].Disposition != plan.BatchPending || len(result.Issues) != 1 || !slices.Equal(result.Issues[0].Sources, requests[0].Sources) {
		t.Fatal("unplannable outcome or source order changed", result)
	}
	wantSources := [][]operations.BatchSource{
		{{Index: 0, Input: 0, Outcome: 2}},
		{{Index: 0, Input: 0, Outcome: 1}, {Index: 1, Input: 1, Outcome: 0}},
	}
	for i, device := range result.Devices {
		if device.Device != []string{"a-policy", "z-policy"}[i] || !slices.Equal(device.Sources, wantSources[i]) || device.Batch.Plan == nil {
			t.Fatal("device-local inputs lost provenance", device)
		}
		for _, source := range device.Sources {
			outcome := result.Inputs[source.Input].Outcomes[source.Outcome]
			if outcome.Device != device.Device || outcome.Disposition != device.Batch.Inputs[source.Index].Disposition {
				t.Fatal("disposition updated a different outcome", device, outcome)
			}
		}
		var material bytes.Buffer
		sum, err := plan.EncodeReconstruction(ctx, &material, plan.SnapshotRevisions{Baseline: device.Revision}, device.Batch.Plan)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := plan.DecodeReconstruction(ctx, &material, sum)
		if err != nil {
			t.Fatal(err)
		}
		rebuilt, err := decoded.Rebuild(ctx, plan.ReconstructionSnapshots{Baseline: device.Batch.Plan.Before()}, vendors.Renderer)
		if err != nil || rebuilt.Digest() != device.Batch.Plan.Digest() {
			t.Fatal("device-local replay changed", err)
		}
	}
	document, err := json.Marshal(result.Document())
	if err != nil {
		t.Fatal(err)
	}
	var restored operations.ReportDocument
	if err := json.Unmarshal(document, &restored); err != nil {
		t.Fatal(err)
	}
	repeated, err := json.Marshal(restored)
	if err != nil || !bytes.Equal(document, repeated) {
		t.Fatal("report provenance roundtrip", err)
	}
}

func TestBatchDesignerBoundsIssueExpansion(t *testing.T) {
	store, _ := snapshot.Open(t.TempDir())
	d, _ := operations.NewBatchDesigner(operations.BatchDesignerOptions{Store: store, Engine: policy.Engine{Limits: policy.Limits{MaxRegions: 1}}})
	result, err := d.Design(context.Background(), operations.BatchRequest{Version: 1, Requests: []operations.AccessRequest{{Traffic: requestTraffic(t, "192.0.2.1/32", "198.51.100.1/32", 1024), Targets: []operations.AccessTarget{{Device: "a"}, {Device: "b"}}}}})
	if !errors.Is(err, policy.ErrBudget) || len(result.Issues) > 1 || len(result.Devices) > 0 {
		t.Fatal("unbounded issue expansion", result, err)
	}
	d, _ = operations.NewBatchDesigner(operations.BatchDesignerOptions{Store: store, Engine: policy.Engine{Limits: policy.Limits{MaxVisits: 1}}})
	result, err = d.Design(context.Background(), operations.BatchRequest{Version: 1, Requests: []operations.AccessRequest{
		{Traffic: requestTraffic(t, "192.0.2.1/32", "198.51.100.1/32", 1024), Targets: []operations.AccessTarget{{Device: "a"}, {Device: "b"}}},
		{ID: "not visited"},
	}})
	if !errors.Is(err, policy.ErrBudget) || len(result.Inputs) != 1 || result.Inputs[0].Index != 0 || len(result.Issues) != 1 {
		t.Fatal("fatal target resolution must retain only visited inputs", result, err)
	}
}

func TestBatchDesignerSameDeviceDoesNotHideStaleDestinationBinding(t *testing.T) {
	_, store, _, req := collectionFixture(t)
	r := func(s string) flow.AddressRange { v, _ := flow.PrefixRange(netip.MustParsePrefix(s)); return v }
	top := inventory.Topology{Version: 1, Bindings: []inventory.Binding{{Device: req.Device, Revision: req.Expected, Zone: "inside", Role: inventory.Protection, View: inventory.Original, Networks: []flow.AddressRange{r("192.0.2.0/24")}}, {Device: req.Device, Revision: "old", Zone: "outside", Role: inventory.Protection, View: inventory.Original, Networks: []flow.AddressRange{r("198.51.100.0/24")}}, {Device: req.Device, Revision: req.Expected, Zone: "inside", Role: inventory.Ingress, View: inventory.Original, Networks: []flow.AddressRange{r("192.0.2.0/24")}}}}
	d, _ := operations.NewBatchDesigner(operations.BatchDesignerOptions{Store: store})
	result, err := d.Design(context.Background(), operations.BatchRequest{Version: 1, Topology: &top, Requests: []operations.AccessRequest{{Traffic: requestTraffic(t, "192.0.2.10/32", "198.51.100.10/32", 1024)}}})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, issue := range result.Issues {
		found = found || issue.Code == "stale_topology"
	}
	if !found {
		t.Fatal("coalescing hid stale topology")
	}
	if len(result.Devices) != 1 || result.Devices[0].Batch.Plan == nil {
		t.Fatal("valid source-side plan lost", result)
	}
}

const businessSRXAliasBase = "set interfaces ge-0/0/0 unit 0 family inet address 192.0.2.1/24\nset interfaces ge-0/0/1 unit 0 family inet address 203.0.113.1/24\nset security zones security-zone inside interfaces ge-0/0/0.0\nset security zones security-zone outside interfaces ge-0/0/1.0\nset security nat static rule-set public from zone outside\nset security nat static rule-set public rule one match destination-address 203.0.113.0/24\nset security nat static rule-set public rule one then static-nat prefix 192.0.2.0/24\n"

func TestBatchDesignerDiscoversRealStaticAliasFromPinnedTopology(t *testing.T) {
	ctx := t.Context()
	store, _ := snapshot.Open(t.TempDir())
	fw := parseNative(t, businessSRXAliasBase, fm.Metadata{Device: "srx", Vendor: "srx"})
	pub, err := store.Publish(ctx, fw, snapshot.PublishOptions{PublicationID: "s"})
	if err != nil {
		t.Fatal(err)
	}
	r := func(s string) flow.AddressRange { v, _ := flow.PrefixRange(netip.MustParsePrefix(s)); return v }
	top := inventory.Topology{Version: 1, Bindings: []inventory.Binding{{Device: "srx", Revision: pub.Revision, Zone: "inside", Role: inventory.Protection, View: inventory.Real, Networks: []flow.AddressRange{r("192.0.2.0/24")}}, {Device: "srx", Revision: pub.Revision, Zone: "outside", Role: inventory.Ingress, View: inventory.Real, Networks: []flow.AddressRange{r("198.51.100.0/24")}}}}
	d, _ := operations.NewBatchDesigner(operations.BatchDesignerOptions{Store: store})
	result, err := d.Design(ctx, operations.BatchRequest{Version: 1, Topology: &top, Requests: []operations.AccessRequest{{Traffic: requestTraffic(t, "198.51.100.1/32", "192.0.2.128/25", 1024), View: inventory.Real}}})
	if err != nil || len(result.Devices) != 1 || result.Devices[0].Batch.Plan == nil || len(result.Inputs[0].Outcomes) != 1 {
		t.Fatal("real topology never reached static alias proof", result, err)
	}
	o := result.Inputs[0].Outcomes[0]
	if o.Wire.Regions()[0].Destination != r("203.0.113.128/25") || o.NativeRequests[0].Traffic.Regions()[0].Destination != r("192.0.2.128/25") {
		t.Fatal(o)
	}
}
func TestBatchDesignerExplicitRealViewAllowsLaterPossibleSNAT(t *testing.T) {
	ctx := t.Context()
	store, _ := snapshot.Open(t.TempDir())
	raw := businessSRXAliasBase + "set security nat source pool pool address 198.51.100.200/32\nset security nat source rule-set incoming from zone outside\nset security nat source rule-set incoming to zone inside\nset security nat source rule-set incoming rule hide match source-address 198.51.100.0/24\nset security nat source rule-set incoming rule hide then source-nat pool pool\n"
	fw := parseNative(t, raw, fm.Metadata{Device: "srx", Vendor: "srx"})
	_, err := store.Publish(ctx, fw, snapshot.PublishOptions{PublicationID: "s"})
	if err != nil {
		t.Fatal(err)
	}
	business := requestTraffic(t, "198.51.100.1/32", "192.0.2.10/32", 1024)
	wire := requestTraffic(t, "198.51.100.1/32", "203.0.113.10/32", 1024)
	d, _ := operations.NewBatchDesigner(operations.BatchDesignerOptions{Store: store})
	result, err := d.Design(ctx, operations.BatchRequest{Version: 1, Requests: []operations.AccessRequest{{Traffic: business, View: inventory.Real, WireCandidates: []operations.WireCandidate{{Traffic: wire, Target: operations.AccessTarget{Device: "srx", Request: policy.Request{FromZone: "outside"}}}}}}})
	if err != nil || len(result.Issues) != 0 || len(result.Devices) != 1 || result.Devices[0].Batch.Plan == nil {
		t.Fatal("real view conflated with full SNAT output", result, err)
	}
	after, err := (policy.Engine{}).QueryPacket(ctx, result.Devices[0].Batch.Plan.After(), policy.PacketRequest{Request: policy.Request{Traffic: wire, FromZone: "outside"}})
	if err != nil || len(after.Paths) != 1 || !after.Paths[0].NAT.PossibleAllocation || after.Paths[0].NAT.Exact {
		t.Fatal(after, err)
	}
	real, ok := after.Paths[0].View(policy.RealView)
	same, err := real.Equal(business, 4096)
	if err != nil || !ok || !same {
		t.Fatal("pre-SNAT real evidence changed", real, err)
	}
}

func TestBatchDesignerPANPartitionedTranslatedCandidate(t *testing.T) {
	ctx := t.Context()
	store, _ := snapshot.Open(t.TempDir())
	r := func(s string) flow.AddressRange { v, _ := flow.PrefixRange(netip.MustParsePrefix(s)); return v }
	any := fm.Match{AnySource: true, AnyDestination: true, AnyService: true, AnyFromZone: true, AnyToZone: true}
	match := any
	match.AnyDestination = false
	match.Destinations = []fm.AddressRef{{Kind: fm.AddressObject, ID: "public"}}
	data := fm.Data{Metadata: fm.Metadata{Device: "pan", Vendor: "paloalto"}, Zones: []fm.ZoneRecord{{Object: fm.Object{ID: "outside"}}, {Object: fm.Object{ID: "left"}}, {Object: fm.Object{ID: "right"}}}, Interfaces: []fm.InterfaceRecord{{Object: fm.Object{ID: "out", Scope: "vr"}, Zone: "outside"}, {Object: fm.Object{ID: "l", Scope: "vr"}, Zone: "left"}, {Object: fm.Object{ID: "r", Scope: "vr"}, Zone: "right"}}, Routes: []fm.RouteRecord{{Object: fm.Object{ID: "default", Scope: "vr"}, Destination: netip.MustParsePrefix("0.0.0.0/0"), Interface: "out"}, {Object: fm.Object{ID: "left", Scope: "vr"}, Destination: netip.MustParsePrefix("10.0.0.0/25"), Interface: "l"}, {Object: fm.Object{ID: "right", Scope: "vr"}, Destination: netip.MustParsePrefix("10.0.0.128/25"), Interface: "r"}}, Addresses: []fm.AddressRecord{{Object: fm.Object{ID: "public"}, Ranges: []flow.AddressRange{r("203.0.113.0/24")}}}, DynamicNATs: []fm.DynamicNATRecord{{Object: fm.Object{ID: "publish"}, Match: match, SourceMode: fm.NoTranslation, DestinationMode: fm.StaticIP, Destination: []fm.Mapping{{Original: r("203.0.113.0/24"), Translated: r("10.0.0.0/24"), Mode: fm.Offset}}}}, Rules: []fm.RuleRecord{{Object: fm.Object{ID: "permit"}, RuleSet: "security", Action: fm.Permit, Match: any}}}
	fw, err := fm.Seal(data)
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.Publish(ctx, fw, snapshot.PublishOptions{PublicationID: "pan"})
	if err != nil {
		t.Fatal(err)
	}
	d, _ := operations.NewBatchDesigner(operations.BatchDesignerOptions{Store: store})
	result, err := d.Design(ctx, operations.BatchRequest{Version: 1, Requests: []operations.AccessRequest{{Traffic: requestTraffic(t, "198.51.100.1/32", "10.0.0.0/24", 1024), View: inventory.Translated, WireCandidates: []operations.WireCandidate{{Traffic: requestTraffic(t, "198.51.100.1/32", "203.0.113.0/24", 1024), Target: operations.AccessTarget{Device: "pan", VRF: "vr", Request: policy.Request{FromZone: "outside"}}}}}}})
	if err != nil || len(result.Issues) != 0 || len(result.Inputs[0].Outcomes) != 2 || len(result.Devices) != 1 || result.Devices[0].Batch.Plan == nil {
		t.Fatal("split NAT candidate failed validation", result, err)
	}
	for _, o := range result.Inputs[0].Outcomes {
		same, err := o.Wire.Equal(o.NAT.Original, 4096)
		if err != nil || !same {
			t.Fatal("relation identity widened", o, err)
		}
	}
}

func TestBatchDesignerRealAliasAmbiguityAndFailedForwardKeepSafeFractions(t *testing.T) {
	for _, scenario := range []string{"ambiguous", "shadowed"} {
		t.Run(scenario, func(t *testing.T) {
			ctx := t.Context()
			store, _ := snapshot.Open(t.TempDir())
			raw := businessSRXAliasBase
			want, code := "192.0.2.0/25", "ambiguous_alias"
			if scenario == "ambiguous" {
				raw += "set security nat static rule-set public rule two match destination-address 198.51.100.128/25\nset security nat static rule-set public rule two then static-nat prefix 192.0.2.128/25\n"
			} else {
				raw = strings.Replace(raw, "set security nat static rule-set public rule one match", "set routing-options static route 10.0.0.0/24 next-hop 192.0.2.254\nset security nat static rule-set public rule earlier match destination-address 203.0.113.0/25\nset security nat static rule-set public rule earlier then static-nat prefix 10.0.0.0/25\nset security nat static rule-set public rule one match", 1)
				want, code = "192.0.2.128/25", "unlocated_alias"
			}
			fw := parseNative(t, raw, fm.Metadata{Device: "srx", Vendor: "srx"})
			pub, err := store.Publish(ctx, fw, snapshot.PublishOptions{PublicationID: "s"})
			if err != nil {
				t.Fatal(err)
			}
			r := func(s string) flow.AddressRange { v, _ := flow.PrefixRange(netip.MustParsePrefix(s)); return v }
			top := inventory.Topology{Version: 1, Bindings: []inventory.Binding{{Device: "srx", Revision: pub.Revision, Zone: "inside", Role: inventory.Protection, View: inventory.Real, Networks: []flow.AddressRange{r("192.0.2.0/24")}}, {Device: "srx", Revision: pub.Revision, Zone: "outside", Role: inventory.Ingress, View: inventory.Real, Networks: []flow.AddressRange{r("198.51.100.0/24")}}}}
			d, _ := operations.NewBatchDesigner(operations.BatchDesignerOptions{Store: store})
			result, err := d.Design(ctx, operations.BatchRequest{Version: 1, Topology: &top, Requests: []operations.AccessRequest{{Traffic: requestTraffic(t, "198.51.100.1/32", "192.0.2.0/24", 1024), View: inventory.Real}}})
			if err != nil || len(result.Devices) != 1 || result.Devices[0].Batch.Plan == nil {
				t.Fatal(result, err)
			}
			targets := result.Devices[0].Batch.Plan.Targets()
			if len(targets) != 1 || targets[0].Traffic.Regions()[0].Destination != r(want) {
				t.Fatal("safe fraction widened or lost", targets)
			}
			found := false
			for _, issue := range result.Issues {
				if issue.Code == code {
					found = true
					if issue.TrafficView != "real" {
						t.Fatal(issue)
					}
				}
			}
			if !found {
				t.Fatal("missing unresolved alias fraction", result.Issues)
			}
		})
	}
}

func TestBatchDesignerBusinessFailureCoordinates(t *testing.T) {
	ctx := t.Context()
	store, _ := snapshot.Open(t.TempDir())
	fw := parseNative(t, businessSRXAliasBase, fm.Metadata{Device: "srx", Vendor: "srx"})
	pub, err := store.Publish(ctx, fw, snapshot.PublishOptions{PublicationID: "s"})
	if err != nil {
		t.Fatal(err)
	}
	d, _ := operations.NewBatchDesigner(operations.BatchDesignerOptions{Store: store})
	network := func(s string) flow.AddressRange { v, _ := flow.PrefixRange(netip.MustParsePrefix(s)); return v }
	business := requestTraffic(t, "198.51.100.1/32", "192.0.2.10/32", 1024)
	for _, view := range []inventory.View{inventory.Real, inventory.Translated} {
		for _, failure := range []string{"stale_protection", "stale_ingress", "missing_ingress", "ambiguous_ingress", "unlocated", "ambiguous_location", "missing_snapshot"} {
			t.Run(string(view)+"/"+failure, func(t *testing.T) {
				protection := inventory.Binding{Device: "srx", Revision: pub.Revision, Zone: "inside", Role: inventory.Protection, View: view, Networks: []flow.AddressRange{network("192.0.2.0/24")}}
				ingress := inventory.Binding{Device: "srx", Revision: pub.Revision, Zone: "outside", Role: inventory.Ingress, View: view, Networks: []flow.AddressRange{network("198.51.100.0/24")}}
				top := inventory.Topology{Version: 1, Bindings: []inventory.Binding{protection, ingress}}
				want := ""
				switch failure {
				case "stale_protection":
					top.Bindings[0].Revision = "stale"
					want = "stale_topology"
				case "stale_ingress":
					top.Bindings[1].Revision = "stale"
					want = "stale_topology"
				case "missing_ingress":
					top.Bindings = top.Bindings[:1]
					want = "ingress_missing"
				case "ambiguous_ingress":
					top.Bindings = append(top.Bindings, ingress)
					want = "ingress_ambiguous"
				case "unlocated":
					top.Bindings = top.Bindings[1:]
					want = "unlocated_destination"
				case "ambiguous_location":
					top.Bindings = append(top.Bindings, protection)
					want = "ambiguous_destination"
				case "missing_snapshot":
					top.Bindings[0].Device = "missing"
					want = "snapshot_missing"
				}
				result, err := d.Query(ctx, operations.BatchRequest{Version: 1, Topology: &top, Requests: []operations.AccessRequest{{Traffic: business, View: view}}})
				if err != nil {
					t.Fatal(err)
				}
				found := false
				for _, issue := range result.Issues {
					if issue.Code == want {
						found = true
					}
					same, err := issue.Traffic.Equal(business, 4096)
					if err != nil || !same || issue.TrafficView != string(view) {
						t.Errorf("%s carries business traffic but view=%q, want %q", issue.Code, issue.TrafficView, view)
					}
				}
				if !found {
					t.Fatalf("missing %s issue", want)
				}
			})
		}
	}
}

func TestBatchDesignerWireCandidateFailureCoordinates(t *testing.T) {
	ctx := t.Context()
	store, _ := snapshot.Open(t.TempDir())
	fw := parseNative(t, businessSRXAliasBase, fm.Metadata{Device: "srx", Vendor: "srx"})
	_, err := store.Publish(ctx, fw, snapshot.PublishOptions{PublicationID: "s"})
	if err != nil {
		t.Fatal(err)
	}
	d, _ := operations.NewBatchDesigner(operations.BatchDesignerOptions{Store: store})
	business := requestTraffic(t, "198.51.100.1/32", "192.0.2.10/32", 1024)
	wire := requestTraffic(t, "198.51.100.1/32", "203.0.113.11/32", 1024)
	for _, view := range []inventory.View{inventory.Real, inventory.Translated} {
		for _, failure := range []string{"stale", "forward"} {
			t.Run(string(view)+"/"+failure, func(t *testing.T) {
				target := operations.AccessTarget{Device: "srx", Request: policy.Request{FromZone: "outside"}}
				want := "forward_validation_failed"
				if failure == "stale" {
					target.Revision = "stale"
					want = "stale_topology"
				}
				sources := []string{"ticket", "ticket", "wire"}
				result, err := d.Query(ctx, operations.BatchRequest{Version: 1, Requests: []operations.AccessRequest{{Traffic: business, View: view, Sources: sources, WireCandidates: []operations.WireCandidate{{Traffic: wire, Target: target}}}}})
				if err != nil {
					t.Fatal(err)
				}
				foundWire, foundBusiness := false, false
				for _, issue := range result.Issues {
					wantSources := sources
					if issue.Code == want {
						wantSources = append(slices.Clone(sources), sources...)
					}
					if !slices.Equal(issue.Sources, wantSources) {
						t.Fatal("wire evidence source order or duplicates changed", issue)
					}
					if issue.Code == want {
						foundWire = true
						same, err := issue.Traffic.Equal(wire, 4096)
						if err != nil || !same || issue.TrafficView != "original" {
							t.Errorf("%s must retain original wire coordinates, got view=%q", issue.Code, issue.TrafficView)
						}
					}
					if issue.Code == "unvalidated_"+string(view) {
						foundBusiness = true
						same, err := issue.Traffic.Equal(business, 4096)
						if err != nil || !same || issue.TrafficView != string(view) {
							t.Errorf("unvalidated remainder must retain %s coordinates, got %q", view, issue.TrafficView)
						}
					}
				}
				if !foundWire || !foundBusiness {
					t.Fatal("missing wire failure or business remainder", result.Issues)
				}
			})
		}
	}
}
