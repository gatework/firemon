package operations_test

import (
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/inventory"
	"github.com/gatework/firemon/operations"
	"github.com/gatework/firemon/policy"
	"github.com/gatework/firemon/snapshot"
)

func emptySearchStore(t *testing.T) *countedBatchStore {
	t.Helper()
	store, err := snapshot.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return &countedBatchStore{Store: store}
}

func TestSearcherBoundsSourceContainersBeforePersistence(t *testing.T) {
	for _, counts := range [][]int{{65}, {33, 33}} {
		store := emptySearchStore(t)
		searcher, err := operations.NewSearcher(operations.SearcherOptions{Store: store, Engine: policy.Engine{Limits: policy.Limits{MaxVisits: 64}}})
		if err != nil {
			t.Fatal(err)
		}
		var requests []operations.AccessRequest
		for _, count := range counts {
			requests = append(requests, operations.AccessRequest{
				Src: "192.0.2.1", Dst: "198.51.100.1", Service: "443",
				// Empty strings still consume slice storage and processing work.
				Sources: make([]string, count),
			})
		}
		report, err := searcher.Query(t.Context(), operations.BatchRequest{Requests: requests})
		if !errors.Is(err, policy.ErrBudget) || len(report.Inputs) != 0 || store.manifests != 0 || store.loads != 0 {
			t.Fatal("request source containers passed preflight", counts, report, err, store.manifests, store.loads)
		}
	}
}

func TestSearcherBoundsTopologyDataBeforeCopyOrPersistence(t *testing.T) {
	network, _ := flow.PrefixRange(netip.MustParsePrefix("192.0.2.0/24"))
	for _, test := range []struct {
		name    string
		sources []string
	}{
		{"source count", make([]string, 65)},
		{"source bytes", []string{strings.Repeat("x", operations.MaxRequestBytes+1)}},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := emptySearchStore(t)
			topology := &inventory.Topology{Version: 1, Bindings: []inventory.Binding{{
				Device: "fw", Revision: strings.Repeat("a", 64), Scope: "policy", VRF: "vr", Zone: "inside",
				Role: inventory.Ingress, View: inventory.Original, Networks: []flow.AddressRange{network}, Sources: test.sources,
			}}}
			options := operations.SearcherOptions{Store: store, Engine: policy.Engine{Limits: policy.Limits{MaxVisits: 64}}, Topology: topology}
			if searcher, err := operations.NewSearcher(options); searcher != nil || !errors.Is(err, policy.ErrBudget) {
				t.Fatal("constructor accepted an oversized nested topology", searcher, err)
			}
			options.Topology = nil
			searcher, err := operations.NewSearcher(options)
			if err != nil {
				t.Fatal(err)
			}
			report, err := searcher.Query(t.Context(), operations.BatchRequest{
				Topology: topology, Requests: []operations.AccessRequest{{Src: "192.0.2.1", Dst: "198.51.100.1", Service: "443"}},
			})
			if !errors.Is(err, policy.ErrBudget) || len(report.Inputs) != 0 || store.manifests != 0 || store.loads != 0 {
				t.Fatal("per-query topology bypassed preflight", report, err, store.manifests, store.loads)
			}
		})
	}
}

func TestSearcherRejectsTrafficInsideTextTargetsWithoutLosingSibling(t *testing.T) {
	store := emptySearchStore(t)
	graph := searchGraph(t, "fw", "192.0.2.1/24", "198.51.100.1/24", fm.Permit)
	publishSearch(t, store.Store, graph, "", "target-contract")
	searcher, err := operations.NewSearcher(operations.SearcherOptions{Store: store})
	if err != nil {
		t.Fatal(err)
	}
	good := operations.AccessRequest{
		Src: "192.0.2.10", Dst: "198.51.100.10", Service: "443",
		Targets: []operations.AccessTarget{{Device: "fw", Request: policy.Request{Scope: "policy", FromZone: "inside", ToZone: "outside"}}},
	}
	bad := good
	bad.ID = "ambiguous input"
	bad.Targets = slices.Clone(good.Targets)
	bad.Targets[0].Request.Traffic = requestTraffic(t, "203.0.113.1/32", "203.0.113.2/32", 1234)
	report, err := searcher.Query(t.Context(), operations.BatchRequest{Requests: []operations.AccessRequest{bad, good}})
	if err != nil || len(report.Inputs) != 2 {
		t.Fatal(report, err)
	}
	first, second := report.Inputs[0], report.Inputs[1]
	if first.Error == nil || len(first.Outcomes) != 0 || first.Request.Targets[0].Request.Traffic.Empty() {
		t.Fatal("text target's conflicting traffic was silently discarded", first)
	}
	if second.Error != nil || len(second.Outcomes) != 1 || second.Outcomes[0].Policy.Allowed.Empty() {
		t.Fatal("invalid target discarded a valid sibling", second)
	}
	if store.manifests != 1 || store.loads != 1 {
		t.Fatal("invalid target performed extra persistence reads", store.manifests, store.loads)
	}
}

func TestSearcherBoundsTargetMetadataBeforePersistence(t *testing.T) {
	large := strings.Repeat("x", operations.MaxRequestBytes+1)
	for _, tc := range []struct {
		name string
		set  func(*operations.AccessRequest)
	}{
		{"input scope", func(a *operations.AccessRequest) { a.Scope = &large }},
		{"input vrf", func(a *operations.AccessRequest) { a.VRF = &large }},
		{"device", func(a *operations.AccessRequest) { a.Targets[0].Device = large }},
		{"target scope", func(a *operations.AccessRequest) { a.Targets[0].Request.Scope = large }},
		{"target revision", func(a *operations.AccessRequest) { a.Targets[0].Revision = large }},
		{"target vrf", func(a *operations.AccessRequest) { a.Targets[0].VRF = large }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := emptySearchStore(t)
			searcher, err := operations.NewSearcher(operations.SearcherOptions{Store: store})
			if err != nil {
				t.Fatal(err)
			}
			a := operations.AccessRequest{Src: "192.0.2.1", Dst: "198.51.100.1", Service: "443", Targets: []operations.AccessTarget{{Device: "fw"}}}
			tc.set(&a)
			report, err := searcher.Query(t.Context(), operations.BatchRequest{Requests: []operations.AccessRequest{a}})
			if !errors.Is(err, policy.ErrBudget) || len(report.Inputs) != 0 || store.manifests != 0 || store.loads != 0 {
				t.Fatal("oversized metadata reached persistence", err, store.manifests, store.loads)
			}
		})
	}
}
