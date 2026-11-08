package inventory_test

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/inventory"
	"github.com/gatework/firemon/snapshot"
)

func indexRange(prefix string) flow.AddressRange {
	r, err := flow.PrefixRange(netip.MustParsePrefix(prefix))
	if err != nil {
		panic(err)
	}
	return r
}

func indexSet(prefixes ...string) flow.AddressSet {
	ranges := make([]flow.AddressRange, len(prefixes))
	for at, prefix := range prefixes {
		ranges[at] = indexRange(prefix)
	}
	set, err := flow.NewAddressSet(ranges...)
	if err != nil {
		panic(err)
	}
	return set
}

func indexGraph(t testing.TB, data fm.Data) *fm.Firewall {
	t.Helper()
	data.Metadata = fm.Metadata{Device: "lab", Vendor: "hillstone", Context: "config"}
	fw, err := fm.Seal(data)
	if err != nil {
		t.Fatal(err)
	}
	return fw
}

func graphIndex(t testing.TB, fw *fm.Firewall) *inventory.Index {
	t.Helper()
	source := &cacheSource{load: func(context.Context, string) (*fm.Firewall, error) { return fw, nil }}
	cache, err := inventory.NewCache(source, inventory.CacheLimits{})
	if err != nil {
		t.Fatal(err)
	}
	index, err := cache.Index(t.Context(), strings.Repeat("a", 64), fw)
	if err != nil {
		t.Fatal(err)
	}
	return index
}

func TestIndexRetainsNativeScopesAndClipsCandidateEvidence(t *testing.T) {
	fw := indexGraph(t, fm.Data{
		Zones: []fm.ZoneRecord{
			{Object: fm.Object{ID: "red", Scope: "vsys"}, Networks: []flow.AddressRange{indexRange("192.0.2.0/24")}},
			{Object: fm.Object{ID: "blue", Scope: "vsys"}},
		},
		Interfaces: []fm.InterfaceRecord{
			{Object: fm.Object{ID: "red-if", Scope: "red-vrf"}, Zone: "red", Addresses: []netip.Prefix{netip.MustParsePrefix("192.0.2.1/24")}},
			{Object: fm.Object{ID: "blue-if", Scope: "blue-vrf"}, Zone: "blue", Addresses: []netip.Prefix{netip.MustParsePrefix("192.0.2.2/24")}},
			{Object: fm.Object{ID: "disabled", Scope: "red-vrf"}, Zone: "red", Addresses: []netip.Prefix{netip.MustParsePrefix("203.0.113.1/24")}, Disabled: true},
		},
		Routes: []fm.RouteRecord{
			{Object: fm.Object{ID: "remote", Scope: "red-vrf"}, Destination: netip.MustParsePrefix("198.51.100.0/24"), Interface: "red-if"},
			{Object: fm.Object{ID: "default", Scope: "red-vrf"}, Destination: netip.MustParsePrefix("0.0.0.0/0"), Interface: "red-if"},
		},
		Addresses: []fm.AddressRecord{
			{Object: fm.Object{ID: "service-host", Scope: "address-book"}, Ranges: []flow.AddressRange{indexRange("192.0.2.64/26")}},
			{Object: fm.Object{ID: "unknown-host", Unsupported: []string{"native condition"}}, Ranges: []flow.AddressRange{indexRange("192.0.2.64/26")}},
			{Object: fm.Object{ID: "any"}, Ranges: []flow.AddressRange{indexRange("0.0.0.0/0"), indexRange("::/0")}},
		},
		Rules: []fm.RuleRecord{{
			Object: fm.Object{ID: "rule", Scope: "policy-scope"}, Action: fm.Permit,
			Match: fm.Match{AnySource: true, AnyDestination: true, AnyService: true, FromZones: []fm.ID{"red", "blue"}, AnyToZone: true},
		}},
	})
	index := graphIndex(t, fw)
	query := indexSet("192.0.2.96/27")
	got, err := index.Candidates(t.Context(), query, 32)
	if err != nil || len(got) != 5 {
		t.Fatal(got, err)
	}
	byID := make(map[fm.ID]inventory.Candidate)
	for _, candidate := range got {
		byID[candidate.ID] = candidate
		if !slices.Equal(candidate.Addresses.Ranges(), query.Ranges()) || candidate.View != inventory.Original {
			t.Fatal("candidate escaped the caller's addresses or changed coordinate view", candidate)
		}
	}
	if byID["red-if"].Scope != "red-vrf" || byID["blue-if"].Scope != "blue-vrf" || byID["red"].Scope != "vsys" || byID["service-host"].Scope != "address-book" {
		t.Fatal("native routing, zone and address namespaces were collapsed", byID)
	}
	if byID["red-if"].Zone != "red" || byID["blue-if"].Zone != "blue" || byID["service-host"].Kind != fm.AddressObject || !byID["service-host"].Reliable || byID["unknown-host"].Reliable {
		t.Fatal("candidate provenance or unknown declaration was lost", byID)
	}
	remote, err := index.Candidates(t.Context(), indexSet("198.51.100.7/32"), 32)
	if err != nil || len(remote) != 1 || remote[0].ID != "remote" || remote[0].Zone != "red" {
		t.Fatal("non-default route evidence was lost", remote, err)
	}
	unknown, err := index.Candidates(t.Context(), indexSet("203.0.113.7/32", "2001:db8::7/128"), 32)
	if err != nil || len(unknown) != 0 {
		t.Fatal("any/default/disabled declarations established candidate evidence", unknown, err)
	}
	wantIngress := []inventory.IngressZone{
		{Scope: "policy-scope", VRF: "blue-vrf", Zone: "blue"},
		{Scope: "policy-scope", VRF: "red-vrf", Zone: "red"},
	}
	ingress := index.Ingress()
	if !slices.Equal(ingress, wantIngress) {
		t.Fatal("policy scope was replaced by VRF", ingress)
	}
	ingress[0] = inventory.IngressZone{}
	got[0].ID = "changed"
	got[1].Addresses = flow.AddressSet{}
	if !slices.Equal(index.Ingress(), wantIngress) {
		t.Fatal("caller changed the cached ingress candidates")
	}
	again, err := index.Candidates(t.Context(), query, 32)
	if err != nil || len(again) != 5 || again[0].ID == "changed" || again[1].Addresses.Empty() {
		t.Fatal("caller changed cached candidate evidence", again, err)
	}
}

func TestIndexKeepsNATCoordinateViewsAndInterfaceHosts(t *testing.T) {
	match := fm.Match{AnySource: true, AnyDestination: true, AnyService: true, FromZones: []fm.ID{"left"}, ToZones: []fm.ID{"right"}}
	fw := indexGraph(t, fm.Data{
		Zones:      []fm.ZoneRecord{{Object: fm.Object{ID: "left"}}, {Object: fm.Object{ID: "right"}}},
		Interfaces: []fm.InterfaceRecord{{Object: fm.Object{ID: "egress", Scope: "vr"}, Zone: "right", Addresses: []netip.Prefix{netip.MustParsePrefix("198.51.100.1/24"), netip.MustParsePrefix("198.51.100.2/24")}}},
		StaticNATs: []fm.StaticNATRecord{
			{Object: fm.Object{ID: "snat", Scope: "nat-scope"}, Match: match, Source: []fm.Mapping{{Original: indexRange("192.0.2.10/32"), Translated: indexRange("203.0.113.10/32"), Mode: fm.Offset}}},
			{Object: fm.Object{ID: "dnat", Scope: "nat-scope"}, Match: match, Destination: []fm.Mapping{{Original: indexRange("203.0.113.20/32"), Translated: indexRange("192.0.2.20/32"), Mode: fm.Offset}}},
			{Object: fm.Object{ID: "disabled", Scope: "nat-scope"}, Match: match, Source: []fm.Mapping{{Original: indexRange("192.0.2.30/32"), Translated: indexRange("203.0.113.30/32"), Mode: fm.Offset}}, Disabled: true},
		},
		NATPools: []fm.NATPoolRecord{{Object: fm.Object{ID: "pool"}, Ranges: []flow.AddressRange{indexRange("203.0.113.40/32")}}},
		DynamicNATs: []fm.DynamicNATRecord{
			{Object: fm.Object{ID: "pat", Scope: "nat-scope"}, Match: match, SourceMode: fm.DynamicIPPort, DestinationMode: fm.NoTranslation, SourcePool: "pool"},
			{Object: fm.Object{ID: "interface", Scope: "nat-scope"}, Match: match, SourceMode: fm.InterfaceIP, DestinationMode: fm.NoTranslation, Interface: "egress", InterfaceAddress: netip.MustParseAddr("198.51.100.2")},
		},
	})
	index := graphIndex(t, fw)
	for _, test := range []struct {
		prefix string
		id     fm.ID
		kind   fm.Kind
		views  []inventory.View
	}{
		{"192.0.2.10/32", "snat", fm.StaticNATObject, []inventory.View{inventory.Original, inventory.Real}},
		{"203.0.113.10/32", "snat", fm.StaticNATObject, []inventory.View{inventory.Translated}},
		{"203.0.113.20/32", "dnat", fm.StaticNATObject, []inventory.View{inventory.Original}},
		{"192.0.2.20/32", "dnat", fm.StaticNATObject, []inventory.View{inventory.Real, inventory.Translated}},
		{"203.0.113.40/32", "pat", fm.DynamicNATObject, []inventory.View{inventory.Translated}},
		{"198.51.100.2/32", "interface", fm.DynamicNATObject, []inventory.View{inventory.Translated}},
	} {
		t.Run(test.prefix, func(t *testing.T) {
			got, err := index.Candidates(t.Context(), indexSet(test.prefix), 32)
			if err != nil {
				t.Fatal(err)
			}
			var views []inventory.View
			for _, candidate := range got {
				if candidate.Kind != test.kind || candidate.ID != test.id {
					continue
				}
				if candidate.Scope != "nat-scope" || !candidate.Reliable {
					t.Fatal(candidate)
				}
				views = append(views, candidate.View)
			}
			if !slices.Equal(views, test.views) {
				t.Fatal("NAT coordinate evidence changed", views, got)
			}
		})
	}
	for _, prefix := range []string{"192.0.2.30/32", "203.0.113.30/32", "198.51.100.1/32", "198.51.100.99/32"} {
		got, err := index.Candidates(t.Context(), indexSet(prefix), 32)
		if err != nil {
			t.Fatal(err)
		}
		for _, candidate := range got {
			if candidate.Kind == fm.StaticNATObject || candidate.Kind == fm.DynamicNATObject {
				t.Fatal("disabled NAT or interface network became a translation target", prefix, candidate)
			}
		}
	}
}

func TestIndexPreservesOverlapsFamiliesAndBoundedResults(t *testing.T) {
	data := fm.Data{Addresses: []fm.AddressRecord{
		{Object: fm.Object{ID: "wide"}, Ranges: []flow.AddressRange{indexRange("192.0.2.0/24")}},
		{Object: fm.Object{ID: "ipv6"}, Ranges: []flow.AddressRange{indexRange("2001:db8::/64")}},
		{Object: fm.Object{ID: "mapped"}, Ranges: []flow.AddressRange{indexRange("::ffff:0:0/96")}},
	}}
	for i := range 64 {
		data.Addresses = append(data.Addresses, fm.AddressRecord{Object: fm.Object{ID: fm.ID(fmt.Sprint("nested-", i))}, Ranges: []flow.AddressRange{indexRange(fmt.Sprintf("192.0.2.%d/32", i))}})
	}
	index := graphIndex(t, indexGraph(t, data))
	got, err := index.Candidates(t.Context(), indexSet("192.0.2.127/32", "2001:db8::7/128", "::ffff:192.0.2.7/128"), 3)
	if err != nil || len(got) != 3 || got[0].ID != "ipv6" || got[1].ID != "mapped" || got[2].ID != "wide" {
		t.Fatal("long containing interval or separate address family was lost", got, err)
	}
	got, err = index.Candidates(t.Context(), indexSet("192.0.2.0/24"), 2)
	if got != nil || !errors.Is(err, flow.ErrBudget) {
		t.Fatal("partial unbounded evidence escaped", got, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if got, err := index.Candidates(ctx, indexSet("192.0.2.127/32"), 2); got != nil || !errors.Is(err, context.Canceled) {
		t.Fatal(got, err)
	}
	if got, err := index.Candidates(t.Context(), indexSet("192.0.2.127/32"), 0); got != nil || !errors.Is(err, flow.ErrBudget) {
		t.Fatal(got, err)
	}
	for _, invalid := range []*inventory.Index{nil, {}} {
		if got, err := invalid.Candidates(t.Context(), indexSet("192.0.2.127/32"), 2); got != nil || !errors.Is(err, inventory.ErrInvalid) {
			t.Fatal(got, err)
		}
	}
}

func TestIndexAgreesWithAddressMembershipAcrossNestedIntervals(t *testing.T) {
	var data fm.Data
	for i := range 128 {
		first := byte((i * 17) % 256)
		last := byte(min(255, int(first)+i%33))
		data.Addresses = append(data.Addresses, fm.AddressRecord{
			Object: fm.Object{ID: fm.ID(fmt.Sprint("range-", i))},
			Ranges: []flow.AddressRange{{First: netip.AddrFrom4([4]byte{192, 0, 2, first}), Last: netip.AddrFrom4([4]byte{192, 0, 2, last})}},
		})
	}
	index := graphIndex(t, indexGraph(t, data))
	for point := range 256 {
		addr := netip.AddrFrom4([4]byte{192, 0, 2, byte(point)})
		query, _ := flow.NewAddressSet(flow.AddressRange{First: addr, Last: addr})
		got, err := index.Candidates(t.Context(), query, 128)
		if err != nil {
			t.Fatal(err)
		}
		found := make(map[fm.ID]bool)
		for _, candidate := range got {
			found[candidate.ID] = true
		}
		for _, record := range data.Addresses {
			r := record.Ranges[0]
			want := r.First.Compare(addr) <= 0 && addr.Compare(r.Last) <= 0
			if found[record.ID] != want {
				t.Fatal("interval pruning changed candidate membership", addr, record.ID, found[record.ID], want)
			}
		}
	}
}

func TestCacheSharesIndexAndAccountsItsRetainedRanges(t *testing.T) {
	fw := cacheGraph(t, "lab", "synthetic")
	for _, test := range []struct {
		name     string
		limit    int
		retained bool
	}{
		{"retained", fw.DeclarationSize() + 1, true},
		{"graph only", fw.DeclarationSize(), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			var loads atomic.Int64
			source := &cacheSource{load: func(context.Context, string) (*fm.Firewall, error) { loads.Add(1); return fw, nil }}
			cache, err := inventory.NewCache(source, inventory.CacheLimits{MaxDeclarations: test.limit})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := cache.Load(t.Context(), strings.Repeat("a", 64)); err != nil {
				t.Fatal(err)
			}
			one, err := cache.Index(t.Context(), strings.Repeat("a", 64), fw)
			if err != nil {
				t.Fatal(err)
			}
			two, err := cache.Index(t.Context(), strings.Repeat("a", 64), fw)
			if err != nil || (one == two) != test.retained || loads.Load() != 1 {
				t.Fatal("derived index retention ignored its structural cost", one == two, loads.Load(), err)
			}
			got, err := one.Candidates(t.Context(), indexSet("192.0.2.10/32"), 1)
			if err != nil || len(got) != 1 {
				t.Fatal("uncached index was unusable", got, err)
			}
		})
	}

	var loads atomic.Int64
	source := &cacheSource{load: func(context.Context, string) (*fm.Firewall, error) { loads.Add(1); return fw, nil }}
	cache, err := inventory.NewCache(source, inventory.CacheLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cache.Load(t.Context(), strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan *inventory.Index, 32)
	for range 32 {
		wg.Go(func() {
			index, err := cache.Index(t.Context(), strings.Repeat("a", 64), fw)
			if err != nil {
				t.Error(err)
			}
			results <- index
		})
	}
	wg.Wait()
	close(results)
	var first *inventory.Index
	for result := range results {
		if first == nil {
			first = result
		}
		if result == nil || result != first {
			t.Fatal("concurrent callers did not share one immutable index")
		}
	}
	if loads.Load() != 1 {
		t.Fatal("concurrent index readers reloaded the graph", loads.Load())
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if index, err := cache.Index(ctx, strings.Repeat("a", 64), fw); index != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("cached index bypassed cancellation", index, err)
	}
	if index, err := cache.Index(t.Context(), strings.Repeat("a", 64), fw); index != first || err != nil {
		t.Fatal("canceled reader evicted the immutable index", index, err)
	}

	limited, err := inventory.NewCache(source, inventory.CacheLimits{MaxDeclarations: 1})
	if err != nil {
		t.Fatal(err)
	}
	if index, err := limited.Index(t.Context(), strings.Repeat("a", 64), fw); index != nil || !errors.Is(err, snapshot.ErrLimit) {
		t.Fatal("oversized index build bypassed preflight", index, err)
	}
	if loaded, err := limited.Load(t.Context(), strings.Repeat("a", 64)); loaded != fw || err != nil {
		t.Fatal("index build limit prohibited a valid graph load", loaded, err)
	}
}

func TestCacheEvictsGraphAndIndexTogether(t *testing.T) {
	fw := cacheGraph(t, "lab", "synthetic")
	loads := make(map[string]int)
	source := &cacheSource{load: func(_ context.Context, revision string) (*fm.Firewall, error) {
		loads[revision]++
		return fw, nil
	}}
	// Two graphs fit; adding each graph's address index requires an eviction.
	cache, err := inventory.NewCache(source, inventory.CacheLimits{MaxDeclarations: 2 * fw.DeclarationSize()})
	if err != nil {
		t.Fatal(err)
	}
	revisionA, revisionB := strings.Repeat("a", 64), strings.Repeat("b", 64)
	if _, err := cache.Load(t.Context(), revisionA); err != nil {
		t.Fatal(err)
	}
	first, err := cache.Index(t.Context(), revisionA, fw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cache.Load(t.Context(), revisionB); err != nil {
		t.Fatal(err)
	}
	if _, err := cache.Index(t.Context(), revisionB, fw); err != nil {
		t.Fatal(err)
	}
	if _, err := cache.Load(t.Context(), revisionA); err != nil {
		t.Fatal(err)
	}
	reloaded, err := cache.Index(t.Context(), revisionA, fw)
	if err != nil || reloaded == first || loads[revisionA] != 2 || loads[revisionB] != 1 {
		t.Fatal("derived index escaped its graph's retention budget", err, loads)
	}
	if got, err := first.Candidates(t.Context(), indexSet("192.0.2.10/32"), 1); len(got) != 1 || err != nil {
		t.Fatal("eviction invalidated an index held by an in-flight caller", got, err)
	}
}
