package policy_test

import (
	"context"
	"errors"
	"net/netip"
	"runtime"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/policy"
)

func TestResolverSharesBudgetAndOwnsCachedTerms(t *testing.T) {
	term := fm.ServiceTerm{Protocol: flow.Interval{Low: 6, High: 6}, DestinationPort: flow.Interval{Low: 443, High: 443}}
	fw, err := fm.Seal(fm.Data{Metadata: fm.Metadata{Device: "resolver", Vendor: "hillstone"}, Services: []fm.ServiceRecord{{Object: fm.Object{ID: "https"}, Terms: []fm.ServiceTerm{term}}}, ServiceGroups: []fm.ServiceGroupRecord{{Object: fm.Object{ID: "web"}, Members: []fm.ServiceRef{{Kind: fm.ServiceObject, ID: "https"}}}}})
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := policy.NewResolver(fw, policy.Limits{MaxVisits: 7, MaxCombinations: 3})
	if err != nil {
		t.Fatal(err)
	}
	refs := []fm.ServiceRef{{Kind: fm.ServiceGroupObject, ID: "web"}}
	first, known, err := resolver.Services(t.Context(), refs, false)
	if err != nil || !known || resolver.Visits() != 3 {
		t.Fatal(known, err, resolver.Visits())
	}
	first[0].Protocol = flow.Interval{}
	second, known, err := resolver.Services(t.Context(), refs, false)
	if err != nil || !known || second[0] != term || resolver.Visits() != 6 {
		t.Fatal("cache escaped or bypassed budget", err)
	}
	partial, known, err := resolver.Services(t.Context(), refs, false)
	if !errors.Is(err, policy.ErrBudget) || known || partial != nil {
		t.Fatal("partial resolution on exhausted shared budget", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, _, err := resolver.Services(ctx, refs, false); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestResolverRestrictsRemainingVisitsBeforeExpansionOrCache(t *testing.T) {
	term := fm.ServiceTerm{Protocol: flow.Interval{Low: 6, High: 6}, DestinationPort: flow.Interval{Low: 443, High: 443}}
	fw, err := fm.Seal(fm.Data{Metadata: fm.Metadata{Device: "resolver", Vendor: "hillstone"}, Services: []fm.ServiceRecord{{Object: fm.Object{ID: "https"}, Terms: []fm.ServiceTerm{term}}}})
	if err != nil {
		t.Fatal(err)
	}
	refs := []fm.ServiceRef{{Kind: fm.ServiceObject, ID: "https"}}
	for _, name := range []string{"cold", "cached"} {
		t.Run(name, func(t *testing.T) {
			resolver, err := policy.NewResolver(fw, policy.Limits{MaxVisits: 100})
			if err != nil {
				t.Fatal(err)
			}
			if name == "cached" {
				if _, known, err := resolver.Services(t.Context(), refs, false); err != nil || !known {
					t.Fatal(known, err)
				}
			}
			if err := resolver.RestrictVisits(2); err != nil {
				t.Fatal(err)
			}
			// A later larger allowance must not restore the cap.
			if err := resolver.RestrictVisits(100); err != nil {
				t.Fatal(err)
			}
			got, known, err := resolver.Services(t.Context(), refs, false)
			if err != nil || !known || len(got) != 1 || got[0] != term {
				t.Fatalf("bounded small query rejected: %v %v", known, err)
			}
			spent := resolver.Visits()
			got, known, err = resolver.Services(t.Context(), refs, false)
			if !errors.Is(err, policy.ErrBudget) || got != nil || known || resolver.Visits() != spent {
				t.Fatalf("exhausted allowance performed more work: %v %v", known, err)
			}
		})
	}
	resolver, err := policy.NewResolver(fw, policy.Limits{MaxVisits: 100})
	if err != nil {
		t.Fatal(err)
	}
	if err := resolver.RestrictVisits(-1); !errors.Is(err, policy.ErrInvalid) {
		t.Fatal("negative remaining allowance", err)
	}
	if err := resolver.RestrictVisits(0); err != nil {
		t.Fatal(err)
	}
	if got, known, err := resolver.Services(t.Context(), refs, false); !errors.Is(err, policy.ErrBudget) || got != nil || known || resolver.Visits() != 0 {
		t.Fatal("externally exhausted allowance was ignored", known, err)
	}
}

func TestResolverBudgetsLargeDeclarationsBeforeCopying(t *testing.T) {
	const count = 1 << 16
	term := fm.ServiceTerm{Protocol: flow.Interval{Low: 6, High: 6}, DestinationPort: flow.Interval{Low: 443, High: 443}}
	address := fm.AddressRef{Kind: fm.AddressObject, ID: "small-address"}
	service := fm.ServiceRef{Kind: fm.ServiceObject, ID: "small-service"}
	ranges := make([]flow.AddressRange, count)
	terms := make([]fm.ServiceTerm, count)
	addresses := make([]fm.AddressRef, count)
	services := make([]fm.ServiceRef, count)
	for i := range count {
		// Nonadjacent addresses keep the normalized range declaration large.
		n := i * 2
		ip := netip.AddrFrom4([4]byte{198, 18 + byte(n>>16), byte(n >> 8), byte(n)})
		ranges[i] = flow.AddressRange{First: ip, Last: ip}
		terms[i], addresses[i], services[i] = term, address, service
	}
	fw, err := fm.Seal(fm.Data{
		Metadata: fm.Metadata{Device: "resolver-budget", Vendor: "hillstone"},
		Addresses: []fm.AddressRecord{
			{Object: fm.Object{ID: address.ID}, Ranges: ranges[:1]},
			{Object: fm.Object{ID: "large-address"}, Ranges: ranges},
		},
		Services: []fm.ServiceRecord{
			{Object: fm.Object{ID: service.ID}, Terms: []fm.ServiceTerm{term}},
			{Object: fm.Object{ID: "large-service"}, Terms: terms},
		},
		AddressGroups: []fm.AddressGroupRecord{{Object: fm.Object{ID: "large-address-group"}, Members: addresses}},
		ServiceGroups: []fm.ServiceGroupRecord{{Object: fm.Object{ID: "large-service-group"}, Members: services}},
	})
	if err != nil || !fw.Complete() {
		t.Fatalf("fixture: complete=%v err=%v", fw != nil && fw.Complete(), err)
	}
	for _, tc := range []struct {
		name      string
		addresses []fm.AddressRef
		services  []fm.ServiceRef
	}{
		{name: "address ranges", addresses: []fm.AddressRef{{Kind: fm.AddressObject, ID: "large-address"}}},
		{name: "address members", addresses: []fm.AddressRef{{Kind: fm.AddressGroupObject, ID: "large-address-group"}}},
		{name: "service terms", services: []fm.ServiceRef{{Kind: fm.ServiceObject, ID: "large-service"}}},
		{name: "service members", services: []fm.ServiceRef{{Kind: fm.ServiceGroupObject, ID: "large-service-group"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resolver, err := policy.NewResolver(fw, policy.Limits{MaxVisits: 1, MaxCombinations: 1})
			if err != nil {
				t.Fatal(err)
			}
			// This test stays serial: process allocation counters must exclude
			// other test work, including construction of the immutable graph.
			var start, end runtime.MemStats
			var size int
			var known bool
			runtime.ReadMemStats(&start)
			if tc.addresses != nil {
				var set flow.AddressSet
				set, known, err = resolver.Addresses(t.Context(), tc.addresses, false)
				size = set.RangeCount()
			} else {
				var result []fm.ServiceTerm
				result, known, err = resolver.Services(t.Context(), tc.services, false)
				size = len(result)
			}
			runtime.ReadMemStats(&end)
			if !errors.Is(err, policy.ErrBudget) || known || size != 0 || resolver.Visits() != 1 {
				t.Fatalf("budget error returned partial data: size=%d known=%v visits=%d err=%v", size, known, resolver.Visits(), err)
			}
			if allocated := end.TotalAlloc - start.TotalAlloc; allocated > 64<<10 {
				t.Fatalf("declaration copied before budget check: %d bytes", allocated)
			}
		})
	}
	// An unrelated large declaration must not consume a small query's budget.
	resolver, err := policy.NewResolver(fw, policy.Limits{MaxVisits: count, MaxCombinations: 2})
	if err != nil {
		t.Fatal(err)
	}
	if err := resolver.RestrictVisits(4); err != nil {
		t.Fatal(err)
	}
	set, known, err := resolver.Addresses(t.Context(), []fm.AddressRef{address}, false)
	if err != nil || !known || set.RangeCount() != 1 || set.Ranges()[0] != ranges[0] {
		t.Fatalf("unrelated ranges blocked query: %v %v", known, err)
	}
	got, known, err := resolver.Services(t.Context(), []fm.ServiceRef{service}, false)
	if err != nil || !known || len(got) != 1 || got[0] != term || resolver.Visits() != 4 {
		t.Fatalf("unrelated service declaration blocked query: %v %v", known, err)
	}
}
