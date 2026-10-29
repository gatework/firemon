package policy

import (
	"context"
	"errors"
	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"net/netip"
	"testing"
)

func TestResolutionReusePreservesBudgetAndGraphIsolation(t *testing.T) {
	ip := netip.MustParseAddr("192.0.2.1")
	d := fm.Data{Metadata: fm.Metadata{Device: "test", Vendor: "huawei"}, Addresses: []fm.AddressRecord{{Object: fm.Object{ID: "a"}, Ranges: []flow.Range{{First: ip, Last: ip}}}}}
	fw, err := fm.Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	c := &resolutionCache{firewall: fw, remaining: 4}
	refs := []fm.AddressRef{{Kind: fm.AddressObject, ID: "a"}}
	for range 2 {
		budget := &resolutionBudget{ctx: context.Background(), limit: 2, cache: c}
		got, known, err := resolveAddresses(fw, refs, false, budget)
		if err != nil || !known || !got.ContainsAddr(ip) || budget.spent != 2 {
			t.Fatalf("%v %v spent=%d", known, err, budget.spent)
		}
	}
	if c.remaining != 2 {
		t.Fatal("cached expansion charged storage twice")
	}
	if _, _, err := resolveAddresses(fw, refs, false, &resolutionBudget{ctx: context.Background(), limit: 1, cache: c}); !errors.Is(err, ErrBudget) {
		t.Fatal("cache bypassed budget", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := resolveAddresses(fw, refs, false, &resolutionBudget{ctx: ctx, limit: 2, cache: c}); !errors.Is(err, context.Canceled) {
		t.Fatal("cache bypassed cancellation", err)
	}
	d.Addresses = nil
	other, err := fm.Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	if _, known, err := resolveAddresses(other, refs, false, &resolutionBudget{ctx: context.Background(), limit: 2, cache: c}); err != nil || known {
		t.Fatal("cache crossed graph boundary", known, err)
	}
	// A missing reference with zero-valued identity differs from no references.
	if _, known, err := resolveAddresses(fw, []fm.AddressRef{{}}, false, &resolutionBudget{ctx: context.Background(), limit: 2, cache: c}); err != nil || known {
		t.Fatal(known, err)
	}
	if got, known, err := resolveAddresses(fw, nil, false, &resolutionBudget{ctx: context.Background(), limit: 2, cache: c}); err != nil || !known || len(got.Ranges()) != 0 {
		t.Fatal("empty key collision", known, err)
	}
}
