package policy_test

import (
	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/policy"
	"testing"
	"time"
)

func TestSameContextUsesDefaultChainAndTimeInstant(t *testing.T) {
	now := time.Now()
	a := policy.Request{At: now, Scope: "vdom", FromZone: "a", ToZone: "b", EgressInterface: "out"}
	b := a
	b.RuleSet = "security"
	b.At = now.In(time.FixedZone("test", 3600))
	if !a.SameContext(b) || !b.SameContext(a) {
		t.Fatal("equivalent context differs")
	}
	for _, change := range []func(*policy.Request){func(r *policy.Request) { r.Scope = "other" }, func(r *policy.Request) { r.RuleSet = "acl" }, func(r *policy.Request) { r.FromZone = "c" }, func(r *policy.Request) { r.ToZone = "c" }, func(r *policy.Request) { r.EgressInterface = "other" }, func(r *policy.Request) { r.At = r.At.Add(time.Second) }} {
		c := b
		change(&c)
		if a.SameContext(c) {
			t.Fatal("distinct context collapsed")
		}
	}
}

func TestNativeOrderingUsesNamedChainBoundaries(t *testing.T) {
	r := fm.RuleRecord{Object: fm.Object{Scope: "vr"}, RuleSet: "security", Match: fm.Match{FromZones: []fm.ID{"a"}, ToZones: []fm.ID{"b"}}}
	for _, vendor := range []string{"srx", "netscreen"} {
		order := policy.NativeRuleOrder(vendor, r)
		if order.Chain.PolicyChain != r.Chain() || order.Chain.FromZone != "a" || order.Chain.ToZone != "b" || order.Terminal {
			t.Fatal(order)
		}
	}
	order := policy.NativeRuleOrder("paloalto", r)
	if order.Chain.FromZone != "" || order.Chain.ToZone != "" {
		t.Fatal("linear chain split by zones")
	}
	r.Builtin = true
	r.Match.AnyFromZone = true
	r.Match.AnyToZone = true
	if !policy.NativeRuleOrder("srx", r).Terminal {
		t.Fatal("default lost terminal order")
	}
}
