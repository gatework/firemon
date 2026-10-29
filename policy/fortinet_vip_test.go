package policy_test

import (
	"context"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/policy"
)

func TestFortinetOrdinaryAddressInVIPNamedScopeRemainsOrdinary(t *testing.T) {
	q := policy.Request{Scope: "vip", Traffic: traffic(t, "192.0.2.1/32", "198.51.100.1/32")}
	m := anyMatch()
	m.AnyDestination = false
	m.Destinations = []fm.AddressRef{{Kind: fm.AddressObject, ID: "vip:ordinary"}}
	d := fm.Data{
		Metadata:  fm.Metadata{Device: "synthetic", Vendor: "fortinet", Context: "vip"},
		Addresses: []fm.AddressRecord{{Object: fm.Object{ID: "vip:ordinary", Name: "vip", Scope: "vip"}, Ranges: []flow.AddressRange{q.Traffic.Regions()[0].Destination}}},
		Rules:     []fm.RuleRecord{{Object: fm.Object{ID: "allow", Scope: "vip"}, Match: m, Action: fm.Permit, RuleSet: "security"}},
	}
	fw, err := fm.Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	if _, known, err := (policy.Engine{}).ResolveAddresses(context.Background(), fw, m.Destinations, false); err != nil || !known {
		t.Fatal("ordinary address classified as VIP by scope or ID")
	}
	got, err := (policy.Engine{}).Query(context.Background(), fw, q)
	if err != nil || !got.Complete || got.Allowed.Empty() {
		t.Fatal("ordinary address did not permit its declared destination", got, err)
	}
}

func TestFortinetInvalidExplicitVIPDoesNotBecomeOrdinaryCoverage(t *testing.T) {
	for _, tc := range []struct {
		name string
		ref  fm.NATRef
	}{
		{"missing", fm.NATRef{Kind: fm.StaticNATObject, ID: "missing"}},
		{"wrong-kind", fm.NATRef{Kind: fm.AddressObject, ID: "ordinary"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q := policy.Request{Scope: "root", Traffic: traffic(t, "192.0.2.1/32", "198.51.100.1/32")}
			m := anyMatch()
			m.AnyDestination = false
			m.Destinations = []fm.AddressRef{{Kind: fm.AddressObject, ID: "ordinary"}}
			d := fm.Data{
				Metadata:  fm.Metadata{Device: "synthetic", Vendor: "fortinet", Context: "root"},
				Addresses: []fm.AddressRecord{{Object: fm.Object{ID: "ordinary", Scope: "root"}, Ranges: []flow.AddressRange{q.Traffic.Regions()[0].Destination}, VIP: tc.ref}},
				Rules:     []fm.RuleRecord{{Object: fm.Object{ID: "allow", Scope: "root"}, Match: m, Action: fm.Permit, RuleSet: "security"}},
			}
			fw, err := fm.Seal(d)
			if err != nil {
				t.Fatal(err)
			}
			if fw.Complete() {
				t.Fatal("unresolved VIP declared complete")
			}
			if _, known, err := (policy.Engine{}).ResolveAddresses(context.Background(), fw, m.Destinations, false); err != nil || known {
				t.Fatal("invalid VIP flattened to address coverage")
			}
			got, err := (policy.Engine{}).Query(context.Background(), fw, q)
			if err != nil || got.Complete || got.Unknown.Empty() || !got.Allowed.Empty() {
				t.Fatal("invalid VIP permitted as an ordinary address", got, err)
			}
		})
	}
}
