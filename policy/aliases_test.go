package policy_test

import (
	"context"
	"errors"
	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/policy"
	"github.com/gatework/firemon/vendors"
	"testing"
)

const aliasSRXBase = "set interfaces ge-0/0/0 unit 0 family inet address 192.0.2.1/24\nset interfaces ge-0/0/1 unit 0 family inet address 203.0.113.1/24\nset security zones security-zone inside interfaces ge-0/0/0.0\nset security zones security-zone outside interfaces ge-0/0/1.0\nset security nat static rule-set public from zone outside\n"

func aliasSRXRule(name, public, real string) string {
	return "set security nat static rule-set public rule " + name + " match destination-address " + public + "\nset security nat static rule-set public rule " + name + " then static-nat prefix " + real + "\n"
}
func aliasSRX(t *testing.T, rules string) *fm.Firewall {
	t.Helper()
	fw, err := (vendors.Parser{}).Parse(t.Context(), config.Source{Text: aliasSRXBase + rules, Complete: true}, fm.Metadata{Device: "srx", Vendor: "srx"})
	if err != nil || !fw.Complete() {
		t.Fatal(fw, err)
	}
	return fw
}
func TestStaticAliasesRealOffsetAndRemainder(t *testing.T) {
	fw := aliasSRX(t, aliasSRXRule("one", "203.0.113.0/25", "192.0.2.0/25"))
	q := policy.PacketRequest{Request: policy.Request{Traffic: traffic(t, "198.51.100.1/32", "192.0.2.0/24"), FromZone: "outside"}}
	result, err := (policy.Engine{}).DiscoverStaticAliases(t.Context(), fw, q, policy.RealView)
	if err != nil || len(result.Candidates) != 1 || !result.Ambiguous.Empty() || result.Unmatched.Regions()[0].Destination != rangeOf("192.0.2.128/25") {
		t.Fatal(result, err)
	}
	c := result.Candidates[0]
	if c.Business.Regions()[0].Destination != rangeOf("192.0.2.0/25") || c.Wire.Regions()[0].Destination != rangeOf("203.0.113.0/25") {
		t.Fatal(c)
	}
}
func TestStaticAliasesPreserveAmbiguityAndSafeFraction(t *testing.T) {
	fw := aliasSRX(t, aliasSRXRule("one", "203.0.113.0/24", "192.0.2.0/24")+aliasSRXRule("two", "198.51.100.128/25", "192.0.2.128/25"))
	q := policy.PacketRequest{Request: policy.Request{Traffic: traffic(t, "198.51.100.1/32", "192.0.2.0/24"), FromZone: "outside"}}
	result, err := (policy.Engine{}).DiscoverStaticAliases(t.Context(), fw, q, policy.RealView)
	if err != nil || len(result.Candidates) != 1 || result.Candidates[0].Business.Regions()[0].Destination != rangeOf("192.0.2.0/25") || result.Ambiguous.Regions()[0].Destination != rangeOf("192.0.2.128/25") || !result.Unmatched.Empty() {
		t.Fatal(result, err)
	}
}
func TestStaticAliasesRejectEarlierNativeShadowWithoutLosingSibling(t *testing.T) {
	fw := aliasSRX(t, "set routing-options static route 10.0.0.0/24 next-hop 192.0.2.254\n"+aliasSRXRule("earlier", "203.0.113.0/25", "10.0.0.0/25")+aliasSRXRule("later", "203.0.113.0/24", "192.0.2.0/24"))
	q := policy.PacketRequest{Request: policy.Request{Traffic: traffic(t, "198.51.100.1/32", "192.0.2.0/24"), FromZone: "outside"}}
	result, err := (policy.Engine{}).DiscoverStaticAliases(t.Context(), fw, q, policy.RealView)
	if err != nil || len(result.Candidates) != 1 || result.Candidates[0].Business.Regions()[0].Destination != rangeOf("192.0.2.128/25") || result.Unmatched.Regions()[0].Destination != rangeOf("192.0.2.0/25") {
		t.Fatal(result, err)
	}
}

func TestStaticAliasesSameObjectAlternativesRemainAmbiguous(t *testing.T) {
	fw := aliasSRX(t, aliasSRXRule("one", "203.0.113.0/24", "192.0.2.0/24"))
	data := fw.Export()
	data.StaticNATs[0].Destination = append(data.StaticNATs[0].Destination, fm.Mapping{Original: rangeOf("198.51.100.128/25"), Translated: rangeOf("192.0.2.128/25"), Mode: fm.Offset})
	data.StaticNATs[0].Match.AnyDestination = true
	data.StaticNATs[0].Match.Destinations = nil
	fw, err := fm.Seal(data)
	if err != nil {
		t.Fatal(err)
	}
	result, err := (policy.Engine{}).DiscoverStaticAliases(t.Context(), fw, policy.PacketRequest{Request: policy.Request{Traffic: traffic(t, "198.51.100.1/32", "192.0.2.0/24"), FromZone: "outside"}}, policy.RealView)
	if err != nil || result.Ambiguous.Empty() || len(result.Candidates) != 1 || result.Candidates[0].Business.Regions()[0].Destination != rangeOf("192.0.2.0/25") {
		t.Fatal("one catalog object hid alternative aliases", result, err)
	}
}

func TestStaticAliasDiscoveryHonorsBudgetsAndCancellation(t *testing.T) {
	fw := aliasSRX(t, aliasSRXRule("one", "203.0.113.0/24", "192.0.2.0/24"))
	q := policy.PacketRequest{Request: policy.Request{Traffic: traffic(t, "198.51.100.1/32", "192.0.2.0/24"), FromZone: "outside"}}
	result, err := (policy.Engine{Limits: policy.Limits{MaxVisits: 1}}).DiscoverStaticAliases(t.Context(), fw, q, policy.RealView)
	if !errors.Is(err, policy.ErrBudget) || len(result.Candidates) != 0 {
		t.Fatal(result, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err = (policy.Engine{}).DiscoverStaticAliases(ctx, fw, q, policy.RealView)
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
