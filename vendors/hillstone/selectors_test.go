package hillstone_test

import (
	"net/netip"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/policy"
)

func TestInlineSelectorsAndReservedAnyPreserveExactTraffic(t *testing.T) {
	fw := parse(t, "policy-global\nrule id 1\nname web\nsrc-ip 192.0.2.0/25\nsrc-range 192.0.2.128 192.0.2.191\ndst-ip 198.51.100.1\nservice Any\naction deny\nexit\nrule id 2\nsrc-addr Any\ndst-addr Any\nservice Any\naction permit\nexit\nexit\n")
	if !fw.Complete() {
		t.Fatal(fw.Diagnostics())
	}
	for _, a := range fw.Addresses() {
		if !a.Record().Inline || a.Name() != "" {
			t.Fatal("inline value became a named declaration")
		}
	}
	src, _ := flow.PrefixRange(netip.MustParsePrefix("192.0.2.0/24"))
	dst, _ := flow.PrefixRange(netip.MustParsePrefix("198.51.100.1/32"))
	traffic, _ := flow.NewTraffic(32, flow.TrafficRegion{Source: src, Destination: dst, Protocol: flow.Interval{Low: 6, High: 6}, SourcePort: flow.Interval{Low: 1024, High: 65535}, DestinationPort: flow.Interval{Low: 443, High: 443}, ICMPType: flow.Interval{Low: 0, High: 255}, ICMPCode: flow.Interval{Low: 0, High: 255}})
	got, err := (policy.Engine{}).Query(t.Context(), fw, policy.Request{Traffic: traffic, RuleSet: "security"})
	if err != nil || !got.Unknown.Empty() || got.Allowed.Empty() || got.Denied.Empty() {
		t.Fatal("first match or wildcard lost", err)
	}
	if got.Denied.Regions()[0].Source.Last != netip.MustParseAddr("192.0.2.191") || got.Allowed.Regions()[0].Source.First != netip.MustParseAddr("192.0.2.192") {
		t.Fatal("inline traffic widened")
	}
	if fw.Rule("1").Name() != "web" || fw.Rule("1").ID() != fm.ID("1") {
		t.Fatal("policy label replaced numeric identity")
	}
}

func TestNATReservedAnyUsesTheSameSelectorSemantics(t *testing.T) {
	fw := parse(t, "ip vrouter blue\nsnatrule id 1 from Any to Any service Any trans-to 203.0.113.1 mode dynamicport\nexit\n")
	r := fw.DynamicNAT("blue/snat:1").Record()
	if !fw.Complete() || !r.Match.AnySource || !r.Match.AnyDestination || !r.Match.AnyService {
		t.Fatal("reserved wildcard became a missing NAT object", fw.Diagnostics())
	}
}
