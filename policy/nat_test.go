package policy_test

import (
	"context"
	"net/netip"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/policy"
)

func rangeOf(s string) flow.AddressRange {
	r, _ := flow.PrefixRange(netip.MustParsePrefix(s))
	return r
}
func TestStaticNATTranslatesOnlyMatchedSubnetWithOffset(t *testing.T) {
	d := fm.Data{Metadata: fm.Metadata{Device: "fw", Vendor: "hillstone"}, StaticNATs: []fm.StaticNATRecord{{Object: fm.Object{ID: "map"}, Match: anyMatch(), Source: []fm.Mapping{{Original: rangeOf("192.0.2.0/24"), Translated: rangeOf("203.0.113.0/24"), Mode: fm.Offset}}}}}
	fw, err := fm.Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	res, err := (policy.Engine{}).QueryNAT(context.Background(), fw, policy.Request{Traffic: traffic(t, "192.0.2.128/25", "198.51.100.1/32")})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Relations) != 1 || !res.Relations[0].Exact {
		t.Fatal(res)
	}
	boxes := res.Relations[0].Translated.Regions()
	if len(boxes) != 1 || boxes[0].Source != rangeOf("203.0.113.128/25") {
		t.Fatal("offset translated entire declared subnet", boxes)
	}
}
func TestNoNATConsumesBeforeDynamicAllocation(t *testing.T) {
	fw, err := fm.Seal(fm.Data{Metadata: fm.Metadata{Device: "fw", Vendor: "hillstone"}, NATPools: []fm.NATPoolRecord{{Object: fm.Object{ID: "pool"}, Ranges: []flow.AddressRange{rangeOf("203.0.113.0/29")}}}, DynamicNATs: []fm.DynamicNATRecord{
		{Object: fm.Object{ID: "exempt"}, Match: anyMatch(), Order: fm.NATOrder{Position: 0}, SourceMode: fm.NoTranslation, DestinationMode: fm.NoTranslation},
		{Object: fm.Object{ID: "pool"}, Match: anyMatch(), Order: fm.NATOrder{Position: 1}, SourceMode: fm.DynamicIPPort, DestinationMode: fm.NoTranslation, SourcePool: "pool"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	res, err := (policy.Engine{}).QueryNAT(context.Background(), fw, policy.Request{Traffic: traffic(t, "192.0.2.1/32", "198.51.100.1/32")})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Relations) != 1 || res.Relations[0].ID != "exempt" || !res.Relations[0].Exact {
		t.Fatal("exemption not terminal", res)
	}
	d := fw.Export()
	d.DynamicNATs = d.DynamicNATs[1:]
	fw, _ = fm.Seal(d)
	res, err = (policy.Engine{}).QueryNAT(context.Background(), fw, policy.Request{Traffic: traffic(t, "192.0.2.1/32", "198.51.100.1/32")})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Relations) != 1 || res.Relations[0].Exact || !res.Relations[0].PossibleAllocation {
		t.Fatal("pool invented exact session translation", res)
	}
}

func TestStaticMappingDoesNotConsumeAddressesOutsideItsOriginalDomain(t *testing.T) {
	fw, err := fm.Seal(fm.Data{Metadata: fm.Metadata{Device: "fw", Vendor: "hillstone"}, StaticNATs: []fm.StaticNATRecord{{Object: fm.Object{ID: "map"}, Match: anyMatch(), Source: []fm.Mapping{{Original: rangeOf("192.0.2.0/25"), Translated: rangeOf("203.0.113.0/25"), Mode: fm.Offset}}}}})
	if err != nil {
		t.Fatal(err)
	}
	res, err := (policy.Engine{}).QueryNAT(context.Background(), fw, policy.Request{Traffic: traffic(t, "192.0.2.0/24", "198.51.100.1/32")})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Relations) != 1 || !res.Unknown.Empty() || res.Unmatched.Empty() {
		t.Fatal("fixed mapping consumed outside original domain", res)
	}
}

func TestBidirectionalStaticReverseNeverReturnsCertainNoNAT(t *testing.T) {
	fw, err := fm.Seal(fm.Data{Metadata: fm.Metadata{Device: "fw", Vendor: "hillstone"}, StaticNATs: []fm.StaticNATRecord{{Object: fm.Object{ID: "bnat"}, Match: anyMatch(), Bidirectional: true, Source: []fm.Mapping{{Original: rangeOf("192.0.2.0/24"), Translated: rangeOf("203.0.113.0/24"), Mode: fm.Offset}}}}})
	if err != nil {
		t.Fatal(err)
	}
	result, err := (policy.Engine{}).QueryNAT(context.Background(), fw, policy.Request{Traffic: traffic(t, "198.51.100.1/32", "203.0.113.10/32")})
	if err == nil && result.Complete && result.Unknown.Empty() && len(result.Relations) == 0 {
		t.Fatal("reverse mapping reported as definite no NAT")
	}
}

func TestMixedHillstoneSourceAndDestinationChainsFailClosed(t *testing.T) {
	fw, err := fm.Seal(fm.Data{Metadata: fm.Metadata{Device: "fw", Vendor: "hillstone"}, NATPools: []fm.NATPoolRecord{{Object: fm.Object{ID: "pool"}, Ranges: []flow.AddressRange{rangeOf("203.0.113.1/32")}}}, DynamicNATs: []fm.DynamicNATRecord{
		{Object: fm.Object{ID: "snat"}, Match: anyMatch(), Order: fm.NATOrder{Position: 0}, SourceMode: fm.DynamicIPPort, DestinationMode: fm.NoTranslation, SourcePool: "pool"},
		{Object: fm.Object{ID: "dnat"}, Match: anyMatch(), Order: fm.NATOrder{Position: 1}, SourceMode: fm.NoTranslation, DestinationMode: fm.StaticIP, Destination: []fm.Mapping{{Original: rangeOf("198.51.100.1/32"), Translated: rangeOf("10.0.0.1/32"), Mode: fm.Constant}}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (policy.Engine{}).QueryNAT(context.Background(), fw, policy.Request{Traffic: traffic(t, "192.0.2.1/32", "198.51.100.1/32")}); err == nil {
		t.Fatal("unestablished mixed native pipeline treated as single first-match chain")
	}
}
