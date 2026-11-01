package policy_test

import (
	"context"
	"net/netip"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/policy"
)

func TestRoutePartitionsSplitRequestAtLongestPrefixBoundaries(t *testing.T) {
	fw, err := fm.Seal(fm.Data{Metadata: fm.Metadata{Device: "fw", Vendor: "paloalto"}, Zones: []fm.ZoneRecord{{Object: fm.Object{ID: "a"}}, {Object: fm.Object{ID: "b"}}}, Interfaces: []fm.InterfaceRecord{{Object: fm.Object{ID: "eth0", Scope: "vr"}, Zone: "a"}, {Object: fm.Object{ID: "eth1", Scope: "vr"}, Zone: "b"}}, Routes: []fm.RouteRecord{
		{Object: fm.Object{ID: "default", Scope: "vr"}, Destination: netip.MustParsePrefix("0.0.0.0/0"), Interface: "eth0"},
		{Object: fm.Object{ID: "specific", Scope: "vr"}, Destination: netip.MustParsePrefix("192.0.2.128/25"), Interface: "eth1"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	addresses, _ := flow.NewAddressSet(rangeOf("192.0.2.0/24"))
	paths, err := (policy.Engine{Limits: policy.Limits{MaxRegions: 64}}).ResolveRoutes(context.Background(), fw, "vr", addresses)
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 2 || paths[0].Zone.Record().ID != "b" || paths[0].Addresses.Ranges()[0] != rangeOf("192.0.2.128/25") || paths[1].Addresses.Ranges()[0] != rangeOf("192.0.2.0/25") {
		t.Fatal(paths)
	}
}
func TestPANPacketUsesOriginalDestinationWithPostDNATZone(t *testing.T) {
	d := fm.Data{Metadata: fm.Metadata{Device: "pan", Vendor: "paloalto"}, Zones: []fm.ZoneRecord{{Object: fm.Object{ID: "outside"}}, {Object: fm.Object{ID: "inside"}}}, Interfaces: []fm.InterfaceRecord{{Object: fm.Object{ID: "out", Scope: "vr"}, Zone: "outside"}, {Object: fm.Object{ID: "in", Scope: "vr"}, Zone: "inside"}}, Routes: []fm.RouteRecord{{Object: fm.Object{ID: "default", Scope: "vr"}, Destination: netip.MustParsePrefix("0.0.0.0/0"), Interface: "out"}, {Object: fm.Object{ID: "internal", Scope: "vr"}, Destination: netip.MustParsePrefix("10.0.0.0/24"), Interface: "in"}}, Addresses: []fm.AddressRecord{{Object: fm.Object{ID: "public"}, Ranges: []flow.AddressRange{rangeOf("203.0.113.10/32")}}}}
	natMatch := anyMatch()
	natMatch.AnyToZone = false
	natMatch.ToZones = []fm.ID{"outside"}
	natMatch.AnyDestination = false
	natMatch.Destinations = []fm.AddressRef{{Kind: fm.AddressObject, ID: "public"}}
	d.DynamicNATs = []fm.DynamicNATRecord{{Object: fm.Object{ID: "publish"}, Match: natMatch, SourceMode: fm.NoTranslation, DestinationMode: fm.StaticIP, Destination: []fm.Mapping{{Original: rangeOf("203.0.113.10/32"), Translated: rangeOf("10.0.0.10/32"), Mode: fm.Constant}}}}
	security := natMatch
	security.ToZones = []fm.ID{"inside"}
	d.Rules = []fm.RuleRecord{{Object: fm.Object{ID: "permit-public"}, RuleSet: "security", Action: fm.Permit, Match: security}}
	fw, err := fm.Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	result, err := (policy.Engine{}).QueryPacket(context.Background(), fw, policy.PacketRequest{Request: policy.Request{Traffic: traffic(t, "198.51.100.1/32", "203.0.113.10/32"), FromZone: "outside"}, VRF: "vr"})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Paths) == 1 {
		native := result.Paths[0].NativeRequests
		if len(native) != 1 || native[0].EgressInterface != "in" || native[0].ToZone != "inside" || native[0].Traffic.Regions()[0].Destination != rangeOf("203.0.113.10/32") {
			t.Fatal("native request lost original PAN destination", native)
		}
	}
	if !result.Complete || len(result.Paths) != 1 || result.Paths[0].ToZone != "inside" || result.Paths[0].Policy.Allowed.Empty() {
		t.Fatal("wrong PAN packet perspective", result)
	}
}

func TestDisabledOrUnsupportedEgressCannotAuthorizePacketPath(t *testing.T) {
	for _, tc := range []struct {
		name        string
		disabled    bool
		unsupported []string
	}{{"disabled", true, nil}, {"unsupported", false, []string{"unknown forwarding mode"}}} {
		t.Run(tc.name, func(t *testing.T) {
			d := fm.Data{Metadata: fm.Metadata{Device: "pan", Vendor: "paloalto"}, Zones: []fm.ZoneRecord{{Object: fm.Object{ID: "outside"}}}, Interfaces: []fm.InterfaceRecord{{Object: fm.Object{ID: "out", Scope: "vr", Unsupported: tc.unsupported}, Zone: "outside", Disabled: tc.disabled}}, Routes: []fm.RouteRecord{{Object: fm.Object{ID: "default", Scope: "vr"}, Destination: netip.MustParsePrefix("0.0.0.0/0"), Interface: "out"}}, Rules: []fm.RuleRecord{{Object: fm.Object{ID: "allow"}, RuleSet: "security", Action: fm.Permit, Match: anyMatch()}}}
			fw, err := fm.Seal(d)
			if err != nil {
				t.Fatal(err)
			}
			result, err := (policy.Engine{}).QueryPacket(context.Background(), fw, policy.PacketRequest{Request: policy.Request{Traffic: traffic(t, "198.51.100.1/32", "203.0.113.10/32"), FromZone: "outside"}, VRF: "vr"})
			if err != nil {
				t.Fatal(err)
			}
			if result.Complete || result.Unknown.Empty() || len(result.Paths) != 0 {
				t.Fatal("unusable egress authorized traffic", result)
			}
		})
	}
}

func TestPANOffsetDNATRoutePartitionsKeepExactRelations(t *testing.T) {
	d := fm.Data{Metadata: fm.Metadata{Device: "pan", Vendor: "paloalto"}, Zones: []fm.ZoneRecord{{Object: fm.Object{ID: "outside"}}, {Object: fm.Object{ID: "left"}}, {Object: fm.Object{ID: "right"}}}, Interfaces: []fm.InterfaceRecord{{Object: fm.Object{ID: "out", Scope: "vr"}, Zone: "outside"}, {Object: fm.Object{ID: "l", Scope: "vr"}, Zone: "left"}, {Object: fm.Object{ID: "r", Scope: "vr"}, Zone: "right"}}, Routes: []fm.RouteRecord{{Object: fm.Object{ID: "default", Scope: "vr"}, Destination: netip.MustParsePrefix("0.0.0.0/0"), Interface: "out"}, {Object: fm.Object{ID: "left", Scope: "vr"}, Destination: netip.MustParsePrefix("10.0.0.0/25"), Interface: "l"}, {Object: fm.Object{ID: "right", Scope: "vr"}, Destination: netip.MustParsePrefix("10.0.0.128/25"), Interface: "r"}}, Addresses: []fm.AddressRecord{{Object: fm.Object{ID: "public"}, Ranges: []flow.AddressRange{rangeOf("203.0.113.0/24")}}}}
	match := anyMatch()
	match.AnyDestination = false
	match.Destinations = []fm.AddressRef{{Kind: fm.AddressObject, ID: "public"}}
	d.DynamicNATs = []fm.DynamicNATRecord{{Object: fm.Object{ID: "publish"}, Match: match, SourceMode: fm.NoTranslation, DestinationMode: fm.StaticIP, Destination: []fm.Mapping{{Original: rangeOf("203.0.113.0/24"), Translated: rangeOf("10.0.0.0/24"), Mode: fm.Offset}}}}
	fw, err := fm.Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	result, err := (policy.Engine{}).QueryPacket(t.Context(), fw, policy.PacketRequest{Request: policy.Request{Traffic: traffic(t, "198.51.100.1/32", "203.0.113.0/24"), FromZone: "outside"}, VRF: "vr"})
	if err != nil || !result.Complete || len(result.Paths) != 2 {
		t.Fatal(result, err)
	}
	for _, path := range result.Paths {
		public, real := "203.0.113.0/25", "10.0.0.0/25"
		if path.ToZone == "right" {
			public, real = "203.0.113.128/25", "10.0.0.128/25"
		}
		if len(path.NAT.Original.Regions()) != 1 || path.NAT.Original.Regions()[0].Destination != rangeOf(public) || path.NAT.Translated.Regions()[0].Destination != rangeOf(real) || len(path.NAT.Steps) != 1 || !path.NAT.Exact || path.NAT.PossibleAllocation {
			t.Fatal("parent NAT relation leaked into partition", path)
		}
	}
}
