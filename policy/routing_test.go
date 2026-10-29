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
	addresses, _ := flow.NewSet(rangeOf("192.0.2.0/24"))
	paths, err := (policy.Engine{Limits: policy.Limits{MaxRegions: 64}}).ResolveRoutes(context.Background(), fw, "vr", addresses)
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 2 || paths[0].Zone.Record().ID != "b" || paths[0].Addresses.Ranges()[0] != rangeOf("192.0.2.128/25") || paths[1].Addresses.Ranges()[0] != rangeOf("192.0.2.0/25") {
		t.Fatal(paths)
	}
}
func TestPANPacketUsesOriginalDestinationWithPostDNATZone(t *testing.T) {
	d := fm.Data{Metadata: fm.Metadata{Device: "pan", Vendor: "paloalto"}, Zones: []fm.ZoneRecord{{Object: fm.Object{ID: "outside"}}, {Object: fm.Object{ID: "inside"}}}, Interfaces: []fm.InterfaceRecord{{Object: fm.Object{ID: "out", Scope: "vr"}, Zone: "outside"}, {Object: fm.Object{ID: "in", Scope: "vr"}, Zone: "inside"}}, Routes: []fm.RouteRecord{{Object: fm.Object{ID: "default", Scope: "vr"}, Destination: netip.MustParsePrefix("0.0.0.0/0"), Interface: "out"}, {Object: fm.Object{ID: "internal", Scope: "vr"}, Destination: netip.MustParsePrefix("10.0.0.0/24"), Interface: "in"}}, Addresses: []fm.AddressRecord{{Object: fm.Object{ID: "public"}, Ranges: []flow.Range{rangeOf("203.0.113.10/32")}}}}
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
