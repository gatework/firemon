package policy_test

import (
	"errors"
	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/policy"
	"net/netip"
	"testing"
)

func stonePacketData() fm.Data {
	d := fm.Data{Metadata: fm.Metadata{Device: "synthetic", Vendor: "hillstone", Software: "5.5R8"}}
	for _, z := range []fm.ID{"outside", "left", "right"} {
		d.Zones = append(d.Zones, fm.ZoneRecord{Object: fm.Object{ID: z, Scope: "vr"}})
		d.Interfaces = append(d.Interfaces, fm.InterfaceRecord{Object: fm.Object{ID: z, Scope: "vr"}, Zone: z, Addresses: []netip.Prefix{netip.MustParsePrefix("198.51.100.1/24")}})
	}
	d.Routes = []fm.RouteRecord{{Object: fm.Object{ID: "l", Scope: "vr"}, Destination: netip.MustParsePrefix("10.0.0.0/25"), Interface: "left"}, {Object: fm.Object{ID: "r", Scope: "vr"}, Destination: netip.MustParsePrefix("10.0.0.128/25"), Interface: "right"}}
	d.StaticNATs = []fm.StaticNATRecord{{Object: fm.Object{ID: "bnat", Scope: "vr"}, Match: anyMatch(), Order: fm.NATOrder{Section: "bnat"}, Bidirectional: true, Source: []fm.Mapping{{Original: rangeOf("10.0.0.0/24"), Translated: rangeOf("203.0.113.0/24"), Mode: fm.Offset}}}}
	d.Rules = []fm.RuleRecord{{Object: fm.Object{ID: "allow", Scope: "vr"}, RuleSet: "security", Match: anyMatch(), Action: fm.Permit}}
	return d
}
func TestStoneOS55R8PacketOriginalPolicyPostDNATRoutes(t *testing.T) {
	d := stonePacketData()
	d.NATPools = []fm.NATPoolRecord{{Object: fm.Object{ID: "pool", Scope: "vr"}, Ranges: []flow.AddressRange{rangeOf("192.0.2.10/32")}}}
	d.DynamicNATs = []fm.DynamicNATRecord{{Object: fm.Object{ID: "pat", Scope: "vr"}, Match: anyMatch(), Order: fm.NATOrder{Stage: 2, Section: "snat"}, SourceMode: fm.DynamicIPPort, DestinationMode: fm.NoTranslation, SourcePool: "pool", Interface: "left"}}
	fw, err := fm.Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	q := policy.PacketRequest{Request: policy.Request{Traffic: traffic(t, "198.51.100.20/32", "203.0.113.0/24"), Scope: "vr", FromZone: "outside"}, VRF: "vr"}
	got, err := (policy.Engine{}).QueryPacket(t.Context(), fw, q)
	if err != nil || !got.Complete || len(got.Paths) != 2 {
		t.Fatal(got, err)
	}
	for _, p := range got.Paths {
		public, real := "203.0.113.0/25", "10.0.0.0/25"
		if p.ToZone == "right" {
			public, real = "203.0.113.128/25", "10.0.0.128/25"
		}
		if p.Original.Regions()[0].Destination != rangeOf(public) || p.Real.Regions()[0].Destination != rangeOf(real) || p.Real.Regions()[0].Source != rangeOf("198.51.100.20/32") || len(p.NativeRequests) != 1 || !sameTraffic(t, p.NativeRequests[0].Traffic, p.Original) || !sameTraffic(t, p.Policy.Allowed, p.Original) {
			t.Fatal("native coordinates or route partition lost", p)
		}
		wantSrc := "198.51.100.20/32"
		if p.ToZone == "left" {
			wantSrc = "192.0.2.10/32"
			if p.NAT.Exact || !p.NAT.PossibleAllocation {
				t.Fatal(p)
			}
		}
		if p.NAT.Translated.Regions()[0].Source != rangeOf(wantSrc) || p.NAT.Translated.Regions()[0].Destination != rangeOf(real) {
			t.Fatal("egress predicate or paired rewrite lost", p)
		}
	}
}
func TestStoneOSPacketUnknownRouteVersionAndPolicy(t *testing.T) {
	for _, tc := range []string{"version", "route", "scope", "unknown-policy", "deny"} {
		t.Run(tc, func(t *testing.T) {
			d := stonePacketData()
			q := policy.PacketRequest{Request: policy.Request{Traffic: traffic(t, "198.51.100.20/32", "203.0.113.10/32"), Scope: "vr", FromZone: "outside"}, VRF: "vr"}
			switch tc {
			case "version":
				d.Metadata.Software = "5.5R7"
			case "route":
				d.Routes = nil
			case "scope":
				q.VRF = "other"
			case "unknown-policy":
				d.Rules[0].Match.Unsupported = []string{"application"}
			case "deny":
				d.Rules[0].Action = fm.Deny
			}
			fw, err := fm.Seal(d)
			if err != nil {
				t.Fatal(err)
			}
			got, err := (policy.Engine{}).QueryPacket(t.Context(), fw, q)
			if tc == "version" {
				if !errors.Is(err, policy.ErrNAT) {
					t.Fatal(got, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if tc == "deny" {
				if len(got.Paths) != 1 || !got.Paths[0].Policy.Allowed.Empty() || !sameTraffic(t, got.Paths[0].NAT.Translated, q.Traffic) {
					t.Fatal("denied packet rewritten", got)
				}
				return
			}
			if got.Complete || !sameTraffic(t, got.Unknown, q.Traffic) {
				t.Fatal("unknown evidence lost", got)
			}
		})
	}
}
