package asa_test

import (
	"context"
	"strings"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/policy"
)

func TestASAPacketUsesRealDestinationAndServiceAfterReverseStaticNAT(t *testing.T) {
	base := strings.ReplaceAll(strings.ReplaceAll(interfaces, "nameif inside", "nameif inside\n security-level 100"), "nameif outside", "nameif outside\n security-level 0")
	base += "object network server\n host 192.0.2.10\n nat (inside,outside) static 203.0.113.10 service tcp 443 8443\naccess-group IN in interface outside\n"
	traffic, err := flow.NewTraffic(16, flow.TrafficRegion{Source: host("198.51.100.2"), Destination: host("203.0.113.10"), Protocol: flow.Interval{Low: 6, High: 6}, SourcePort: flow.Interval{Low: 1234, High: 1234}, DestinationPort: flow.Interval{Low: 8443, High: 8443}, ICMPType: flow.Interval{High: 255}, ICMPCode: flow.Interval{High: 255}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, acl string
		allow     bool
	}{
		{"real", "access-list IN extended permit tcp any4 object server eq 443\n", true},
		{"mapped", "access-list IN extended permit tcp any4 host 203.0.113.10 eq 8443\n", false},
		{"outbound-deny", "access-list IN extended permit tcp any4 object server eq 443\naccess-list OUT extended deny ip any4 any4\naccess-group OUT out interface inside\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fw := parseASA(t, base+tc.acl)
			r, err := (policy.Engine{}).QueryPacket(context.Background(), fw, policy.PacketRequest{Request: policy.Request{Traffic: traffic, FromZone: "outside"}})
			if err != nil || !r.Complete || len(r.Paths) != 1 {
				t.Fatal(r, err)
			}
			path := r.Paths[0]
			if path.ToZone != "inside" || path.NAT.Steps[0].Kind != fm.StaticNATObject || !path.NAT.Steps[0].Reverse || (!path.Policy.Allowed.Empty()) != tc.allow {
				t.Fatal(path)
			}
			if !tc.allow && path.Policy.Denied.Empty() {
				t.Fatal("implicit/outbound deny lost")
			}
		})
	}
}

func TestASAPacketNeedsSecurityAndInterfaceEvidence(t *testing.T) {
	traffic, _ := flow.NewTraffic(16, flow.TrafficRegion{Source: host("192.0.2.10"), Destination: host("203.0.113.10"), Protocol: flow.Interval{Low: 6, High: 6}, SourcePort: flow.Interval{High: 65535}, DestinationPort: flow.Interval{Low: 443, High: 443}, ICMPType: flow.Interval{High: 255}, ICMPCode: flow.Interval{High: 255}})
	for _, tc := range []struct {
		name, raw    string
		known, allow bool
	}{
		{"missing-level", interfaces, false, false},
		{"default-high-to-low", strings.ReplaceAll(strings.ReplaceAll(interfaces, "nameif inside", "nameif inside\n security-level 100"), "nameif outside", "nameif outside\n security-level 0"), true, true},
		{"same-level", strings.ReplaceAll(interfaces, "nameif", "security-level 50\n nameif"), true, false},
		{"disabled-egress", strings.ReplaceAll(interfaces, "nameif outside", "shutdown\n nameif outside"), false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fw := parseASA(t, tc.raw)
			r, err := (policy.Engine{}).QueryPacket(context.Background(), fw, policy.PacketRequest{Request: policy.Request{Traffic: traffic, FromZone: "inside"}})
			if err != nil || r.Complete != tc.known {
				t.Fatal(r, err)
			}
			if !tc.known && r.Unknown.Empty() {
				t.Fatal("missing evidence became certain")
			}
			if tc.known && (len(r.Paths) != 1 || (!r.Paths[0].Policy.Allowed.Empty()) != tc.allow) {
				t.Fatal(r)
			}
		})
	}
}

func TestASAPacketDoesNotTreatMulticastAsOrdinaryACLPermit(t *testing.T) {
	raw := strings.ReplaceAll(strings.ReplaceAll(interfaces, "nameif inside", "nameif inside\n security-level 100"), "nameif outside", "nameif outside\n security-level 0")
	raw += "route outside 0.0.0.0 0.0.0.0 203.0.113.254\naccess-list IN extended permit ip any4 any4\naccess-group IN in interface inside\n"
	fw := parseASA(t, raw)
	traffic, _ := flow.NewTraffic(16, flow.TrafficRegion{Source: host("192.0.2.10"), Destination: host("224.0.0.1"), Protocol: flow.Interval{Low: 17, High: 17}, SourcePort: flow.Interval{High: 65535}, DestinationPort: flow.Interval{Low: 5000, High: 5000}, ICMPType: flow.Interval{High: 255}, ICMPCode: flow.Interval{High: 255}})
	r, err := (policy.Engine{}).QueryPacket(context.Background(), fw, policy.PacketRequest{Request: policy.Request{Traffic: traffic, FromZone: "inside"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range r.Paths {
		if !path.Policy.Allowed.Empty() {
			t.Fatal("multicast became an ordinary permitted path", path)
		}
	}
}
