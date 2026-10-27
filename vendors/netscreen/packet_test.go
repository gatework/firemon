package netscreen_test

import (
	"context"
	"strings"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/policy"
)

func TestPacketPolicyUsesOriginalAddressAndPortWithNativeDestinationZone(t *testing.T) {
	fw := parse(t, fixture(t, "nat"))
	for _, tc := range []struct {
		src, dst, from, to, translated string
		port, translatedPort           uint16
		allow                          bool
	}{
		{"203.0.113.5/32", "198.51.100.60/32", "Untrust", "Trust", "192.0.2.60", 443, 443, true},
		{"203.0.113.5/32", "198.51.100.70/32", "Untrust", "Trust", "192.0.2.70", 8443, 443, true},
		{"203.0.113.5/32", "203.0.113.100/32", "Untrust", "Trust", "192.0.2.80", 80, 8080, true},
		{"192.0.2.10/32", "203.0.113.5/32", "Trust", "Untrust", "203.0.113.5", 443, 443, false},
	} {
		q := policy.PacketRequest{Request: policy.Request{Traffic: traffic(t, tc.src, tc.dst, 6, 12345, tc.port), FromZone: fm.ID(tc.from)}}
		r, err := (policy.Engine{}).QueryPacket(context.Background(), fw, q)
		if err != nil || !r.Complete || !r.Unknown.Empty() || len(r.Paths) != 1 {
			t.Fatal(tc, r, err)
		}
		p := r.Paths[0]
		b := p.NAT.Translated.Boxes()
		if p.ToZone != fm.ID(tc.to) || p.Policy.Allowed.Empty() == tc.allow || len(b) != 1 || b[0].Destination.First.String() != tc.translated || b[0].DestinationPort.Low != tc.translatedPort {
			t.Fatal(tc, p)
		}
		if tc.allow && p.Policy.Allowed.Boxes()[0].DestinationPort.Low != tc.port {
			t.Fatal("policy evaluated translated service", p)
		}
	}
}

func TestPolicyDestinationNATRequiresPublicAndPrivateRoutesInSameZone(t *testing.T) {
	raw := strings.ReplaceAll(fixture(t, "nat"), "set route 203.0.113.100/32 interface ethernet0/1\n", "")
	fw := parse(t, raw)
	q := policy.PacketRequest{Request: policy.Request{Traffic: traffic(t, "203.0.113.5/32", "203.0.113.100/32", 6, 12345, 80), FromZone: "Untrust"}}
	r, err := (policy.Engine{}).QueryPacket(context.Background(), fw, q)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range r.Paths {
		if !p.Policy.Allowed.Empty() {
			t.Fatal("used policy DNAT to invent its original destination zone", p)
		}
	}
	raw = fixture(t, "nat") + "set route 192.0.2.80/32 interface ethernet0/2\n"
	fw = parse(t, raw)
	r, err = (policy.Engine{}).QueryPacket(context.Background(), fw, q)
	if err != nil || r.Complete || r.Unknown.Empty() {
		t.Fatal("translated destination crossed security zone", r, err)
	}
}

func TestNATCannotSilentlyDiscardMixedDirectionTranslation(t *testing.T) {
	raw := strings.ReplaceAll(fixture(t, "nat"), "VIP(198.51.100.70) outside-https permit", "VIP(198.51.100.70) outside-https nat src permit")
	q := policy.Request{Traffic: traffic(t, "203.0.113.5/32", "198.51.100.70/32", 6, 12345, 8443), FromZone: "Untrust", ToZone: "Trust"}
	r, err := (policy.Engine{}).QueryNAT(context.Background(), parse(t, raw), q)
	if err != nil {
		t.Fatal(err)
	}
	if r.Complete {
		for _, n := range r.Relations {
			for _, b := range n.Translated.Boxes() {
				if b.Source.First.String() == "203.0.113.5" {
					t.Fatal("policy SNAT silently discarded by VIP", n)
				}
			}
		}
	} else if r.Unknown.Empty() {
		t.Fatal("missing unresolved evidence", r)
	}
}
