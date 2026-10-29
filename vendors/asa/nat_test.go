package asa_test

import (
	"context"
	"net/netip"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/policy"
	"github.com/gatework/firemon/vendors/asa"
)

const interfaces = "interface i\n nameif inside\n ip address 192.0.2.1 255.255.255.0\n!\ninterface o\n nameif outside\n ip address 203.0.113.1 255.255.255.0\n!\n"

func parseASA(t *testing.T, raw string) *fm.Firewall {
	t.Helper()
	fw, err := asa.Parse(context.Background(), config.Source{Text: raw, Complete: true}, fm.Metadata{Device: "asa", Software: "9.12"})
	if err != nil {
		t.Fatal(err)
	}
	if !fw.Complete() {
		t.Fatal(fw.Diagnostics())
	}
	return fw
}
func host(s string) flow.AddressRange {
	a := netip.MustParseAddr(s)
	return flow.AddressRange{First: a, Last: a}
}
func natQuery(t *testing.T, fw *fm.Firewall, src, dst, from, to string) policy.NATResult {
	t.Helper()
	traffic, err := flow.NewTraffic(16, flow.TrafficRegion{Source: host(src), Destination: host(dst), Protocol: flow.Interval{Low: 6, High: 6}, SourcePort: flow.Interval{Low: 1234, High: 1234}, DestinationPort: flow.Interval{Low: 443, High: 443}, ICMPType: flow.Interval{High: 255}, ICMPCode: flow.Interval{High: 255}})
	if err != nil {
		t.Fatal(err)
	}
	r, err := (policy.Engine{}).QueryNAT(context.Background(), fw, policy.Request{Traffic: traffic, FromZone: fm.ID(from), ToZone: fm.ID(to)})
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func TestASANativeSectionsChooseFirstMatchAndStaticReverse(t *testing.T) {
	// A subnet mapping uses an explicit mapped subnet object in this fixture.
	raw := interfaces + "object network public\n subnet 203.0.113.0 255.255.255.0\nobject network real\n subnet 192.0.2.0 255.255.255.0\n nat (inside,outside) static public\nobject network host\n host 192.0.2.10\nobject network manual\n host 198.51.100.10\nnat (inside,outside) source static host manual\nnat (inside,outside) after-auto source static real public\n"
	fw := parseASA(t, raw)
	r := natQuery(t, fw, "192.0.2.10", "198.51.100.1", "inside", "outside")
	if len(r.Relations) != 1 || !r.Relations[0].Exact || r.Relations[0].Translated.Regions()[0].Source != host("198.51.100.10") {
		t.Fatal("manual section did not precede auto", r)
	}
	r = natQuery(t, fw, "198.51.100.1", "203.0.113.11", "outside", "inside")
	if len(r.Relations) != 1 || r.Relations[0].Translated.Regions()[0].Destination != host("192.0.2.11") {
		t.Fatal("auto inverse offset lost", r)
	}
}

func TestASAStaticPortTranslationAndReverseUseNativeServiceAxes(t *testing.T) {
	for _, tc := range []struct {
		name, config                   string
		src, dst, mappedSrc, mappedDst uint16
	}{
		{"object", "object network real\n host 192.0.2.10\n nat (inside,outside) static 203.0.113.10 service tcp 443 8443\n", 443, 1234, 8443, 1234},
		{"twice", "object network real\n host 192.0.2.10\nobject network mapped\n host 203.0.113.10\nobject service original\n service tcp source eq 80 destination eq 443\nobject service translated\n service tcp source eq 8080 destination eq 8443\nnat (inside,outside) source static real mapped service original translated\n", 80, 443, 8080, 8443},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fw := parseASA(t, interfaces+tc.config)
			for _, reverse := range []bool{false, true} {
				from, to := fm.ID("inside"), fm.ID("outside")
				box := flow.TrafficRegion{Source: host("192.0.2.10"), Destination: host("198.51.100.1"), Protocol: flow.Interval{Low: 6, High: 6}, SourcePort: flow.Interval{Low: tc.src, High: tc.src}, DestinationPort: flow.Interval{Low: tc.dst, High: tc.dst}, ICMPType: flow.Interval{High: 255}, ICMPCode: flow.Interval{High: 255}}
				wantSrc, wantDst := tc.mappedSrc, tc.mappedDst
				if reverse {
					from, to = to, from
					box.Source, box.Destination = host("198.51.100.1"), host("203.0.113.10")
					box.SourcePort, box.DestinationPort = flow.Interval{Low: tc.mappedDst, High: tc.mappedDst}, flow.Interval{Low: tc.mappedSrc, High: tc.mappedSrc}
					wantSrc, wantDst = tc.dst, tc.src
				}
				traffic, err := flow.NewTraffic(16, box)
				if err != nil {
					t.Fatal(err)
				}
				r, err := (policy.Engine{}).QueryNAT(context.Background(), fw, policy.Request{Traffic: traffic, FromZone: from, ToZone: to})
				if err != nil || !r.Complete || len(r.Relations) != 1 {
					t.Fatalf("reverse=%v result=%+v error=%v", reverse, r, err)
				}
				got := r.Relations[0].Translated.Regions()[0]
				if got.SourcePort.Low != wantSrc || got.DestinationPort.Low != wantDst {
					t.Fatalf("wrong port axes: %+v", got)
				}
				box.Protocol = flow.Interval{Low: 17, High: 17}
				traffic, _ = flow.NewTraffic(16, box)
				r, err = (policy.Engine{}).QueryNAT(context.Background(), fw, policy.Request{Traffic: traffic, FromZone: from, ToZone: to})
				if err != nil || len(r.Relations) != 0 || r.Unmatched.Empty() {
					t.Fatal("TCP NAT matched UDP", r, err)
				}
			}
		})
	}
}

func TestASAUnsupportedStaticCardinalityAndDynamicSubnetRemainEvidence(t *testing.T) {
	for _, raw := range []string{
		interfaces + "object network real\n subnet 192.0.2.0 255.255.255.0\n nat (inside,outside) static 203.0.113.10\n",
		interfaces + "object network pool\n subnet 203.0.113.0 255.255.255.0\nobject network real\n host 192.0.2.10\n nat (inside,outside) dynamic pool\n",
	} {
		fw, err := asa.Parse(context.Background(), config.Source{Text: raw, Complete: true}, fm.Metadata{Device: "asa", Software: "9.12"})
		if err != nil {
			t.Fatal("unmodeled native mapping must remain inspectable", err)
		}
		if fw.Complete() {
			t.Fatal("unproven cardinality or subnet pool became complete")
		}
	}
}
func TestASATwiceNATUsesOriginalPredicatesAndInvertsBothSides(t *testing.T) {
	fw := parseASA(t, interfaces+"object network client\n host 192.0.2.10\nobject network mapped-client\n host 203.0.113.10\nobject network public-server\n host 198.51.100.10\nobject network real-server\n host 10.0.0.10\nnat (inside,outside) source static client mapped-client destination static public-server real-server\n")
	r := natQuery(t, fw, "192.0.2.10", "198.51.100.10", "inside", "outside")
	if len(r.Relations) != 1 || r.Relations[0].Translated.Regions()[0].Source != host("203.0.113.10") || r.Relations[0].Translated.Regions()[0].Destination != host("10.0.0.10") {
		t.Fatal("twice NAT forward relation lost", r)
	}
	r = natQuery(t, fw, "10.0.0.10", "203.0.113.10", "outside", "inside")
	if len(r.Relations) != 1 || r.Relations[0].Translated.Regions()[0].Source != host("198.51.100.10") || r.Relations[0].Translated.Regions()[0].Destination != host("192.0.2.10") {
		t.Fatal("twice NAT reverse relation lost", r)
	}
	r = natQuery(t, fw, "192.0.2.10", "198.51.100.11", "inside", "outside")
	if len(r.Relations) != 0 || r.Unmatched.Empty() {
		t.Fatal("destination predicate ignored", r)
	}
}
func TestASAObjectPoolPreservesPortsAndAutoTieBreakUsesObjectName(t *testing.T) {
	fw := parseASA(t, interfaces+"object network pool\n range 203.0.113.10 203.0.113.20\nobject network z\n host 192.0.2.10\n nat (inside,outside) dynamic pool\nobject network a\n host 192.0.2.10\n nat (inside,outside) dynamic 203.0.113.30\n")
	first := fw.NATSequence()[0]
	if fw.DynamicNAT(first.ID).Record().Match.Sources[0].ID != "a" {
		t.Fatal("native object-name tie break lost")
	}
	for _, n := range fw.DynamicNATs() {
		if n.Record().Match.Sources[0].ID == "z" && n.Record().SourceMode != fm.DynamicIP {
			t.Fatal("dynamic pool turned into PAT")
		}
	}
}
