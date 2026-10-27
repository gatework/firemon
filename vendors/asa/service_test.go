package asa_test

import (
	"context"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/policy"
	"github.com/gatework/firemon/vendors/asa"
)

func TestASAServiceGroupsPreserveProtocolAndBothPortAxes(t *testing.T) {
	fw := parseASA(t, interfaces+"object service web\n service tcp source range 1000 2000 destination eq 443\nobject-group service allowed\n service-object object web\n service-object udp source eq 53 destination eq 5353\naccess-list IN extended permit object-group allowed any4 any4\naccess-group IN in interface inside\n")
	for _, tc := range []struct {
		proto, src, dst uint16
		allowed         bool
	}{
		{6, 1234, 443, true}, {6, 1234, 80, false}, {6, 5000, 443, false},
		{17, 53, 5353, true}, {17, 1234, 443, false}, {6, 53, 5353, false},
	} {
		traffic, err := flow.NewTraffic(16, flow.Box{Source: host("192.0.2.2"), Destination: host("198.51.100.2"), Protocol: flow.Interval{Low: tc.proto, High: tc.proto}, SourcePort: flow.Interval{Low: tc.src, High: tc.src}, DestinationPort: flow.Interval{Low: tc.dst, High: tc.dst}, ICMPType: flow.Interval{High: 255}, ICMPCode: flow.Interval{High: 255}})
		if err != nil {
			t.Fatal(err)
		}
		r, err := (policy.Engine{}).Query(context.Background(), fw, policy.Request{Traffic: traffic, RuleSet: "IN", FromZone: "inside", ToZone: "outside"})
		if err != nil || !r.Complete || (!r.Allowed.Empty()) != tc.allowed {
			t.Fatalf("%+v: %+v %v", tc, r, err)
		}
	}
}

func TestASAUnknownServiceSuffixCannotBecomeUnrestricted(t *testing.T) {
	for _, declaration := range []string{"object service x\n service tcp opaque value\n", "object-group service x tcp\n port-object eq 443 opaque\n", "object-group network x\n network-object host 192.0.2.1 opaque\n"} {
		fw, err := asa.Parse(context.Background(), config.Source{Text: declaration, Complete: true}, fm.Metadata{Device: "asa"})
		if err != nil {
			t.Fatal(err)
		}
		if fw.Complete() {
			t.Fatalf("unsupported suffix was consumed: %s", declaration)
		}
	}
}

func TestASAServiceProtocolZeroIsDistinctFromIP(t *testing.T) {
	fw := parseASA(t, "object service zero\n service 0\nobject service all\n service ip\n")
	if fw.Service("zero").Record().Terms[0].Protocol != (flow.Interval{}) || fw.Service("all").Record().Terms[0].Protocol != (flow.Interval{High: 255}) {
		t.Fatal("ip wildcard conflated with protocol zero")
	}
}
