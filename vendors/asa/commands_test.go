package asa_test

import (
	"context"
	"slices"
	"strings"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/policy"
	"github.com/gatework/firemon/vendors/asa"
)

func TestASADeclarationIdentitiesSurviveUnrelatedLineInsertion(t *testing.T) {
	raw := interfaces + "object-group network servers\n network-object host 192.0.2.10\nobject-group service web tcp\n port-object eq 443\naccess-list IN extended permit tcp any4 object-group servers object-group web\naccess-group IN in interface inside\n"
	a, b := parseASA(t, raw), parseASA(t, "! moved lines\n! comment\n"+raw)
	if a.Rules()[0].ID() != b.Rules()[0].ID() || a.Rules()[0].Record().Match.Services[0] != b.Rules()[0].Record().Match.Services[0] {
		t.Fatal("ACL identity depends on source line")
	}
	if !slices.Equal(a.AddressGroup("servers").Record().Members, b.AddressGroup("servers").Record().Members) || !slices.Equal(a.ServiceGroup("web").Record().Members, b.ServiceGroup("web").Record().Members) {
		t.Fatal("literal identities depend on source line")
	}
}

func TestASANewACLCommandsRoundTripThroughIndependentNativeParser(t *testing.T) {
	raw := interfaces + "access-list IN extended deny ip any4 any4\naccess-group IN in interface inside\n"
	before := parseASA(t, raw)
	traffic, _ := flow.NewTraffic(16, flow.TrafficRegion{Source: host("192.0.2.10"), Destination: host("198.51.100.10"), Protocol: flow.Interval{Low: 6, High: 6}, SourcePort: flow.Interval{Low: 1000, High: 2000}, DestinationPort: flow.Interval{Low: 443, High: 443}, ICMPType: flow.Interval{High: 255}, ICMPCode: flow.Interval{High: 255}})
	p, err := (plan.Planner{Renderer: asa.Renderer{}}).Plan(context.Background(), before, []policy.Request{{Traffic: traffic, RuleSet: "IN", FromZone: "inside"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Changes()) != 1 || p.Changes()[0].Kind != plan.CreateRule {
		t.Fatal(p.Changes())
	}
	// Independently build the capture in the native ACL insertion order. CLI
	// transaction frames and line indices are absent from show running-config.
	var objects, entries []string
	inObject := false
	for _, command := range p.Commands() {
		switch {
		case command == "configure terminal" || command == "end":
		case command == "exit":
			inObject = false
			objects = append(objects, "!")
		case strings.HasPrefix(command, "object "):
			inObject = true
			objects = append(objects, command)
		case strings.HasPrefix(command, "access-list IN line 1 extended "):
			entries = append(entries, strings.Replace(command, " line 1 ", " ", 1))
		case inObject:
			objects = append(objects, " "+command)
		default:
			t.Fatal("unexpected command or ACL placement", command)
		}
	}
	if len(entries) != 1 {
		t.Fatal(p.Commands())
	}
	observed := parseASA(t, strings.Join(objects, "\n")+"\n"+strings.Join(entries, "\n")+"\n"+raw)
	if _, err := p.Verify(context.Background(), observed); err != nil {
		t.Fatal(err, p.Commands())
	}
	if len(observed.StaticNATs()) != len(before.StaticNATs()) || len(observed.DynamicNATs()) != len(before.DynamicNATs()) {
		t.Fatal("ACL plan modified NAT catalogs")
	}
	// ASA ACLs cannot encode an arbitrary destination zone predicate.
	_, err = (plan.Planner{Renderer: asa.Renderer{}}).Plan(context.Background(), before, []policy.Request{{Traffic: traffic, RuleSet: "IN", FromZone: fm.ID("inside"), ToZone: fm.ID("outside")}})
	if err == nil {
		t.Fatal("unrenderable zone predicate was accepted")
	}
}
