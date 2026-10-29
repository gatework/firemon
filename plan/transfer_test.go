package plan_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/policy"
	"github.com/gatework/firemon/vendors/fortinet"
	"github.com/gatework/firemon/vendors/paloalto"
)

func TestTransferCannotRemoveEffectivePolicyNAT(t *testing.T) {
	raw, err := os.ReadFile("../vendors/fortinet/testdata/basic.conf")
	if err != nil {
		t.Fatal(err)
	}
	text := strings.ReplaceAll(string(raw), "set logtraffic all", "set logtraffic disable\n        set nat enable")
	before, err := fortinet.Parse(context.Background(), config.Source{Text: text, Complete: true}, fm.Metadata{Device: "fg", Context: "root"})
	if err != nil || !before.Complete() {
		t.Fatal(err)
	}
	traffic, err := flow.NewTraffic(32, flow.Box{Source: addressRange("192.0.2.10/32"), Destination: addressRange("203.0.113.10/32"), Protocol: flow.Interval{Low: 6, High: 6}, SourcePort: flow.Interval{Low: 1000, High: 1000}, DestinationPort: flow.Interval{Low: 443, High: 443}, ICMPType: flow.Interval{High: 255}, ICMPCode: flow.Interval{High: 255}})
	if err != nil {
		t.Fatal(err)
	}
	q := policy.Request{Scope: "root", RuleSet: "security", FromZone: "inside", ToZone: "wan1", Traffic: traffic}
	nat, err := (policy.Engine{}).QueryNAT(context.Background(), before, q)
	if err != nil || !nat.Complete || len(nat.Relations) != 1 {
		t.Fatal("baseline SNAT must be effective", nat, err)
	}
	intent := plan.RuleIntent{Request: q, Action: fm.Permit, Log: fm.Irrelevant, LogStart: fm.Irrelevant, LogEnd: fm.Irrelevant}
	if p, err := (plan.Planner{Renderer: fortinet.Renderer{}}).Transfer(context.Background(), before, []plan.RuleIntent{intent}, time.Time{}); err == nil {
		t.Fatal("transfer removed the SNAT-owning permit policy from the effective path", p.Proof())
	}
	// A disjoint transfer remains supported when the existing translation is
	// unaffected; NAT presence alone is not grounds for rejection.
	b := traffic.Boxes()[0]
	b.Source = addressRange("192.0.2.11/32")
	intent.Request.Traffic, _ = flow.NewTraffic(32, b)
	p, err := (plan.Planner{Renderer: fortinet.Renderer{}}).Transfer(context.Background(), before, []plan.RuleIntent{intent}, time.Time{})
	if err != nil || !p.Proof().NATUnchanged {
		t.Fatal("disjoint transfer rejected", err)
	}
	commands := strings.Join(p.Commands(), "\n") + "\n"
	if !strings.Contains(commands, "move 1 before 10\n") {
		t.Fatal("native insertion order is missing", commands)
	}
	// The native saved configuration contains the resulting rule order, not
	// the imperative move command. Reparse it independently of the plan graph.
	created := strings.ReplaceAll(commands, "move 1 before 10\n", "")
	observed, err := fortinet.Parse(context.Background(), config.Source{Text: created + text, Complete: true}, before.Metadata())
	if err != nil || !observed.Complete() {
		t.Fatal("native readback is incomplete", err)
	}
	if _, err := p.Verify(context.Background(), observed); err != nil {
		t.Fatal("native readback did not preserve NAT", err)
	}
	changed, err := fortinet.Parse(context.Background(), config.Source{Text: created + strings.ReplaceAll(text, "set nat enable", "set nat disable"), Complete: true}, before.Metadata())
	if err != nil || !changed.Complete() {
		t.Fatal("invalid changed-NAT fixture", err)
	}
	if _, err := p.Verify(context.Background(), changed); err == nil {
		t.Fatal("readback with lost SNAT passed the transfer proof")
	}
}

func TestTransferDoesNotReuseVIPAsOrdinaryAddress(t *testing.T) {
	address := addressRange("198.51.100.1/32")
	before, err := fm.Seal(fm.Data{Metadata: fm.Metadata{Device: "fg", Vendor: "fortinet", Context: "root"},
		Zones:      []fm.ZoneRecord{{Object: fm.Object{ID: "inside", Scope: "root"}, AddressScope: "root"}, {Object: fm.Object{ID: "outside", Scope: "root"}, AddressScope: "root"}},
		Addresses:  []fm.AddressRecord{{Object: fm.Object{ID: "public", Name: "public", Scope: "root"}, Ranges: []flow.Range{address}, VIP: fm.NATRef{Kind: fm.StaticNATObject, ID: "vip"}}},
		StaticNATs: []fm.StaticNATRecord{{Object: fm.Object{ID: "vip", Scope: "root"}, Disabled: true, Order: fm.NATOrder{Section: "vip"}, Match: fm.Match{AnySource: true, AnyDestination: true, AnyService: true, AnyFromZone: true, AnyToZone: true}, Destination: []fm.Mapping{{Original: address, Translated: address, Mode: fm.Identity}}}},
	})
	if err != nil || !before.Complete() {
		t.Fatal(err)
	}
	q := request(t, "192.0.2.1/32")
	q.Scope, q.FromZone, q.ToZone = "root", "inside", "outside"
	intent := plan.RuleIntent{Request: q, Action: fm.Permit, Log: fm.Irrelevant, LogStart: fm.Irrelevant, LogEnd: fm.Irrelevant}
	p, err := (plan.Planner{Renderer: renderer{}}).Transfer(context.Background(), before, []plan.RuleIntent{intent}, time.Time{})
	if err != nil {
		t.Fatal("ordinary policy design reused the inactive VIP selector", err)
	}
	r := p.After().Rule(p.Changes()[0].Rule).Record()
	if len(r.Match.Destinations) != 1 || p.After().Address(r.Match.Destinations[0].ID).Record().VIP != (fm.NATRef{}) {
		t.Fatal("ordinary address silently carries VIP selection semantics", r.Match)
	}
}

func TestTransferPreservesActionsAndNativeLogEventsThroughReadback(t *testing.T) {
	raw := "set zone inside network layer3 ethernet1/1\nset zone outside network layer3 ethernet1/2\nset network interface ethernet ethernet1/1 layer3 ip 192.0.2.1/24\nset network interface ethernet ethernet1/2 layer3 ip 198.51.100.1/24\n"
	parse := func(raw string) *fm.Firewall {
		t.Helper()
		fw, err := paloalto.Parse(context.Background(), config.Source{Text: raw, Complete: true}, fm.Metadata{Device: "pan"})
		if err != nil || !fw.Complete() {
			t.Fatal(err)
		}
		return fw
	}
	before := parse(raw)
	a, b := request(t, "192.0.2.1/32"), request(t, "192.0.2.2/32")
	a.FromZone, a.ToZone = "inside", "outside"
	b.FromZone, b.ToZone = "inside", "outside"
	intents := []plan.RuleIntent{{Request: a, Action: fm.Drop, Log: fm.Known, LogStart: fm.Irrelevant, LogEnd: fm.Known}, {Request: b, Action: fm.Permit, Log: fm.Irrelevant, LogStart: fm.Irrelevant, LogEnd: fm.Irrelevant}}
	p, err := (plan.Planner{Renderer: paloalto.Renderer{}}).Transfer(context.Background(), before, intents, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	for _, cmd := range p.Commands() {
		if strings.HasPrefix(cmd, "set ") {
			raw += cmd + "\n"
		}
	}
	observed := parse(raw)
	if _, err := p.Verify(context.Background(), observed); err != nil {
		t.Fatal(err, p.Commands())
	}
	if p.Proof().TargetAllowed || !p.Proof().TargetSatisfied || !p.Proof().OutsidePreserved {
		t.Fatal(p.Proof())
	}
	d := observed.Export()
	for i := range d.Rules {
		if d.Rules[i].Action == fm.Drop {
			d.Rules[i].Action = fm.Deny
		}
	}
	changed, err := fm.Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Verify(context.Background(), changed); err == nil {
		t.Fatal("drop silently downgraded to deny")
	}
}

func TestTransferRejectsOverlappingContradictoryTargets(t *testing.T) {
	q := request(t, "192.0.2.1/32")
	intents := []plan.RuleIntent{{Request: q, Action: fm.Permit, Log: fm.Irrelevant, LogStart: fm.Irrelevant, LogEnd: fm.Irrelevant}, {Request: q, Action: fm.Deny, Log: fm.Irrelevant, LogStart: fm.Irrelevant, LogEnd: fm.Irrelevant}}
	if _, err := (plan.Planner{Renderer: renderer{}}).Transfer(context.Background(), baseline(t), intents, time.Time{}); err == nil {
		t.Fatal("contradictory targets accepted")
	}
}
