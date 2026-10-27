package plan_test

import (
	"context"
	"strings"
	"testing"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/vendors/paloalto"
)

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
