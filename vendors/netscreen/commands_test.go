package netscreen_test

import (
	"context"
	"strings"
	"testing"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/policy"
	"github.com/gatework/firemon/vendors/netscreen"
)

const topology = "set interface ethernet0/1 zone Trust\nset interface ethernet0/1 ip 192.0.2.1/24\nset interface ethernet0/2 zone Untrust\nset interface ethernet0/2 ip 198.51.100.1/24\n"

func TestCreateAndIndependentScreenOSReadback(t *testing.T) {
	ctx := context.Background()
	raw := topology + "set policy id 1 from Trust to Untrust Any Any ANY deny\nexit\n"
	before := parse(t, raw)
	p, err := (plan.Planner{Renderer: netscreen.Renderer{}}).Plan(ctx, before, []policy.Request{{Traffic: traffic(t, "192.0.2.10/32", "198.51.100.10/32", 6, 1000, 443), FromZone: "Trust", ToZone: "Untrust"}})
	if err != nil {
		t.Fatal(err)
	}
	commands := strings.Join(p.Commands(), "\n")
	if !strings.Contains(commands, "set policy id 2 top from \"Trust\" to \"Untrust\"") || strings.Contains(commands, "save") {
		t.Fatal(commands)
	}
	// The capture reflects the device's final ordering and omits the transient top modifier.
	var objects, policyLines []string
	policyContext := false
	for _, line := range p.Commands() {
		if strings.HasPrefix(line, "set policy ") {
			policyContext = true
		}
		if policyContext {
			policyLines = append(policyLines, strings.ReplaceAll(line, " top from ", " from "))
		} else {
			objects = append(objects, line)
		}
	}
	observed := parse(t, topology+strings.Join(objects, "\n")+"\n"+strings.Join(policyLines, "\n")+"\nset policy id 1 from Trust to Untrust Any Any ANY deny\nexit\n")
	if _, err := p.Verify(ctx, observed); err != nil {
		t.Fatal(err, commands, observed.Diagnostics())
	}
	wrong := parse(t, raw+strings.Join(objects, "\n")+"\n"+strings.Join(policyLines, "\n")+"\n")
	if _, err := p.Verify(ctx, wrong); err == nil {
		t.Fatal("native order was not verified")
	}
}

func TestAppendUsesScopedObjectsAndIndependentContinuation(t *testing.T) {
	ctx := context.Background()
	raw := topology + "set address Trust client 192.0.2.10/32\nset address Untrust client 198.51.100.10/32\nset service web protocol tcp src-port 1000-1001 dst-port 443-443\nset policy id 10 from Trust to Untrust client client web permit\nexit\n"
	b := traffic(t, "192.0.2.11/32", "198.51.100.10/32", 6, 1000, 443).Boxes()[0]
	b.SourcePort.High = 1001
	v, _ := flow.NewTraffic(8, b)
	p, err := (plan.Planner{Renderer: netscreen.Renderer{}}).Plan(ctx, parse(t, raw), []policy.Request{{Traffic: v, FromZone: "Trust", ToZone: "Untrust"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Changes()) != 1 || p.Changes()[0].Kind != plan.AppendMembers {
		t.Fatal(p.Changes())
	}
	if _, err := p.Verify(ctx, parse(t, raw+strings.Join(p.Commands(), "\n")+"\n")); err != nil {
		t.Fatal(err, p.Commands())
	}
}

func TestRemovingPolicyCannotExposePreviouslyShadowedPolicyNAT(t *testing.T) {
	raw := fixture(t, "nat")
	fw := parse(t, raw)
	d := fw.Export()
	for i, r := range d.Rules {
		if r.ID == "11" {
			d.Rules = append(d.Rules[:i], d.Rules[i+1:]...)
			break
		}
	}
	after, err := fm.Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (policy.Engine{}).Equivalent(context.Background(), fw, after, time.Now()); err == nil {
		t.Fatal("equal permit/logging hid a new NAT effect")
	}
}

func TestRemoveDisabledNativePolicyAndRejectNATOwnerEdits(t *testing.T) {
	ctx := context.Background()
	raw := topology + "set policy id 5 from Trust to Untrust Any Any ANY permit\nexit\nset policy id 5 disable\nexit\n"
	before := parse(t, raw)
	d := before.Export()
	var rules []fm.RuleRecord
	for _, r := range d.Rules {
		if r.ID != "5" {
			rules = append(rules, r)
		}
	}
	d.Rules = rules
	after, err := fm.Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	p, err := (plan.Planner{Renderer: netscreen.Renderer{}}).Preserve(ctx, before, after, []plan.Change{{Kind: plan.RemoveRule, Rule: "5"}}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Commands()) != 1 || p.Commands()[0] != "unset policy id 5" {
		t.Fatal(p.Commands())
	}
	if _, err := p.Verify(ctx, parse(t, topology)); err != nil {
		t.Fatal(err)
	}
	before = parse(t, fixture(t, "nat"))
	d = before.Export()
	for i := range d.Rules {
		if d.Rules[i].ID == "12" {
			d.Rules[i].Match.AnySource = true
		}
	}
	after, err = fm.Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (netscreen.Renderer{}).Render(ctx, before, after, []plan.Change{{Kind: plan.AppendMembers, Rule: "12"}}); err == nil {
		t.Fatal("policy NAT edit escaped joint validation")
	}
}
