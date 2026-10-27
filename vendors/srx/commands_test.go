package srx_test

import (
	"context"
	"strings"
	"testing"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/policy"
	"github.com/gatework/firemon/vendors/srx"
)

const topology = "set interfaces ge-0/0/0 unit 0 family inet address 192.0.2.1/24\nset interfaces ge-0/0/1 unit 0 family inet address 198.51.100.1/24\nset security zones security-zone inside interfaces ge-0/0/0.0\nset security zones security-zone outside interfaces ge-0/0/1.0\n"

func TestSRXCreateCommandsRoundTripWithoutRawReparseDuringPlanning(t *testing.T) {
	ctx := context.Background()
	before := parse(t, topology)
	p, err := (plan.Planner{Renderer: srx.Renderer{}}).Plan(ctx, before, []policy.Request{{Traffic: traffic(t, "192.0.2.10/32", "198.51.100.10/32", 6, 1000, 443), FromZone: "inside", ToZone: "outside"}})
	if err != nil {
		t.Fatal(err)
	}
	var native []string
	for _, c := range p.Commands() {
		if strings.HasPrefix(c, "set ") {
			native = append(native, c)
		} else if c != "configure" && c != "exit" {
			t.Fatal("unexpected command", c)
		}
	}
	observed := parse(t, topology+strings.Join(native, "\n")+"\n")
	if _, err := p.Verify(ctx, observed); err != nil {
		t.Fatal(err, p.Commands(), observed.Diagnostics())
	}
}

func TestSRXAppendResolvesScopedNamesAndKeepsExistingMembers(t *testing.T) {
	ctx := context.Background()
	raw := fixture(t)
	// A single application term makes a source-member append exact.
	rows := strings.Split(raw, "\n")
	var retained []string
	for _, row := range rows {
		if !strings.Contains(row, "term udp") {
			retained = append(retained, row)
		}
	}
	raw = strings.Join(retained, "\n")
	p, err := (plan.Planner{Renderer: srx.Renderer{}}).Plan(ctx, parse(t, raw), []policy.Request{{Traffic: func() flow.Traffic {
		b := traffic(t, "192.0.2.11/32", "198.51.100.20/32", 6, 1000, 443).Boxes()[0]
		b.SourcePort.High = 1001
		v, _ := flow.NewTraffic(8, b)
		return v
	}(), FromZone: "inside", ToZone: "outside"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Changes()) != 1 || p.Changes()[0].Kind != plan.AppendMembers {
		t.Fatal(p.Changes())
	}
	for _, c := range p.Commands() {
		if strings.HasPrefix(c, "set ") {
			raw += c + "\n"
		}
	}
	if _, err := p.Verify(ctx, parse(t, raw)); err != nil {
		t.Fatal(err, p.Commands())
	}
}

func TestSRXNewPolicyIsInsertedBeforeNativeDenyInTheSameZonePair(t *testing.T) {
	ctx := context.Background()
	block := "set security policies from-zone inside to-zone outside policy stop match source-address any\nset security policies from-zone inside to-zone outside policy stop match destination-address any\nset security policies from-zone inside to-zone outside policy stop match application any\nset security policies from-zone inside to-zone outside policy stop then deny\n"
	p, err := (plan.Planner{Renderer: srx.Renderer{}}).Plan(ctx, parse(t, topology+block), []policy.Request{{Traffic: traffic(t, "192.0.2.10/32", "198.51.100.10/32", 6, 1000, 443), FromZone: "inside", ToZone: "outside"}})
	if err != nil {
		t.Fatal(err)
	}
	var native []string
	inserted := false
	for _, c := range p.Commands() {
		if strings.HasPrefix(c, "set ") {
			native = append(native, c)
		}
		if strings.HasPrefix(c, "insert security policies from-zone inside to-zone outside policy ") && strings.HasSuffix(c, " before policy stop") {
			inserted = true
		}
	}
	if !inserted {
		t.Fatal("missing native insert before deny", p.Commands())
	}
	// Independent display-set capture after the device applied insertion.
	if _, err := p.Verify(ctx, parse(t, topology+strings.Join(native, "\n")+"\n"+block)); err != nil {
		t.Fatal(err)
	}
}

func TestSRXPlannerReusesAddressesOnlyInTheirVisibleBook(t *testing.T) {
	ctx := context.Background()
	raw := topology + "set security address-book clients attach zone inside\nset security address-book clients address host 192.0.2.10/32\n"
	p, err := (plan.Planner{Renderer: srx.Renderer{}}).Plan(ctx, parse(t, raw), []policy.Request{{Traffic: traffic(t, "192.0.2.10/32", "192.0.2.10/32", 6, 1000, 443), FromZone: "inside", ToZone: "outside"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range p.Commands() {
		if strings.HasPrefix(c, "set ") {
			raw += c + "\n"
		}
	}
	if _, err := p.Verify(ctx, parse(t, raw)); err != nil {
		t.Fatal("cross-zone book reference leaked", err, p.Commands())
	}
}

func TestSRXReadbackComparesOrderWithinEachNativeZonePair(t *testing.T) {
	ctx := context.Background()
	block := func(from, to string) string {
		return "set security policies from-zone " + from + " to-zone " + to + " policy stop match source-address any\nset security policies from-zone " + from + " to-zone " + to + " policy stop match destination-address any\nset security policies from-zone " + from + " to-zone " + to + " policy stop match application any\nset security policies from-zone " + from + " to-zone " + to + " policy stop then deny\n"
	}
	outside, inside := block("outside", "inside"), block("inside", "outside")
	p, err := (plan.Planner{Renderer: srx.Renderer{}}).Plan(ctx, parse(t, topology+outside+inside), []policy.Request{{Traffic: traffic(t, "192.0.2.10/32", "198.51.100.10/32", 6, 1000, 443), FromZone: "inside", ToZone: "outside"}})
	if err != nil {
		t.Fatal(err)
	}
	var native []string
	for _, c := range p.Commands() {
		if strings.HasPrefix(c, "set ") {
			native = append(native, c)
		}
	}
	if _, err := p.Verify(ctx, parse(t, topology+outside+strings.Join(native, "\n")+"\n"+inside)); err != nil {
		t.Fatal("unrelated zone pair order affected proof", err)
	}
	if _, err := p.Verify(ctx, parse(t, topology+outside+inside+strings.Join(native, "\n")+"\n")); err == nil {
		t.Fatal("policy after blocking deny passed readback")
	}
}

func TestSRXDisabledPolicyRemovalHasIndependentReadbackProof(t *testing.T) {
	ctx := context.Background()
	raw := fixture(t)
	path := "security policies from-zone inside to-zone outside policy permit-web"
	before := parse(t, raw+"deactivate "+path+"\n")
	var lines []string
	for _, line := range strings.Split(raw, "\n") {
		if !strings.Contains(line, path) {
			lines = append(lines, line)
		}
	}
	after := parse(t, strings.Join(lines, "\n"))
	p, err := (plan.Planner{Renderer: srx.Renderer{}}).Preserve(ctx, before, after, []plan.Change{{Kind: plan.RemoveRule, Rule: fm.ID("policy:inside/outside/permit-web")}}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Commands()) != 3 || p.Commands()[1] != "delete "+path {
		t.Fatal(p.Commands())
	}
	if _, err := p.Verify(ctx, after); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Verify(ctx, before); err == nil {
		t.Fatal("removed policy remained in readback")
	}
}
