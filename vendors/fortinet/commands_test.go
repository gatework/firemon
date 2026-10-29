package fortinet_test

import (
	"context"
	"strings"
	"testing"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/policy"
	"github.com/gatework/firemon/vendors/fortinet"
)

func TestFortinetCreateRequiresNativeMoveAndIndependentReadback(t *testing.T) {
	ctx := context.Background()
	raw := fixture(t, "basic")
	before := parse(t, raw)
	q := policy.Request{Scope: "root", FromZone: "inside", ToZone: "wan1", Traffic: traffic(t, "192.0.2.11/32", "203.0.113.30/32", 6, 1000, 443)}
	p, err := (plan.Planner{Renderer: fortinet.Renderer{}}).Plan(ctx, before, []policy.Request{q})
	if err != nil {
		t.Fatal(err)
	}
	commands := strings.Join(p.Commands(), "\n") + "\n"
	if !strings.Contains(commands, "move 1 before 10") || !strings.Contains(commands, "set action accept") {
		t.Fatal(commands)
	}
	// A native final capture no longer contains the imperative move command.
	final := strings.ReplaceAll(commands, "move 1 before 10\n", "")
	observed := parse(t, final+raw)
	if _, err := p.Verify(ctx, observed); err != nil {
		t.Fatal(err, commands, observed.Diagnostics())
	}
	if _, err := p.Verify(ctx, parse(t, raw+final)); err == nil {
		t.Fatal("wrong native order accepted")
	}
}

func TestFortinetRemovingShadowedVIPPolicyCannotDeactivateSourceNAT(t *testing.T) {
	raw := fixture(t, "basic") + nativeNAT
	// A match-vip deny shadows the inbound VIP policy, while its reference still
	// activates outbound reverse VIP translation on the owning SNAT policy.
	deny := `config firewall policy
edit 19
set srcintf "wan1"
set dstintf "inside"
set srcaddr "all"
set dstaddr "all"
set action deny
set schedule "always"
set service "ALL"
set match-vip enable
next
end
`
	raw = strings.Replace(raw, "config firewall policy\nedit 20", deny+"config firewall policy\nedit 20", 1)
	before := parse(t, raw)
	d := before.Export()
	var rules []fm.RuleRecord
	for _, r := range d.Rules {
		if r.ID != "20" {
			rules = append(rules, r)
		}
	}
	d.Rules = rules
	after, err := fm.Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (policy.Engine{}).Equivalent(context.Background(), before, after, time.Now()); err == nil {
		t.Fatal("VIP activation dependency disappeared in lifecycle proof")
	}
}

func TestFortinetAppendRendersFullGraphMembersWithoutRawReparse(t *testing.T) {
	ctx := context.Background()
	raw := fixture(t, "basic")
	before := parse(t, raw)
	q := policy.Request{Scope: "root", FromZone: "inside", ToZone: "wan1", Traffic: traffic(t, "192.0.2.11/32", "203.0.113.10/32", 6, 1000, 443)}
	// Keep the original rule's other dimensions singleton for an exact append.
	raw = strings.Replace(raw, "set end-ip 203.0.113.20", "set end-ip 203.0.113.10", 1)
	raw = strings.Replace(raw, "443:1000-1001", "443:1000", 1)
	raw = strings.Replace(raw, "        set udp-portrange 53:2000\n", "", 1)
	before = parse(t, raw)
	p, err := (plan.Planner{Renderer: fortinet.Renderer{}}).Plan(ctx, before, []policy.Request{q})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Changes()) != 1 || p.Changes()[0].Kind != plan.AppendMembers {
		t.Fatal(p.Changes())
	}
	text := strings.Join(p.Commands(), "\n") + "\n"
	marker := "config firewall policy\n"
	i := strings.Index(text, marker)
	if i < 0 || !strings.Contains(text[i:], "set srcaddr \"clients\" ") {
		t.Fatal(text)
	}
	// The final policy retains its name and other fields, which a native edit
	// does not delete. Build that capture independently from the original block.
	sourceLine := ""
	for _, line := range strings.Split(text[i:], "\n") {
		if strings.HasPrefix(line, "set srcaddr ") {
			sourceLine = line
		}
	}
	observed := parse(t, strings.Replace(raw, "set srcaddr \"clients\"", sourceLine, 1)+text[:i])
	if _, err := p.Verify(ctx, observed); err != nil {
		t.Fatal(err, text)
	}
}

func TestFortinetPlanPreservesMultipleVIPRegionsOwnedByOneRule(t *testing.T) {
	raw := fixture(t, "basic") + nativeNAT
	fw := parse(t, raw)
	q := policy.Request{Scope: "root", FromZone: "wan1", ToZone: "inside", Traffic: traffic(t, "203.0.113.50/32", "192.0.2.30/32", 6, 1000, 443)}
	p, err := (plan.Planner{Renderer: fortinet.Renderer{}}).Plan(context.Background(), fw, []policy.Request{q})
	if err != nil {
		t.Fatal(err)
	}
	final := strings.ReplaceAll(strings.Join(p.Commands(), "\n")+"\n", "move 1 before 10\n", "")
	if _, err := p.Verify(context.Background(), parse(t, final+raw)); err != nil {
		t.Fatal(err, p.Commands())
	}
}

func TestFortinetRemoveDisabledPolicyHasIndependentReadback(t *testing.T) {
	raw := strings.Replace(fixture(t, "basic"), "set action accept", "set action accept\nset status disable", 1)
	before := parse(t, raw)
	d := before.Export()
	var rules []fm.RuleRecord
	for _, r := range d.Rules {
		if r.ID != "10" {
			rules = append(rules, r)
		}
	}
	d.Rules = rules
	after, err := fm.Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	p, err := (plan.Planner{Renderer: fortinet.Renderer{}}).Preserve(context.Background(), before, after, []plan.Change{{Kind: plan.RemoveRule, Rule: "10"}}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(p.Commands(), "\n") != "config firewall policy\ndelete 10\nend" {
		t.Fatal(p.Commands())
	}
	observed := parse(t, raw[:strings.Index(raw, "config firewall policy")])
	if _, err := p.Verify(context.Background(), observed); err != nil {
		t.Fatal(err)
	}
}
