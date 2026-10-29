package paloalto_test

import (
	"context"
	"strings"
	"testing"

	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/policy"
	"github.com/gatework/firemon/vendors/paloalto"
)

func TestPANNewRuleCommandsRoundTripThroughIndependentNativeParser(t *testing.T) {
	fw := pan(t, zones)
	p, err := (plan.Planner{Renderer: paloalto.Renderer{}}).Plan(context.Background(), fw, []policy.Request{{Traffic: packet(t), FromZone: "inside", ToZone: "outside"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Changes()) != 1 || p.Changes()[0].Kind != plan.CreateRule {
		t.Fatal("did not create before default deny")
	}
	var native []string
	for _, line := range p.Commands() {
		if strings.HasPrefix(line, "set ") {
			native = append(native, line)
		}
		if line == "commit" || strings.Contains(line, "move rulebase security rules \"$default:") {
			t.Fatal("persistence or implicit rule in command flow", line)
		}
	}
	observed := pan(t, zones+strings.Join(native, "\n")+"\n")
	if _, err := p.Verify(context.Background(), observed); err != nil {
		t.Fatal("native command representation did not produce planned graph", err)
	}
	r := observed.Rule(p.Changes()[0].Rule)
	terms, known, err := (policy.Engine{}).ResolveServices(context.Background(), observed, r.Record().Match.Services, false)
	if err != nil {
		t.Fatal(err)
	}
	if !known || len(terms) != 1 || terms[0].SourcePort != (flow.Interval{Low: 1024, High: 65535}) {
		t.Fatal("native service lost source port")
	}
}
func TestPANUnsafeBroadAppendFallsBackToNewRuleBeforeNativeBlocker(t *testing.T) {
	raw := zones + "set address old ip-netmask 192.0.2.8/32\nset rulebase security rules web from inside\nset rulebase security rules web to outside\nset rulebase security rules web source old\nset rulebase security rules web destination any\nset rulebase security rules web service any\nset rulebase security rules web application any\nset rulebase security rules web action allow\nset rulebase security rules web log-start no\nset rulebase security rules web log-end no\n"
	fw := pan(t, raw)
	// Match the existing destination/service dimensions so source append is exact.
	b := packet(t).Boxes()[0]
	b.Destination = fw.Address("old").Set().Ranges()[0]
	// A narrow request could not safely extend a rule with unrestricted destination
	// and service: the planner must choose a newly scoped rule instead.
	q, _ := flow.NewTraffic(8, b)
	p, err := (plan.Planner{Renderer: paloalto.Renderer{}}).Plan(context.Background(), fw, []policy.Request{{Traffic: q, FromZone: "inside", ToZone: "outside"}})
	if err != nil {
		t.Fatal(err)
	}
	if p.Changes()[0].Kind != plan.CreateRule {
		t.Fatal("unsafe broad append chosen")
	}
	script := strings.Join(p.Commands(), "\n")
	if !strings.Contains(script, "before \"web\"") {
		t.Fatal("new top placement lost", script)
	}
}

func TestPANAppendCommandsRetainExistingMembersAndRoundTrip(t *testing.T) {
	raw := zones + "set address old ip-netmask 192.0.2.8/32\nset address server ip-netmask 198.51.100.9/32\nset service web protocol tcp port 443\nset service web protocol tcp source-port 1024-65535\nset rulebase security rules web from inside\nset rulebase security rules web to outside\nset rulebase security rules web source old\nset rulebase security rules web destination server\nset rulebase security rules web service web\nset rulebase security rules web application any\nset rulebase security rules web action allow\nset rulebase security rules web log-start no\nset rulebase security rules web log-end no\n"
	fw := pan(t, raw)
	p, err := (plan.Planner{Renderer: paloalto.Renderer{}}).Plan(context.Background(), fw, []policy.Request{{Traffic: packet(t), FromZone: "inside", ToZone: "outside"}})
	if err != nil {
		t.Fatal(err)
	}
	if p.Changes()[0].Kind != plan.AppendMembers {
		t.Fatal("safe native append not selected")
	}
	for _, line := range p.Commands() {
		if strings.HasPrefix(line, "set ") {
			raw += line + "\n"
		}
	}
	observed := pan(t, raw)
	if _, err := p.Verify(context.Background(), observed); err != nil {
		t.Fatal(err)
	}
	if len(observed.Rule("web").Record().Match.Sources) != 2 {
		t.Fatal("set append replaced existing source")
	}
}
