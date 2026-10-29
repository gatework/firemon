package hillstone_test

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/policy"
	"github.com/gatework/firemon/vendors/hillstone"
)

func TestPlannerRendersNativeHillstoneAppendWithExactSourcePorts(t *testing.T) {
	fw := parse(t, "address a\nip 192.0.2.1/32\nexit\naddress b\nip 198.51.100.1/32\nexit\nservice https\ntcp dst-port 443 443 src-port 1024 65535\nexit\npolicy-global\nrule id 10\nsrc-addr a\ndst-addr b\nservice https\naction permit\nexit\nexit\n")
	src, _ := flow.PrefixRange(netip.MustParsePrefix("192.0.2.2/32"))
	dst, _ := flow.PrefixRange(netip.MustParsePrefix("198.51.100.1/32"))
	traffic, _ := flow.NewTraffic(32, flow.Box{Source: src, Destination: dst, Protocol: flow.Interval{Low: 6, High: 6}, SourcePort: flow.Interval{Low: 1024, High: 65535}, DestinationPort: flow.Interval{Low: 443, High: 443}, ICMPType: flow.Interval{Low: 0, High: 255}, ICMPCode: flow.Interval{Low: 0, High: 255}})
	result, err := (plan.Planner{Renderer: hillstone.Renderer{}}).Plan(context.Background(), fw, []policy.Request{{Traffic: traffic}})
	if err != nil {
		t.Fatal(err)
	}
	script := strings.Join(result.Commands(), "\n")
	if !strings.Contains(script, "rule id 10") || !strings.Contains(script, "src-addr \"fm-a-") || result.Changes()[0].Kind != plan.AppendMembers {
		t.Fatal(script)
	}
	if strings.Contains(script, "save") {
		t.Fatal("renderer performed persistence outside deploy save phase")
	}
}
func TestRendererRejectsControlCharactersInNativeNames(t *testing.T) {
	before, _ := fm.Seal(fm.Data{Metadata: fm.Metadata{Device: "fw", Vendor: "hillstone"}})
	d := before.Export()
	d.Addresses = append(d.Addresses, fm.AddressRecord{Object: fm.Object{ID: "bad\nexit"}})
	after, _ := fm.Seal(d)
	if _, err := (hillstone.Renderer{}).Render(context.Background(), before, after, []plan.Change{{Kind: plan.CreateRule, Rule: "missing"}}); err == nil {
		t.Fatal("unsafe name rendered")
	}
}

func TestRendererRejectsCreationAfterSurvivingRule(t *testing.T) {
	before := parse(t, "policy-global\nrule id 10\nsrc-addr any\ndst-addr any\nservice any\naction permit\nexit\nexit\n")
	data := before.Export()
	r := data.Rules[0]
	r.ID = "new"
	r.Position = 100
	data.Rules = append(data.Rules, r)
	after, err := fm.Seal(data)
	if err != nil {
		t.Fatal(err)
	}
	change := plan.Change{Kind: plan.CreateRule, Rule: r.ID, Sources: r.Match.Sources, Destinations: r.Match.Destinations, Services: r.Match.Services}
	if commands, err := (hillstone.Renderer{}).Render(context.Background(), before, after, []plan.Change{change}); !errors.Is(err, plan.ErrRender) || commands != nil {
		t.Fatalf("top-only renderer accepted trailing rule: %v %v", commands, err)
	}
}

func TestRendererEmitsExplicitAnyMembers(t *testing.T) {
	before, _ := fm.Seal(fm.Data{Metadata: fm.Metadata{Device: "fw", Vendor: "hillstone"}})
	d := before.Export()
	d.Rules = []fm.RuleRecord{{Object: fm.Object{ID: "new"}, RuleSet: "security", Action: fm.Permit, Log: fm.Irrelevant, LogStart: fm.Irrelevant, LogEnd: fm.Irrelevant, Match: fm.Match{AnySource: true, AnyDestination: true, AnyService: true, AnyFromZone: true, AnyToZone: true}}}
	after, _ := fm.Seal(d)
	commands, err := (hillstone.Renderer{}).Render(context.Background(), before, after, []plan.Change{{Kind: plan.CreateRule, Rule: "new"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"src-addr any", "dst-addr any", "service any"} {
		if !slices.Contains(commands, want) {
			t.Fatalf("missing %q: %v", want, commands)
		}
	}
}
