package hillstone_test

import (
	"context"
	"net/netip"
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
