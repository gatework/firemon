package hillstone_test

import (
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/converge"
	"github.com/gatework/firemon/design"
	"github.com/gatework/firemon/vendors/hillstone"
)

// Disabled NAT rules and their descriptions survive rendering: a migrated
// disabled rule must not come up enabled.
func TestRender_DisabledNATReadsBack(t *testing.T) {
	t.Parallel()
	in := natIntent(t, "10.0.7.0/24", "192.0.2.10", "tcp/443", design.NATIntent{Mode: design.NATModeSource, Address: netip.MustParseAddr("198.51.100.77")})
	p, _ := natPlan(t, natOrderConf, in)
	n := 0
	for i, c := range p.Changes {
		if a, ok := c.(design.AddNAT); ok {
			a.Rule.Disabled, a.Rule.Description = true, "migrated, kept off"
			p.Changes[i] = a
			n++
		}
	}
	if n == 0 {
		t.Fatal("the intent needs a NAT rule")
	}
	script, err := hillstone.Renderer{}.Render(p)
	if err != nil {
		t.Fatal(err)
	}
	predicted := mustParse(t, hillstone.Options{}, natOrderConf)
	if err := design.Apply(predicted, p.Changes); err != nil {
		t.Fatal(err)
	}
	got := compileText(t, natOrderConf+strings.Join(script.Commands, "\n")+"\n")
	if got.Fingerprint() != compileConfig(t, predicted).Fingerprint() {
		t.Fatalf("disabled NAT reads back differently:\n%s", strings.Join(script.Commands, "\n"))
	}
}

// nestedConf holds unused groups three levels deep, the outermost declared
// last, and a schedule only a policy route uses.
const nestedConf = `zone "inside"
exit
zone "outside"
exit
address "h1"
  ip 203.0.113.1/32
exit
address "inner"
  member "h1"
exit
address "outer"
  member "inner"
exit
schedule "night"
  periodic daily 00:00:00 to 06:00:00
exit
pbr-policy "p" vrouter "trust-vr"
  match id 1
    src-ip 10.9.0.0/16
    schedule "night"
    nexthop 10.0.0.1
  exit
exit
rule id 1
  action permit
  src-zone "inside"
  dst-zone "outside"
  src-addr "Any"
  dst-addr "Any"
  service "HTTPS"
exit
`

// Unused nested groups delete outermost first, so the device never sees a
// member removed while a group still holds it; the rollback recreates
// them; a schedule only a policy route uses is not unused.
func TestConverge_NestedGroupsDeleteInOrder(t *testing.T) {
	t.Parallel()
	fw := compileText(t, nestedConf)
	rep := converge.Analyze(fw, converge.Options{Now: convergeNow})
	var order []string
	for _, f := range rep.Findings {
		if f.Category == converge.CategoryUnusedObject {
			order = append(order, f.Objects[0].Name)
		}
	}
	if strings.Join(order, ",") != "outer,inner,h1" {
		t.Fatalf("unused objects %v, want outer,inner,h1 (night is used by the policy route)", order)
	}
	plan, err := converge.Plan(fw, rep, converge.Selection{}, converge.PlanOptions{Now: convergeNow})
	if err != nil || !plan.Verified {
		t.Fatalf("plan: %v %+v", err, plan)
	}
	script, err := hillstone.Renderer{}.Render(plan)
	if err != nil {
		t.Fatal(err)
	}
	got := compileText(t, nestedConf+strings.Join(script.Commands, "\n")+"\n")
	if slices.ContainsFunc(got.Config().Addresses, func(a firemon.Address) bool { return a.Name == "h1" }) {
		t.Fatalf("h1 survived:\n%s", strings.Join(script.Commands, "\n"))
	}
	back := compileText(t, nestedConf+strings.Join(script.Commands, "\n")+"\n"+strings.Join(script.Rollback, "\n")+"\n")
	if back.Fingerprint() != fw.Fingerprint() {
		t.Fatalf("rollback does not restore:\n%s", strings.Join(script.Rollback, "\n"))
	}

	// Deleting a member before its group is refused.
	cfg := mustParse(t, hillstone.Options{}, nestedConf)
	h1 := cfg.Addresses[0]
	if err := design.Apply(cfg, []design.Change{design.DeleteAddress{Address: h1}}); !errors.Is(err, design.ErrInUse) {
		t.Fatalf("deleting h1 while inner holds it: %v", err)
	}
}

// A report of another configuration is refused, not applied.
func TestConverge_StaleReportRefused(t *testing.T) {
	t.Parallel()
	rep := converge.Analyze(compileText(t, convergeConf), converge.Options{Now: convergeNow})
	changed := compileText(t, convergeConf+`rule id 10
  action deny
  src-zone "inside"
  dst-zone "outside"
  src-addr "Any"
  dst-addr "Any"
  service "Any"
exit
`)
	if _, err := converge.Plan(changed, rep, converge.Selection{}, converge.PlanOptions{Now: convergeNow}); !errors.Is(err, converge.ErrStaleReport) {
		t.Fatalf("stale report: %v", err)
	}
}

// A tracked next hop forwards only while its track object is up: the
// entry cannot be decided offline.
func TestPBR_TrackedNextHopIsConditional(t *testing.T) {
	t.Parallel()
	fw := compileText(t, `zone "inside"
exit
interface ethernet0/1
  zone "inside"
  ip address 10.0.0.2/24
exit
pbr-policy "p" vrouter "trust-vr"
  match id 1
    src-ip 10.9.0.0/16
    nexthop 10.0.0.1 track "t1"
  exit
exit
`)
	routes := fw.Config().PolicyRoutes
	if len(routes) != 1 || len(routes[0].Conditions) != 1 || routes[0].Conditions[0].Raw != "nexthop 10.0.0.1 track t1" {
		t.Fatalf("policy routes %+v", routes)
	}
}
