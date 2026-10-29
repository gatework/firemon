package analysis_test

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/analysis"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/policy"
	"github.com/gatework/firemon/vendors/asa"
	"github.com/gatework/firemon/vendors/fortinet"
	"github.com/gatework/firemon/vendors/hillstone"
	"github.com/gatework/firemon/vendors/paloalto"
)

func translationGraphs(t *testing.T) (*fm.Firewall, *fm.Firewall) {
	t.Helper()
	d := graph(t, [][2]string{{"192.0.2.1", "198.51.100.1"}, {"192.0.2.2", "198.51.100.1"}}).Export()
	d.Metadata.Vendor = "paloalto"
	d.Zones = []fm.ZoneRecord{{Object: fm.Object{ID: "inside"}}, {Object: fm.Object{ID: "outside"}}}
	term := request(t, "192.0.2.1", "198.51.100.1").Traffic.Boxes()[0]
	d.Services = []fm.ServiceRecord{{Object: fm.Object{ID: "web"}, Terms: []fm.ServiceTerm{{Protocol: term.Protocol, SourcePort: term.SourcePort, DestinationPort: term.DestinationPort, ICMPType: term.ICMPType, ICMPCode: term.ICMPCode}}}}
	d.Rules[0].Action = fm.Drop
	// The permit declares both hosts; only the second survives the earlier drop.
	d.Rules[1].Match.Sources = append(d.Rules[1].Match.Sources, d.Rules[0].Match.Sources...)
	for i := range d.Rules {
		m := &d.Rules[i].Match
		m.AnyFromZone, m.AnyToZone, m.AnyService = false, false, false
		m.FromZones, m.ToZones = []fm.ID{"inside"}, []fm.ID{"outside"}
		m.Services = []fm.ServiceRef{{Kind: fm.ServiceObject, ID: "web"}}
	}
	source, err := fm.Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	target, err := fm.Seal(fm.Data{Metadata: fm.Metadata{Device: "target", Vendor: "paloalto"}, Zones: []fm.ZoneRecord{{Object: fm.Object{ID: "trust"}}, {Object: fm.Object{ID: "untrust"}}}})
	if err != nil {
		t.Fatal(err)
	}
	return source, target
}

func TestTranslationExplicitASAIngressChainAllowsOmittedTargetDestinationZone(t *testing.T) {
	ctx := context.Background()
	interfaces := `interface GigabitEthernet0/0
 nameif inside
 security-level 100
 ip address 192.0.2.254 255.255.255.0
!
interface GigabitEthernet0/1
 nameif outside
 security-level 0
 ip address 198.51.100.254 255.255.255.0
!
`
	parse := func(raw, device string) *fm.Firewall {
		t.Helper()
		fw, err := asa.Parse(ctx, config.Source{Text: raw, Complete: true}, fm.Metadata{Device: device})
		if err != nil || !fw.Complete() {
			t.Fatalf("ASA native capture: %v, %v", err, fw.Diagnostics())
		}
		return fw
	}
	source := parse(interfaces+"access-list IN extended permit tcp host 192.0.2.1 host 198.51.100.1 eq 443\naccess-group IN in interface inside\n", "source")
	raw := interfaces + "access-list TARGET extended deny ip any4 any4\naccess-group TARGET in interface inside\naccess-list OTHER extended deny ip any4 any4\naccess-group OTHER in interface outside\n"
	target := parse(raw, "target")
	x := analysis.PolicyMigrator{Planner: plan.Planner{Renderer: asa.Renderer{}}}
	migration := analysis.MigrationRequest{Zones: map[fm.ID]fm.ID{"inside": "inside", "outside": ""}, Chains: map[fm.PolicyChain]fm.PolicyChain{{RuleSet: "IN"}: {RuleSet: "TARGET"}}, Pairs: []analysis.ZonePair{{From: "inside", To: "outside"}}}
	p, err := x.Plan(ctx, source, target, migration)
	if err != nil {
		t.Fatalf("explicit native ACL mapping must render: %v", err)
	}
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
		case strings.HasPrefix(command, "access-list TARGET line 1 extended "):
			entries = append(entries, strings.Replace(command, " line 1 ", " ", 1))
		case inObject:
			objects = append(objects, " "+command)
		default:
			t.Fatalf("unexpected ACL command: %s", command)
		}
	}
	if len(entries) != 1 {
		t.Fatalf("wrong target ACL: %v", p.Commands())
	}
	observed := parse(strings.Join(objects, "\n")+"\n"+strings.Join(entries, "\n")+"\n"+raw, "target")
	if _, err := p.Verify(ctx, observed); err != nil {
		t.Fatalf("independent ASA readback: %v", err)
	}
	q := request(t, "192.0.2.1", "198.51.100.1")
	q.RuleSet, q.FromZone, q.ToZone = "TARGET", "inside", "outside"
	r, err := (policy.Engine{}).Query(ctx, observed, q)
	if err != nil || !r.Complete || r.Allowed.Empty() {
		t.Fatal(r, err)
	}
	q.RuleSet, q.FromZone = "OTHER", "outside"
	r, err = (policy.Engine{}).Query(ctx, observed, q)
	if err != nil || !r.Complete || !r.Allowed.Empty() {
		t.Fatalf("unselected ACL changed: %v, %v", r, err)
	}
	delete(migration.Zones, "outside")
	if _, err := x.Plan(ctx, source, target, migration); !errors.Is(err, analysis.ErrInvalid) {
		t.Fatalf("absent destination mapping was guessed: %v", err)
	}
}

func TestTranslationRequiresExplicitAmbiguousChainMapping(t *testing.T) {
	source, target := translationGraphs(t)
	d := target.Export()
	d.Metadata.Vendor = "hillstone"
	// Hillstone derives the native VRF from the referenced zones.
	for i := range d.Zones {
		d.Zones[i].Scope = "red"
	}
	for i, scope := range []string{"blue", "red"} {
		d.Rules = append(d.Rules, fm.RuleRecord{Object: fm.Object{ID: fm.ID(scope), Scope: scope}, Position: i, RuleSet: "security", Builtin: true, Action: fm.Drop, Log: fm.Irrelevant, LogStart: fm.Irrelevant, LogEnd: fm.Irrelevant, Match: fm.Match{AnySource: true, AnyDestination: true, AnyService: true, AnyFromZone: true, AnyToZone: true}})
	}
	var err error
	target, err = fm.Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	x := analysis.PolicyMigrator{Planner: plan.Planner{Renderer: hillstone.Renderer{}}}
	migration := analysis.MigrationRequest{Zones: map[fm.ID]fm.ID{"inside": "trust", "outside": "untrust"}, Pairs: []analysis.ZonePair{{From: "inside", To: "outside"}}, Rules: []fm.ID{"2"}}
	if _, err := x.Plan(context.Background(), source, target, migration); !errors.Is(err, analysis.ErrInvalid) {
		t.Fatalf("ambiguous target chain must require mapping: %v", err)
	}
	migration.Chains = map[fm.PolicyChain]fm.PolicyChain{{RuleSet: "security"}: {Scope: "red", RuleSet: "security"}}
	p, err := x.Plan(context.Background(), source, target, migration)
	if err != nil {
		t.Fatal(err)
	}
	q := request(t, "192.0.2.2", "198.51.100.1")
	q.FromZone, q.ToZone = "trust", "untrust"
	for _, scope := range []string{"blue", "red"} {
		q.Scope = scope
		r, err := (policy.Engine{}).Query(context.Background(), p.After(), q)
		if err != nil || !r.Complete || (!r.Allowed.Empty()) != (scope == "red") {
			t.Fatalf("wrong chain %s: %v, %v", scope, r, err)
		}
	}
	d.Metadata.Vendor = "asa"
	target, err = fm.Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	migration.Chains = nil
	if _, err := x.Plan(context.Background(), source, target, migration); !errors.Is(err, analysis.ErrInvalid) {
		t.Fatalf("ASA chain must require mapping: %v", err)
	}
}

func TestTranslationInfersNativeFortinetSelectedContextAndVerifiesReadback(t *testing.T) {
	ctx := context.Background()
	topology := `config system interface
edit "inside"
set vdom "root"
set ip 192.0.2.254 255.255.255.0
next
edit "outside"
set vdom "root"
set ip 198.51.100.254 255.255.255.0
next
end
`
	native := topology + `config firewall address
edit "client"
set subnet 192.0.2.1 255.255.255.255
next
edit "server"
set subnet 198.51.100.1 255.255.255.255
next
end
config firewall service custom
edit "https"
set tcp-portrange 443
next
end
config firewall policy
edit 10
set srcintf "inside"
set dstintf "outside"
set srcaddr "client"
set dstaddr "server"
set service "https"
set action accept
set schedule "always"
set logtraffic disable
next
end
`
	parse := func(text, device string) *fm.Firewall {
		t.Helper()
		fw, err := fortinet.Parse(ctx, config.Source{Text: text, Complete: true}, fm.Metadata{Device: device})
		if err != nil || !fw.Complete() {
			t.Fatalf("native capture: %v, %v", err, fw.Diagnostics())
		}
		return fw
	}
	source, target := parse(native, "source"), parse(topology, "target")
	x := analysis.PolicyMigrator{Planner: plan.Planner{Renderer: fortinet.Renderer{}}}
	migration := analysis.MigrationRequest{Zones: map[fm.ID]fm.ID{"inside": "inside", "outside": "outside"}, Pairs: []analysis.ZonePair{{From: "inside", To: "outside"}}}
	p, err := x.Plan(ctx, source, target, migration)
	if err != nil {
		t.Fatalf("native no-NAT migration must select root/security: %v", err)
	}
	observed := parse(topology+strings.Join(p.Commands(), "\n")+"\n", "target")
	if _, err := p.Verify(ctx, observed); err != nil {
		t.Fatalf("independent native readback: %v", err)
	}
	q := request(t, "192.0.2.1", "198.51.100.1")
	q.Scope, q.FromZone, q.ToZone = "root", "inside", "outside"
	r, err := (policy.Engine{}).Query(ctx, observed, q)
	if err != nil || r.Allowed.Empty() {
		t.Fatalf("mapped native chain has no permit: %v, %v", r, err)
	}
}

func TestTranslationUsesEffectivePartitionsAndExplicitZoneMapping(t *testing.T) {
	source, target := translationGraphs(t)
	x := analysis.PolicyMigrator{Planner: plan.Planner{Renderer: paloalto.Renderer{}}}
	migration := analysis.MigrationRequest{Zones: map[fm.ID]fm.ID{"inside": "trust", "outside": "untrust"}, Pairs: []analysis.ZonePair{{From: "inside", To: "outside"}}}
	p, err := x.Plan(context.Background(), source, target, migration)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		src     string
		allowed bool
	}{{"192.0.2.1", false}, {"192.0.2.2", true}} {
		q := request(t, tc.src, "198.51.100.1")
		q.FromZone, q.ToZone = "trust", "untrust"
		r, err := (policy.Engine{}).Query(context.Background(), p.After(), q)
		if err != nil || !r.Complete || (!r.Allowed.Empty()) != tc.allowed {
			t.Fatal(tc, r, err)
		}
	}
	if p.Proof().TargetAllowed || !p.Proof().TargetSatisfied {
		t.Fatal("drop partition discarded", p.Proof())
	}
	if _, err := p.Verify(context.Background(), p.After()); err != nil {
		t.Fatal(err)
	}
	if source.Rule("2").Record().Match.Sources[0].ID != "192.0.2.2" {
		t.Fatal("source graph mutated")
	}
}

func TestTranslationRejectsNATAndImplicitZoneMerging(t *testing.T) {
	source, target := translationGraphs(t)
	x := analysis.PolicyMigrator{Planner: plan.Planner{Renderer: paloalto.Renderer{}}}
	migration := analysis.MigrationRequest{Zones: map[fm.ID]fm.ID{"inside": "trust", "outside": "trust"}, Pairs: []analysis.ZonePair{{From: "inside", To: "outside"}}}
	if _, err := x.Plan(context.Background(), source, target, migration); err == nil {
		t.Fatal("implicit zone merge accepted")
	}
	migration.Zones["outside"] = "untrust"
	d := source.Export()
	a := netip.MustParseAddr("192.0.2.1")
	b := netip.MustParseAddr("203.0.113.1")
	d.StaticNATs = []fm.StaticNATRecord{{Object: fm.Object{ID: "nat"}, Source: []fm.Mapping{{Original: flow.Range{First: a, Last: a}, Translated: flow.Range{First: b, Last: b}, Mode: fm.Offset}}}}
	withNAT, err := fm.Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := x.Plan(context.Background(), withNAT, target, migration); err == nil {
		t.Fatal("NAT semantics silently omitted from translation")
	}
}
