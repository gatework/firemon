package analysis_test

import (
	"context"
	"net/netip"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/analysis"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/policy"
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

func TestTranslationUsesEffectivePartitionsAndExplicitZoneMapping(t *testing.T) {
	source, target := translationGraphs(t)
	x := analysis.Translator{Planner: plan.Planner{Renderer: paloalto.Renderer{}}, Zones: map[fm.ID]fm.ID{"inside": "trust", "outside": "untrust"}}
	p, err := x.Plan(context.Background(), source, target, []analysis.ZonePair{{From: "inside", To: "outside"}}, nil)
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
	x := analysis.Translator{Planner: plan.Planner{Renderer: paloalto.Renderer{}}, Zones: map[fm.ID]fm.ID{"inside": "trust", "outside": "trust"}}
	if _, err := x.Plan(context.Background(), source, target, []analysis.ZonePair{{From: "inside", To: "outside"}}, nil); err == nil {
		t.Fatal("implicit zone merge accepted")
	}
	x.Zones["outside"] = "untrust"
	d := source.Export()
	a := netip.MustParseAddr("192.0.2.1")
	b := netip.MustParseAddr("203.0.113.1")
	d.StaticNATs = []fm.StaticNATRecord{{Object: fm.Object{ID: "nat"}, Source: []fm.Mapping{{Original: flow.Range{First: a, Last: a}, Translated: flow.Range{First: b, Last: b}, Mode: fm.Offset}}}}
	withNAT, err := fm.Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := x.Plan(context.Background(), withNAT, target, []analysis.ZonePair{{From: "inside", To: "outside"}}, nil); err == nil {
		t.Fatal("NAT semantics silently omitted from translation")
	}
}
