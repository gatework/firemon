package firemon_test

import (
	"testing"

	fm "github.com/gatework/firemon"
)

func TestRuleAndNATShareImmutableMatchView(t *testing.T) {
	d := seed()
	m := fm.Match{Sources: []fm.AddressRef{{Kind: fm.AddressObject, ID: "host"}}, FromZones: []fm.ID{"inside"}, AnyDestination: true, AnyService: true, AnyToZone: true}
	d.Rules = []fm.RuleRecord{{Object: fm.Object{ID: "rule", Name: "allow", Scope: "vr1"}, Match: m, Action: fm.Permit, RuleSet: "security", Position: 7}}
	d.StaticNATs[0].Match = m
	d.DynamicNATs[0].Match = m
	fw, err := fm.Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	r := fw.Rule("rule")
	if r.ID() != "rule" || r.Name() != "allow" || r.Scope() != "vr1" || r.Position() != 7 || r.Chain() != (fm.PolicyChain{Scope: "vr1", RuleSet: "security"}) {
		t.Fatal("domain identity differs from declaration")
	}
	for _, owner := range []interface{ Match() fm.MatchObjects }{r, fw.StaticNAT("static"), fw.DynamicNAT("dynamic")} {
		m := owner.Match()
		if m.Sources()[0] != fw.Address("host") || m.FromZones()[0] != fw.Zone("inside") {
			t.Fatal("references are not shared")
		}
		m.Sources()[0] = nil
		m.FromZones()[0] = nil
		if owner.Match().Sources()[0] != fw.Address("host") || owner.Match().FromZones()[0] != fw.Zone("inside") {
			t.Fatal("mutable match container")
		}
	}
	if r.Sources()[0] != r.Match().Sources()[0] {
		t.Fatal("direct and shared views differ")
	}
}
