package design_test

import (
	"testing"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/design"
)

// A rule asked for without a name is named after the day, numbered after
// the day's rules the firewall already has, and described after its name.
func TestPlanner_DatedRuleNames(t *testing.T) {
	t.Parallel()
	in := intent(t, "10.0.1.5", "172.16.0.10", "tcp/443")
	in.Name = ""
	newRule := func(cfg *firemon.Config) firemon.SecurityRule {
		p := plan(t, cfg, in)
		add, ok := p.Changes[len(p.Changes)-1].(design.AddRule)
		if !ok {
			t.Fatalf("changes %v", p.Changes)
		}
		return add.Rule
	}
	if r := newRule(lab()); r.Name != "P-20261117-001" || r.Description != "P-20261117-001-By-Firemon" {
		t.Fatalf("first rule of the day: %q %q", r.Name, r.Description)
	}
	existing := firemon.SecurityRule{ID: "9", Name: "P-20261117-004", Action: firemon.ActionDeny, From: []string{"dmz"}, To: []string{"untrust"}}
	if r := newRule(lab(existing)); r.Name != "P-20261117-005" {
		t.Fatalf("after the day's rule 004: %q", r.Name)
	}
}
