package hillstone_test

import (
	"slices"
	"testing"

	"github.com/gatework/firemon"
)

// TestRule_ConditionsAndInspection: StoneOS criteria map to condition
// kinds, inspection is kept as written, and both survive a round trip.
func TestRule_ConditionsAndInspection(t *testing.T) {
	t.Parallel()
	fw := compileText(t, `rule id 1
  action permit
  src-zone "trust"
  dst-zone "untrust"
  src-addr "Any"
  dst-addr "Any"
  service "HTTPS"
  application "HTTPS"
  domain-book "white"
  role "ops"
  vlan-id 100
  ips "default"
  av "strict"
exit
`)
	r := fw.Config().Rules[0]
	var kinds []firemon.ConditionKind
	for _, c := range r.Conditions {
		kinds = append(kinds, c.Kind)
	}
	want := []firemon.ConditionKind{firemon.ConditionApplication, firemon.ConditionDomain, firemon.ConditionUser, firemon.ConditionOther}
	if !slices.Equal(kinds, want) || !slices.Equal(r.Conditions[1].Values, []string{"white"}) {
		t.Fatalf("conditions %+v", r.Conditions)
	}
	if !slices.Equal(r.Inspection, []string{"ips default", "av strict"}) {
		t.Fatalf("inspection %v", r.Inspection)
	}
	if fw.Rules()[0].Decidable() {
		t.Fatal("domain, user and vlan conditions cannot be decided offline")
	}
}
