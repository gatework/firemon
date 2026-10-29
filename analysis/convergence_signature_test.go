package analysis

import (
	"reflect"
	"testing"

	fm "github.com/gatework/firemon"
)

func TestConvergenceSignatureMatchesStructuralCompatibility(t *testing.T) {
	base := fm.RuleRecord{Object: fm.Object{Scope: "native"}, RuleSet: "security"}
	changes := []struct {
		name   string
		change func(*fm.RuleRecord)
	}{
		{"scope", func(r *fm.RuleRecord) { r.Scope = "other" }},
		{"chain", func(r *fm.RuleRecord) { r.RuleSet = "acl" }},
		{"action", func(r *fm.RuleRecord) { r.Action = fm.Permit }},
		{"disabled", func(r *fm.RuleRecord) { r.Disabled = true }},
		{"log", func(r *fm.RuleRecord) { r.Log = fm.Known }},
		{"start", func(r *fm.RuleRecord) { r.LogStart = fm.Known }},
		{"end", func(r *fm.RuleRecord) { r.LogEnd = fm.Known }},
		{"vip", func(r *fm.RuleRecord) { r.MatchVIP = fm.Known }},
		{"builtin", func(r *fm.RuleRecord) { r.Builtin = true }},
		{"description", func(r *fm.RuleRecord) { r.Description = "different" }},
		{"empty zones", func(r *fm.RuleRecord) { r.Match.FromZones = []fm.ID{} }},
		{"empty destination zones", func(r *fm.RuleRecord) { r.Match.ToZones = []fm.ID{} }},
		{"empty applications", func(r *fm.RuleRecord) { r.Match.Applications = []string{} }},
		{"empty users", func(r *fm.RuleRecord) { r.Match.Users = []string{} }},
		{"empty unsupported", func(r *fm.RuleRecord) { r.Match.Unsupported = []string{} }},
		{"schedule", func(r *fm.RuleRecord) { r.Match.Schedule = "time" }},
		{"relation", func(r *fm.RuleRecord) { r.Match.ZoneRelation = fm.SameZone }},
		{"any source", func(r *fm.RuleRecord) { r.Match.AnySource = true }},
		{"any destination", func(r *fm.RuleRecord) { r.Match.AnyDestination = true }},
		{"any service", func(r *fm.RuleRecord) { r.Match.AnyService = true }},
		{"any ingress", func(r *fm.RuleRecord) { r.Match.AnyFromZone = true }},
		{"any egress", func(r *fm.RuleRecord) { r.Match.AnyToZone = true }},
		{"identity and operands ignored", func(r *fm.RuleRecord) {
			r.ID = "other"
			r.Name = "name"
			r.Position = 20
			r.Match.Sources = []fm.AddressRef{{ID: "source"}}
		}},
	}
	for _, tc := range changes {
		t.Run(tc.name, func(t *testing.T) {
			other := base
			tc.change(&other)
			a, b := convergenceSignature(base), convergenceSignature(other)
			if got, want := sameConvergenceSignature(a, b), reflect.DeepEqual(a, b); got != want {
				t.Fatalf("compatibility=%v want %v", got, want)
			}
		})
	}
}
