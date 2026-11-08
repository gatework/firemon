package render

import (
	"context"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/internal/names"
	"github.com/gatework/firemon/plan"
)

// Native namespaces, rather than graph IDs, determine what a CLI edit targets.
// Existing names seed the index even when a rule is scheduled for removal: a
// delete/create replacement of the same native identity is not a rule addition.
func (b Batch) validateNames(ctx context.Context, before, after *fm.Firewall) error {
	vendor := before.Metadata().Vendor
	key := func(object fm.Object, group bool) names.ObjectKey {
		return names.Object(before.Metadata(), object, group)
	}
	addresses, services := make(map[names.ObjectKey]bool), make(map[names.ObjectKey]bool)
	for _, a := range before.Addresses() {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !a.Record().Inline && a.Name() != "" {
			addresses[key(a.Record().Object, false)] = true
		}
	}
	for _, g := range before.AddressGroups() {
		if err := ctx.Err(); err != nil {
			return err
		}
		if g.Name() != "" {
			addresses[key(g.Record().Object, true)] = true
		}
	}
	for _, s := range before.Services() {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !s.Record().Inline && s.Name() != "" {
			services[key(s.Record().Object, false)] = true
		}
	}
	for _, g := range before.ServiceGroups() {
		if err := ctx.Err(); err != nil {
			return err
		}
		if g.Name() != "" {
			services[key(g.Record().Object, true)] = true
		}
	}
	for _, a := range after.Addresses() {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !b.DeclaresAddress(a.ID()) {
			continue
		}
		if !declarationIdentity(vendor, a.Record().Object) {
			return plan.ErrRender
		}
		k := key(a.Record().Object, false)
		if addresses[k] {
			return plan.ErrRender
		}
		addresses[k] = true
	}
	for _, s := range after.Services() {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !b.DeclaresService(s.ID()) {
			continue
		}
		if !declarationIdentity(vendor, s.Record().Object) {
			return plan.ErrRender
		}
		k := key(s.Record().Object, false)
		if services[k] {
			return plan.ErrRender
		}
		services[k] = true
	}
	if !names.NamedRules(vendor) {
		return ctx.Err()
	}
	rules := make(map[names.RuleKey]bool)
	ruleKey := func(rule fm.RuleRecord) names.RuleKey {
		return names.Rule(vendor, rule)
	}
	for _, r := range before.Rules() {
		if err := ctx.Err(); err != nil {
			return err
		}
		if r.Name() != "" {
			rules[ruleKey(r.Record())] = true
		}
	}
	for _, c := range b.changes {
		if err := ctx.Err(); err != nil {
			return err
		}
		if c.Kind != plan.CreateRule {
			continue
		}
		r := after.Rule(c.Rule).Record()
		if r.Name == "" {
			return plan.ErrRender
		}
		k := ruleKey(r)
		if rules[k] {
			return plan.ErrRender
		}
		rules[k] = true
	}
	return ctx.Err()
}

// New inline values have no independent declaration. Global object emitters must
// preserve the identity their parser reconstructs from the native object name.
func declarationIdentity(vendor string, object fm.Object) bool {
	if object.Inline || object.Name == "" {
		return false
	}
	switch vendor {
	case "paloalto", "asa", "hillstone":
		return object.Scope == "" && object.ID == fm.ID(object.Name)
	default:
		return true // Scoped native adapters validate their own identity scheme.
	}
}
