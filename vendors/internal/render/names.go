package render

import (
	"context"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/internal/nativename"
	"github.com/gatework/firemon/plan"
)

// Native namespaces, rather than graph IDs, determine what a CLI edit targets.
// Existing names seed the index even when a rule is scheduled for removal: a
// delete/create replacement of the same native identity is not a rule addition.
func (b batch) validateNames(ctx context.Context, before, after *fm.Firewall) error {
	vendor := before.Metadata().Vendor
	key := func(object fm.Object, group bool) nativename.ObjectKey {
		return nativename.Object(before.Metadata(), object, group)
	}
	addresses, services := make(map[nativename.ObjectKey]bool), make(map[nativename.ObjectKey]bool)
	for _, a := range before.Addresses() {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !a.Record().Inline {
			addresses[key(a.Record().Object, false)] = true
		}
	}
	for _, g := range before.AddressGroups() {
		if err := ctx.Err(); err != nil {
			return err
		}
		addresses[key(g.Record().Object, true)] = true
	}
	for _, s := range before.Services() {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !s.Record().Inline {
			services[key(s.Record().Object, false)] = true
		}
	}
	for _, g := range before.ServiceGroups() {
		if err := ctx.Err(); err != nil {
			return err
		}
		services[key(g.Record().Object, true)] = true
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
	if !nativename.NamedRules(vendor) {
		return ctx.Err()
	}
	rules := make(map[nativename.RuleKey]bool)
	ruleKey := func(rule fm.RuleRecord) nativename.RuleKey {
		return nativename.Rule(vendor, rule)
	}
	for _, r := range before.Rules() {
		if err := ctx.Err(); err != nil {
			return err
		}
		rules[ruleKey(r.Record())] = true
	}
	for _, c := range b.changes {
		if err := ctx.Err(); err != nil {
			return err
		}
		if c.Kind != plan.CreateRule {
			continue
		}
		k := ruleKey(after.Rule(c.Rule).Record())
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
	if object.Inline {
		return false
	}
	switch vendor {
	case "paloalto", "asa", "hillstone":
		return object.Scope == "" && object.ID == fm.ID(nativename.Name(object))
	default:
		return true // Scoped native adapters validate their own identity scheme.
	}
}
