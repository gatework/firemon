package render

import (
	"context"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/policy"
)

func nativeName(o fm.Object) string {
	if o.Name != "" {
		return o.Name
	}
	return string(o.ID)
}

// Native namespaces, rather than graph IDs, determine what a CLI edit targets.
// Existing names seed the index even when a rule is scheduled for removal: a
// delete/create replacement of the same native identity is not a rule addition.
func (b batch) validateNames(ctx context.Context, before, after *fm.Firewall) error {
	vendor := before.Metadata().Vendor
	type objectName struct {
		scope, name string
		group       bool
	}
	key := func(o fm.Object, group bool) objectName {
		scope := o.Scope
		if vendor == "fortinet" && scope == "" {
			scope = before.Metadata().Context
		}
		// ASA references distinguish object from object-group explicitly.
		return objectName{scope, nativeName(o), group && vendor == "asa"}
	}
	addresses, services := make(map[objectName]bool), make(map[objectName]bool)
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
	if vendor != "paloalto" && vendor != "srx" {
		return ctx.Err()
	}
	type ruleName struct {
		chain policy.RuleChain
		name  string
	}
	rules := make(map[ruleName]bool)
	ruleKey := func(r fm.RuleRecord) ruleName {
		return ruleName{policy.NativeRuleOrder(vendor, r).Chain, nativeName(r.Object)}
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
		return object.Scope == "" && object.ID == fm.ID(nativeName(object))
	default:
		return true // Scoped native adapters validate their own identity scheme.
	}
}
