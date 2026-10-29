// Package nativename identifies the native declarations targeted by commands.
// Graph IDs alone do not establish whether two edits target the same object.
package nativename

import (
	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/policy"
)

func Name(object fm.Object) string {
	if object.Name != "" {
		return object.Name
	}
	return string(object.ID)
}

type ObjectKey struct {
	scope, name string
	group       bool
}

func Object(metadata fm.Metadata, object fm.Object, group bool) ObjectKey {
	scope := object.Scope
	if metadata.Vendor == "fortinet" && scope == "" {
		scope = metadata.Context
	}
	// ASA references distinguish object from object-group explicitly.
	return ObjectKey{scope: scope, name: Name(object), group: group && metadata.Vendor == "asa"}
}

type RuleKey struct {
	chain policy.RuleChain
	name  string
}

func Rule(vendor string, rule fm.RuleRecord) RuleKey {
	return RuleKey{chain: policy.NativeRuleOrder(vendor, rule).Chain, name: Name(rule.Object)}
}

// NamedRules reports whether creation addresses rules by native name.
// Numeric rule allocation remains the native renderer's responsibility.
func NamedRules(vendor string) bool {
	return vendor == "paloalto" || vendor == "srx" || vendor == "huawei"
}
