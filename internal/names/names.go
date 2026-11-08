// Package names identifies firewall objects and policies within their scopes.
// Configuration names are separate from internal graph IDs.
package names

import (
	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/policy"
)

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
	return ObjectKey{scope: scope, name: object.Name, group: group && metadata.Vendor == "asa"}
}

type RuleKey struct {
	chain policy.RuleChain
	name  string
	id    fm.ID
}

func Rule(vendor string, rule fm.RuleRecord) RuleKey {
	key := RuleKey{chain: policy.NativeRuleOrder(vendor, rule).Chain}
	if NamedRules(vendor) {
		key.name = rule.Name
	} else {
		key.id = rule.ID
	}
	return key
}

// NamedRules reports whether creation addresses rules by native name.
// Numeric rule allocation remains the native renderer's responsibility.
func NamedRules(vendor string) bool {
	return vendor == "paloalto" || vendor == "srx" || vendor == "huawei"
}
