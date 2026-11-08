package names_test

import (
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/internal/names"
)

func TestObjectNamespaceIdentity(t *testing.T) {
	object := fm.Object{ID: "id", Name: "web"}
	for _, vendor := range []string{"paloalto", "srx", "huawei", "hillstone", "fortinet", "netscreen", "asa"} {
		metadata := fm.Metadata{Vendor: vendor, Context: "root"}
		if equal := names.Object(metadata, object, false) == names.Object(metadata, object, true); equal == (vendor == "asa") {
			t.Fatalf("object/group namespace: %s", vendor)
		}
		local := object
		local.Scope = "root"
		if equal := names.Object(metadata, object, false) == names.Object(metadata, local, false); equal != (vendor == "fortinet") {
			t.Fatalf("context resolution: %s", vendor)
		}
		alias := object
		alias.ID = "different-graph-id"
		if names.Object(metadata, object, false) != names.Object(metadata, alias, false) {
			t.Fatalf("graph identity escaped native name: %s", vendor)
		}
	}
}

func TestRuleNameNamespaceRetainsNativeChain(t *testing.T) {
	first := fm.RuleRecord{Object: fm.Object{ID: "one", Name: "web"}, RuleSet: "security", Match: fm.Match{FromZones: []fm.ID{"inside"}, ToZones: []fm.ID{"outside"}}}
	second := first
	second.ID = "two"
	second.Match.ToZones = []fm.ID{"dmz"}
	for _, vendor := range []string{"srx", "paloalto", "huawei"} {
		if equal := names.Rule(vendor, first) == names.Rule(vendor, second); equal == (vendor == "srx") {
			t.Fatalf("native chain separation: %s", vendor)
		}
	}
}

func TestRuleIdentityUsesNamesOrIDs(t *testing.T) {
	first := fm.RuleRecord{Object: fm.Object{ID: "10", Name: "web"}, RuleSet: "security"}
	for _, tc := range []struct {
		vendor string
		named  bool
	}{
		{vendor: "paloalto", named: true},
		{vendor: "srx", named: true},
		{vendor: "huawei", named: true},
		{vendor: "hillstone"},
		{vendor: "fortinet"},
		{vendor: "netscreen"},
		{vendor: "asa"},
	} {
		t.Run(tc.vendor, func(t *testing.T) {
			second := first
			second.ID = "20"
			if equal := names.Rule(tc.vendor, first) == names.Rule(tc.vendor, second); equal != tc.named {
				t.Fatal("rule identity uses the wrong field")
			}
			second = first
			second.Name = "other"
			if equal := names.Rule(tc.vendor, first) == names.Rule(tc.vendor, second); equal == tc.named {
				t.Fatal("rule label changed numeric identity or reused a different name")
			}
		})
	}
}

func TestUnnamedRuleDoesNotUseGraphIDAsName(t *testing.T) {
	unnamed := fm.RuleRecord{Object: fm.Object{ID: "web"}, RuleSet: "security"}
	named := fm.RuleRecord{Object: fm.Object{ID: "different", Name: "web"}, RuleSet: "security"}
	for _, vendor := range []string{"paloalto", "srx", "huawei"} {
		if names.Rule(vendor, unnamed) == names.Rule(vendor, named) {
			t.Fatalf("graph ID substituted for missing rule name: %s", vendor)
		}
	}
}
