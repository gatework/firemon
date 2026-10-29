package nativename_test

import (
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/internal/nativename"
)

func TestObjectNamespaceIdentity(t *testing.T) {
	object := fm.Object{ID: "id", Name: "web"}
	for _, vendor := range []string{"paloalto", "srx", "huawei", "hillstone", "fortinet", "netscreen", "asa"} {
		metadata := fm.Metadata{Vendor: vendor, Context: "root"}
		if equal := nativename.Object(metadata, object, false) == nativename.Object(metadata, object, true); equal == (vendor == "asa") {
			t.Fatalf("object/group namespace: %s", vendor)
		}
		local := object
		local.Scope = "root"
		if equal := nativename.Object(metadata, object, false) == nativename.Object(metadata, local, false); equal != (vendor == "fortinet") {
			t.Fatalf("context resolution: %s", vendor)
		}
		alias := object
		alias.ID = "different-graph-id"
		if nativename.Object(metadata, object, false) != nativename.Object(metadata, alias, false) {
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
		if equal := nativename.Rule(vendor, first) == nativename.Rule(vendor, second); equal == (vendor == "srx") {
			t.Fatalf("native chain separation: %s", vendor)
		}
	}
}
