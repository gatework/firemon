package migrate_test

import (
	"testing"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/migrate"
)

// panRegress declares a service group before the group it contains, an
// address group with an undefined member, a rule on an undefined schedule
// and a source NAT to two addresses.
const panRegress = `set zone trust network layer3 ethernet1/2
set zone untrust network layer3 ethernet1/1
set network interface ethernet ethernet1/1 layer3 ip 203.0.113.2/30
set network interface ethernet ethernet1/2 layer3 ip 10.0.0.1/24
set network virtual-router default interface [ ethernet1/1 ethernet1/2 ]
set address web ip-netmask 192.0.2.10
set address-group dangling static [ web missing ]
set service tcp-8080 protocol tcp port 8080
set service-group outer members [ inner tcp-8080 ]
set service-group inner members [ service-https ]
set rulebase security rules nested from trust
set rulebase security rules nested to untrust
set rulebase security rules nested source any
set rulebase security rules nested destination web
set rulebase security rules nested service outer
set rulebase security rules nested application any
set rulebase security rules nested action allow
set rulebase security rules timed from trust
set rulebase security rules timed to untrust
set rulebase security rules timed source any
set rulebase security rules timed destination web
set rulebase security rules timed service service-https
set rulebase security rules timed application any
set rulebase security rules timed schedule nowhere
set rulebase security rules timed action allow
set rulebase nat rules pool from trust
set rulebase nat rules pool to untrust
set rulebase nat rules pool source any
set rulebase nat rules pool destination any
set rulebase nat rules pool service any
set rulebase nat rules pool source-translation dynamic-ip-and-port translated-address [ 198.51.100.1 198.51.100.2 ]
`

func TestTranslate_Regressions(t *testing.T) {
	t.Parallel()
	res, src, back := translate(t, firemon.VendorPaloAlto, firemon.VendorHillstone, panRegress, migrate.Mapping{})
	for _, name := range []string{"inner", "outer"} {
		if it := item(res, migrate.ItemKindServiceGroup, name); it.Fidelity != migrate.FidelityExact {
			t.Errorf("service group %s, declared after its user, translates: %+v", name, it)
		}
	}
	nested := item(res, migrate.ItemKindRule, "nested")
	if nested.Fidelity != migrate.FidelityExact {
		t.Fatalf("rule on nested service groups: %+v", nested)
	}
	sameMatch(t, src, back, nested)
	if it := item(res, migrate.ItemKindAddressGroup, "dangling"); it.Fidelity != migrate.FidelityUntranslatable {
		t.Errorf("a group with an undefined member: %+v", it)
	}
	if it := item(res, migrate.ItemKindRule, "timed"); it.Fidelity != migrate.FidelityUntranslatable {
		t.Errorf("a rule on an undefined schedule would apply all the time: %+v", it)
	}
	if it := item(res, migrate.ItemKindNAT, "pool"); it.Fidelity != migrate.FidelityExact || len(it.Target) != 1 {
		t.Errorf("source NAT to two addresses: %+v", it)
	}
	if len(back.NATRules()) == 0 {
		t.Error("the NAT rule reads back")
	}
}
