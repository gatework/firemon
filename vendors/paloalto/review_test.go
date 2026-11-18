package paloalto_test

import (
	"encoding/json"
	"testing"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/vendors/paloalto"
)

func compileSet(t *testing.T, text string) (*firemon.Config, *firemon.Firewall) {
	t.Helper()
	cfg, err := paloalto.New(paloalto.Options{}).Parse(text)
	if err != nil {
		t.Fatal(err)
	}
	fw, err := firemon.Compile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return cfg, fw
}

func TestHb_RuleTypeRestrictsZonePairs(t *testing.T) {
	t.Parallel()
	_, fw := compileSet(t, `set zone a network layer3 ethernet1/1
set zone b network layer3 ethernet1/2
set rulebase security rules inter from [ a b ]
set rulebase security rules inter to [ a b ]
set rulebase security rules inter rule-type interzone
set rulebase security rules inter action allow
set rulebase security rules intra from [ a b ]
set rulebase security rules intra rule-type intrazone
set rulebase security rules intra action allow
`)
	inter, _ := fw.Rule("inter")
	intra, _ := fw.Rule("intra")
	switch {
	case inter.Applies("a", "a") || !inter.Applies("a", "b"):
		t.Error("interzone rule applies only between different zones")
	case !intra.Applies("b", "b") || intra.Applies("a", "b"):
		t.Error("intrazone rule applies only within one zone")
	}
}

func TestVsysShadowsShared(t *testing.T) {
	t.Parallel()
	_, fw := compileSet(t, `set shared address web ip-netmask 10.0.0.1
set address web ip-netmask 10.0.0.2
set shared address web description late-shared
`)
	if got, _ := fw.Address("web"); got.String() != "10.0.0.2" {
		t.Fatalf("vsys object must shadow the shared one, got %s", got)
	}
}

func TestHc_InvalidValueMakesObjectUnresolvable(t *testing.T) {
	t.Parallel()
	_, fw := compileSet(t, `set address bad ip-netmask 10.0.0.300
set rulebase security rules r source bad
set rulebase security rules r action allow
`)
	if r, _ := fw.Rule("r"); r.Decidable() {
		t.Fatal("an address with an invalid value cannot be exact")
	}
}

func TestV2_InterfaceAddressIsTheHost(t *testing.T) {
	t.Parallel()
	cfg, _ := compileSet(t, `set rulebase nat rules out from inside to outside source any destination any service any
set rulebase nat rules out source-translation dynamic-ip-and-port interface-address interface ethernet1/2
set rulebase nat rules out source-translation dynamic-ip-and-port interface-address ip 103.24.178.130/28
`)
	got := cfg.DynamicNATs[0].TranslatedSource.Addresses
	if len(got) != 1 || got[0].Entry.Prefix.String() != "103.24.178.130/32" {
		t.Fatalf("interface address %+v", got)
	}
}

func equalJSON(t *testing.T, a, b any) bool {
	t.Helper()
	x, err1 := json.Marshal(a)
	y, err2 := json.Marshal(b)
	if err1 != nil || err2 != nil {
		t.Fatal(err1, err2)
	}
	return string(x) == string(y)
}
