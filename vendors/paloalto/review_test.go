package paloalto_test

import (
	"encoding/json"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/design"
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
set rulebase nat rules out source-translation dynamic-ip-and-port interface-address ip 198.51.100.146/28
`)
	got := cfg.DynamicNATs[0].TranslatedSource.Addresses
	if len(got) != 1 || got[0].Entry.Prefix.String() != "198.51.100.146/32" {
		t.Fatalf("interface address %+v", got)
	}
}

// TestNAT_InterfaceAddressObjectIsHost: the interface address may name an
// address object written with the interface mask; it is still one host.
func TestNAT_InterfaceAddressObjectIsHost(t *testing.T) {
	t.Parallel()
	cfg, _ := compileSet(t, `set address wan-ip ip-netmask 198.51.100.146/28
set rulebase nat rules out from inside to outside source any destination any service any
set rulebase nat rules out source-translation dynamic-ip-and-port interface-address interface ethernet1/2
set rulebase nat rules out source-translation dynamic-ip-and-port interface-address ip wan-ip
`)
	got := cfg.DynamicNATs[0].TranslatedSource.Addresses
	if len(got) != 1 || !got[0].IsInline() || got[0].Entry.Prefix.String() != "198.51.100.146/32" {
		t.Fatalf("interface address %+v", got)
	}
}

// TestRouting_LogicalRouterAndDroppedRoutes: the Advanced Routing Engine
// form is a routing context like a virtual router; routes that do not
// forward, or whose next hop is a name, are left out and reported.
func TestRouting_LogicalRouterAndDroppedRoutes(t *testing.T) {
	t.Parallel()
	cfg, _ := compileSet(t, `set network interface ethernet ethernet1/1 layer3 ip 192.0.2.2/24
set network logical-router lr1 vrf default interface [ ethernet1/1 ]
set network logical-router lr1 vrf default routing-table ip static-route def destination 0.0.0.0/0
set network logical-router lr1 vrf default routing-table ip static-route def nexthop ip-address 192.0.2.1
set network logical-router lr1 vrf blue routing-table ip static-route b destination 10.9.0.0/16
set network logical-router lr1 vrf blue routing-table ip static-route b nexthop ip-address 192.0.2.9
set network logical-router lr1 vrf default routing-table ip static-route quiet destination 10.8.0.0/16
set network logical-router lr1 vrf default routing-table ip static-route quiet nexthop ip-address 192.0.2.1
set network logical-router lr1 vrf default routing-table ip static-route quiet route-table no-install
set network logical-router lr1 vrf default routing-table ip static-route named destination 10.7.0.0/16
set network logical-router lr1 vrf default routing-table ip static-route named nexthop fqdn gw.example.com
set network logical-router lr1 vrf default routing-table ip static-route named interface ethernet1/1
`)
	var got []string
	for _, r := range cfg.Routes {
		got = append(got, r.VirtualRouter+" "+r.Destination.String())
	}
	if !slices.Equal(got, []string{"lr1 0.0.0.0/0", "lr1/blue 10.9.0.0/16"}) {
		t.Fatalf("routes %v", got)
	}
	if cfg.Interfaces[0].VirtualRouter != "lr1" || len(cfg.Diagnostics) != 2 {
		t.Fatalf("interface %+v diagnostics %+v", cfg.Interfaces[0], cfg.Diagnostics)
	}
}

// TestNAT_UnmodelledTranslationsAreUndecidable: NAT64, NPTv6 and source
// translation fallback are not in the model; such rules stay undecidable.
func TestNAT_UnmodelledTranslationsAreUndecidable(t *testing.T) {
	t.Parallel()
	_, fw := compileSet(t, `set rulebase nat rules six from inside to outside source any destination any service any
set rulebase nat rules six nat-type nat64
set rulebase nat rules fb from inside to outside source any destination any service any
set rulebase nat rules fb source-translation dynamic-ip-and-port translated-address 203.0.113.5 fallback translated-address 203.0.113.6
`)
	for _, r := range fw.NATRules() {
		if r.Decidable() {
			t.Errorf("nat rule %s is decidable", r.Spec().ID)
		}
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

func TestPBF_ParsedAndItsObjectsUsed(t *testing.T) {
	t.Parallel()
	cfg, fw := compileSet(t, `set address intranet ip-netmask 10.0.0.0/8
set address qos-host ip-netmask 192.0.2.9
set zone trust network layer3 ethernet1/2
set network interface ethernet ethernet1/2 layer3 ip 10.0.0.1/24
set network interface ethernet ethernet1/3 layer3 ip 198.51.100.2/24
set network virtual-router default interface [ ethernet1/2 ethernet1/3 ]
set rulebase pbf rules out-isp2 from zone trust
set rulebase pbf rules out-isp2 source any
set rulebase pbf rules out-isp2 destination intranet
set rulebase pbf rules out-isp2 negate-destination yes
set rulebase pbf rules out-isp2 service any
set rulebase pbf rules out-isp2 action forward egress-interface ethernet1/3
set rulebase pbf rules out-isp2 action forward nexthop ip-address 198.51.100.1
set rulebase qos rules shape destination qos-host
`)
	if len(cfg.PolicyRoutes) != 1 || len(cfg.PolicyBindings) != 1 || !cfg.PolicyRoutes[0].NegateDestination || cfg.PolicyRoutes[0].Interface != "ethernet1/3" {
		t.Fatalf("pbf %+v bindings %+v", cfg.PolicyRoutes, cfg.PolicyBindings)
	}
	if routes := fw.PolicyRoutesFor("trust", ""); len(routes) != 1 || routes[0].Match().Dst.Contains(netip.MustParseAddr("10.1.1.1")) {
		t.Fatal("negate-destination: traffic to the intranet is not forwarded")
	}
	if u := fw.References().Unused(); len(u) != 0 {
		t.Fatalf("pbf and qos objects are in use: %v", u)
	}
}

// TestRules_ExternalListsAndRegionsSayWhatTheyMatch: an external list or a
// region in a rule leaves it undecidable and names the kind.
func TestRules_ExternalListsAndRegionsSayWhatTheyMatch(t *testing.T) {
	t.Parallel()
	var text strings.Builder
	text.WriteString("set external-list bad-ips type ip url https://example.com/bad.txt\n")
	for _, r := range []struct{ name, src string }{{"edl", "bad-ips"}, {"geo", "CN"}} {
		for _, attr := range []string{"from any", "to any", "source " + r.src, "destination any", "service any", "application any", "action deny"} {
			text.WriteString("set rulebase security rules " + r.name + " " + attr + "\n")
		}
	}
	cfg, fw := compileSet(t, text.String())
	for i, want := range []string{"external-list bad-ips", "region CN"} {
		if got := firemon.Criteria(cfg.Rules[i].Conditions); !slices.Equal(got, []string{want}) {
			t.Errorf("rule %s unsupported %v, want %s", cfg.Rules[i].ID, got, want)
		}
	}
	for _, r := range fw.Rules() {
		if r.Decidable() {
			t.Errorf("rule %s is decidable", r.ID())
		}
	}
}

// TestParse_VersionFromSystemInfo: "show system info" saved with the set
// output gives the software version; its other lines are not diagnosed.
func TestParse_VersionFromSystemInfo(t *testing.T) {
	t.Parallel()
	cfg, _ := compileSet(t, "hostname: pa1\nsw-version: 10.2.4\nmodel: PA-3220\nset deviceconfig system hostname pa1\n")
	if cfg.Version != "10.2.4" || len(cfg.Diagnostics) != 0 {
		t.Fatalf("version %q diagnostics %+v", cfg.Version, cfg.Diagnostics)
	}
}

// TestRule_InspectionRoundTrip: a profile group and single profiles are
// read as inspection and written back.
func TestRule_InspectionRoundTrip(t *testing.T) {
	t.Parallel()
	var text strings.Builder
	for _, attr := range []string{"from any", "to any", "source any", "destination any", "service any", "application any", "action allow",
		"profile-setting group Protect", "category adult", "source-user alice"} {
		text.WriteString("set rulebase security rules r1 " + attr + "\n")
	}
	text.WriteString("set rulebase security rules r2 profile-setting profiles vulnerability strict\n")
	cfg, _ := compileSet(t, text.String())
	if !slices.Equal(cfg.Rules[0].Inspection, []string{"group Protect"}) || !slices.Equal(cfg.Rules[1].Inspection, []string{"vulnerability strict"}) {
		t.Fatalf("inspection %v %v", cfg.Rules[0].Inspection, cfg.Rules[1].Inspection)
	}
	if got := firemon.ConditionValues(cfg.Rules[0].Conditions, firemon.ConditionURLCategory); !slices.Equal(got, []string{"adult"}) {
		t.Fatalf("url category %v", got)
	}
	if got := firemon.ConditionValues(cfg.Rules[0].Conditions, firemon.ConditionUser); !slices.Equal(got, []string{"alice"}) {
		t.Fatalf("user %v", got)
	}
	script, err := paloalto.Renderer{}.Render(&design.Plan{Changes: []design.Change{design.AddRule{Rule: cfg.Rules[0]}}, Verified: true})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(script.Commands, "set rulebase security rules r1 profile-setting group Protect") {
		t.Fatalf("commands %q", script.Commands)
	}
}
