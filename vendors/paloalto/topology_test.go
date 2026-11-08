package paloalto_test

import (
	"fmt"
	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/policy"
	"github.com/gatework/firemon/vendors/paloalto"
	"net/netip"
	"strings"
	"testing"
)

func TestLogicalInterfacesBindBeforeRoutes(t *testing.T) {
	for _, path := range []string{"ethernet ethernet1/1 layer3 units ethernet1/1.10", "aggregate-ethernet ae1 layer3 units ae1.10", "tunnel units tunnel.1", "loopback units loopback.1", "vlan units vlan.10"} {
		t.Run(path, func(t *testing.T) {
			var name string
			for word := range strings.FieldsSeq(path) {
				name = word
			}
			source := fmt.Sprintf("set network virtual-router blue routing-table ip static-route default destination 0.0.0.0/0\nset network virtual-router blue routing-table ip static-route default nexthop ip-address 192.0.2.254\nset network virtual-router blue interface %s\nset zone inside network layer3 %s\nset network interface %s ip 192.0.2.1/24\n", name, name, path)
			fw := parse(t, source)
			if !fw.Complete() || fw.Interface(fm.ID(name)) == nil || fw.Interface(fm.ID(name)).Zone() != fw.Zone("inside") {
				t.Fatal("logical topology incomplete", fw.Diagnostics())
			}
			for _, route := range fw.Routes() {
				if route.Interface() != fw.Interface(fm.ID(name)) || route.Record().Scope != "blue" {
					t.Fatal("route lost binding")
				}
			}
			if len(fw.Routes()) != 2 {
				t.Fatal("connected/static route missing")
			}
		})
	}
}

func TestAddresslessInterfaceAndConflictingZoneBindings(t *testing.T) {
	fw := parse(t, "set network interface tunnel units tunnel.1 comment synthetic\nset zone inside network layer3 tunnel.1\nset zone outside network layer3 tunnel.1\n")
	if fw.Interface("tunnel.1") == nil || len(fw.Interface("tunnel.1").Record().Unsupported) == 0 {
		t.Fatal("ambiguous zone binding silently selected")
	}
}

func parse(t *testing.T, raw string) *fm.Firewall {
	t.Helper()
	fw, err := (paloalto.Parser{}).Parse(t.Context(), config.Source{Text: raw, Complete: true}, fm.Metadata{Device: "synthetic"})
	if err != nil {
		t.Fatal(err)
	}
	return fw
}

func TestIPv6AddressRequiresBothEnableFlags(t *testing.T) {
	for _, enabled := range []string{"yes", "no", ""} {
		for _, addressEnabled := range []string{"yes", "no", ""} {
			t.Run(enabled+"/"+addressEnabled, func(t *testing.T) {
				raw := "set network interface ethernet ethernet1/1 layer3 ipv6 address 2001:db8::1/64"
				if addressEnabled != "" {
					raw += " enable-on-interface " + addressEnabled
				}
				raw += "\n"
				if enabled != "" {
					raw += "set network interface ethernet ethernet1/1 layer3 ipv6 enabled " + enabled + "\n"
				}
				fw := parse(t, raw)
				want := 0
				if enabled == "yes" && addressEnabled == "yes" {
					want = 1
				}
				if len(fw.Routes()) != want {
					t.Fatal("disabled IPv6 address created a connected route")
				}
			})
		}
	}
}

func TestStaticRouteIdentityIncludesAddressFamily(t *testing.T) {
	fw := parse(t, "set network interface tunnel units tunnel.1 comment synthetic\n"+
		"set network virtual-router blue interface tunnel.1\n"+
		"set network virtual-router blue routing-table ip static-route default destination 0.0.0.0/0\n"+
		"set network virtual-router blue routing-table ip static-route default interface tunnel.1\n"+
		"set network virtual-router blue routing-table ipv6 static-route default destination ::/0\n"+
		"set network virtual-router blue routing-table ipv6 static-route default interface tunnel.1\n")
	if !fw.Complete() || len(fw.Routes()) != 2 {
		t.Fatal("same-name IPv4 and IPv6 routes collided", fw.Diagnostics())
	}
}

func TestLogicalInterfaceXMLAndSetHaveSameRoutes(t *testing.T) {
	const xml = `<config><devices><entry name="local"><network>
<interface><tunnel><units><entry name="tunnel.1">
<ip><entry name="192.0.2.1/24"/></ip><ipv6><enabled>yes</enabled>
<address><entry name="2001:db8::1/64"><enable-on-interface>yes</enable-on-interface></entry></address>
</ipv6></entry></units></tunnel></interface>
<virtual-router><entry name="blue"><interface><member>tunnel.1</member></interface>
<routing-table><ip><static-route><entry name="default"><destination>0.0.0.0/0</destination>
<interface>tunnel.1</interface></entry></static-route></ip>
<ipv6><static-route><entry name="default"><destination>::/0</destination>
<interface>tunnel.1</interface></entry></static-route></ipv6></routing-table>
</entry></virtual-router></network><vsys><entry name="vsys1"><zone><entry name="inside">
<network><layer3><member>tunnel.1</member></layer3></network></entry></zone></entry></vsys>
</entry></devices></config>`
	const set = "set network interface tunnel units tunnel.1 ip 192.0.2.1/24\n" +
		"set network interface tunnel units tunnel.1 ipv6 enabled yes\n" +
		"set network interface tunnel units tunnel.1 ipv6 address 2001:db8::1/64 enable-on-interface yes\n" +
		"set network virtual-router blue interface tunnel.1\n" +
		"set network virtual-router blue routing-table ip static-route default destination 0.0.0.0/0\n" +
		"set network virtual-router blue routing-table ip static-route default interface tunnel.1\n" +
		"set network virtual-router blue routing-table ipv6 static-route default destination ::/0\n" +
		"set network virtual-router blue routing-table ipv6 static-route default interface tunnel.1\n" +
		"set vsys vsys1 zone inside network layer3 tunnel.1\n"
	for format, raw := range map[string]string{"xml": xml, "set": set} {
		t.Run(format, func(t *testing.T) {
			fw := parse(t, raw)
			if !fw.Complete() || len(fw.Routes()) != 4 {
				t.Fatal("native paths lost topology", fw.Diagnostics())
			}
			for _, prefix := range []string{"198.51.100.0/24", "2001:db8:1::/64"} {
				r, err := flow.PrefixRange(netip.MustParsePrefix(prefix))
				if err != nil {
					t.Fatal(err)
				}
				addresses, err := flow.NewAddressSet(r)
				if err != nil {
					t.Fatal(err)
				}
				paths, err := (policy.Engine{}).ResolveRoutes(t.Context(), fw, "blue", addresses)
				if err != nil || len(paths) != 1 || !paths[0].Known || paths[0].Interface != fw.Interface("tunnel.1") {
					t.Fatal("route lost exact binding", err)
				}
			}
		})
	}
}
