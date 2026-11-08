package vendors_test

import (
	"strings"
	"testing"

	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/vendors"
)

func TestPANOrderedNativeNATCreation(t *testing.T) {
	base := "set network interface ethernet ethernet1/1 layer3 ip 192.0.2.1/24\nset network interface ethernet ethernet1/2 layer3 ip 198.51.100.1/24\nset zone inside network layer3 ethernet1/1\nset zone outside network layer3 ethernet1/2\nset address client ip-netmask 192.0.2.10/32\nset address server ip-netmask 203.0.113.20/32\nset service https protocol tcp port 443\n"
	match := "set rulebase nat rules change from inside\nset rulebase nat rules change to outside\nset rulebase nat rules change source client\nset rulebase nat rules change destination server\nset rulebase nat rules change service https\n"
	for _, tc := range []struct{ name, body, command string }{
		{"static-source", "set rulebase nat rules change source-translation static-ip translated-address 198.51.100.10\nset rulebase nat rules change source-translation static-ip bi-directional no\n", "source-translation static-ip translated-address 198.51.100.10/32"},
		{"pool-pat", "set rulebase nat rules change source-translation dynamic-ip-and-port translated-address [ 198.51.100.10-198.51.100.13 ]\n", "source-translation dynamic-ip-and-port translated-address [ 198.51.100.10-198.51.100.13 ]"},
		{"pool-no-pat", "set rulebase nat rules change source-translation dynamic-ip translated-address 198.51.100.10-198.51.100.13\n", "source-translation dynamic-ip translated-address [ 198.51.100.10-198.51.100.13 ]"},
		{"interface-pat", "set rulebase nat rules change source-translation dynamic-ip-and-port interface-address interface ethernet1/2\nset rulebase nat rules change source-translation dynamic-ip-and-port interface-address ip 198.51.100.1\n", "interface-address ip 198.51.100.1"},
		{"destination-port", "set rulebase nat rules change destination-translation translated-address 192.0.2.20\nset rulebase nat rules change destination-translation translated-port 8443\n", "destination-translation translated-port 8443"},
		{"no-translation", "", "service \"https\""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := nativeParse(t, "paloalto", "10.2.7", base)
			after := nativeParse(t, "paloalto", "10.2.7", base+match+tc.body)
			r, err := vendors.Renderer("paloalto")
			if err != nil {
				t.Fatal(err)
			}
			commands, err := r.(plan.NativeRenderer).RenderNative(t.Context(), before, after, nativeDelta(before, after))
			if err != nil || !strings.Contains(strings.Join(commands, "\n"), tc.command) {
				t.Fatal(commands, err)
			}
			// A different independently captured translation must not pass as the
			// same declarative delta, even when its native name is unchanged.
			changed := strings.Replace(base+match+tc.body, "source client", "source server", 1)
			other := nativeParse(t, "paloalto", "10.2.7", changed)
			if _, err = r.(plan.NativeRenderer).RenderNative(t.Context(), before, other, nativeDelta(before, after)); err == nil {
				t.Fatal("mismatched captured NAT accepted")
			}
		})
	}
}
