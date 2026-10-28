package benchmarks_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/vendors/asa"
	"github.com/gatework/firemon/vendors/fortinet"
	"github.com/gatework/firemon/vendors/hillstone"
	"github.com/gatework/firemon/vendors/huawei"
	"github.com/gatework/firemon/vendors/netscreen"
	"github.com/gatework/firemon/vendors/paloalto"
	"github.com/gatework/firemon/vendors/srx"
)

type parseFunc func(context.Context, config.Source, fm.Metadata) (*fm.Firewall, error)

var parsers = []struct {
	name  string
	parse parseFunc
}{{"asa", asa.Parse}, {"fortinet", fortinet.Parse}, {"hillstone", hillstone.Parse}, {"huawei", huawei.Parse}, {"netscreen", netscreen.Parse}, {"paloalto", paloalto.Parse}, {"srx", srx.Parse}}

// All addresses are documentation or network-benchmark ranges. Each generated
// capture has N address objects, N ordered policies and one shared TCP service.
func nativeConfig(vendor string, n int) string {
	var out strings.Builder
	write := func(format string, args ...any) { fmt.Fprintf(&out, format, args...) }
	switch vendor {
	case "asa":
		write("interface inside0\n nameif inside\n ip address 198.18.0.1 255.254.0.0\n!\ninterface outside0\n nameif outside\n ip address 203.0.113.1 255.255.255.0\n!\naccess-group inbound in interface inside\nobject-group service web tcp\n port-object eq 443\n")
		for i := range n {
			write("object network host-%d\n host 198.18.%d.%d\n", i, i>>8, i&255)
		}
		for i := range n {
			write("access-list inbound extended permit tcp object host-%d host 203.0.113.10 object-group web\n", i)
		}
	case "fortinet":
		write("config system interface\nedit inside\nset ip 198.18.0.1 255.254.0.0\nnext\nedit outside\nset ip 203.0.113.1 255.255.255.0\nnext\nend\nconfig firewall service custom\nedit WEB\nset tcp-portrange 443:1000-65535\nnext\nend\nconfig firewall address\n")
		for i := range n {
			write("edit host-%d\nset subnet 198.18.%d.%d 255.255.255.255\nnext\n", i, i>>8, i&255)
		}
		write("end\nconfig firewall policy\n")
		for i := range n {
			write("edit %d\nset srcintf inside\nset dstintf outside\nset srcaddr host-%d\nset dstaddr all\nset service WEB\nset schedule always\nset action accept\nnext\n", i+1, i)
		}
		write("end\n")
	case "hillstone":
		write("zone inside\nexit\nzone outside\nexit\ninterface eth0\n zone inside\n ip address 198.18.0.1 255.254.0.0\nexit\ninterface eth1\n zone outside\n ip address 203.0.113.1 255.255.255.0\nexit\nservice web\n tcp dst-port 443 443 src-port 1000 65535\nexit\n")
		for i := range n {
			write("address host-%d\n ip 198.18.%d.%d/32\nexit\n", i, i>>8, i&255)
		}
		write("policy from inside to outside\n")
		for i := range n {
			write(" rule id %d\n  src-addr host-%d\n  dst-addr any\n  service web\n  action permit\n exit\n", i+1, i)
		}
		write("exit\n")
	case "huawei":
		write("interface GigabitEthernet1/0/1\n ip address 198.18.0.1 15\n#\ninterface GigabitEthernet1/0/2\n ip address 203.0.113.1 24\n#\nfirewall zone inside\n add interface GigabitEthernet1/0/1\n#\nfirewall zone outside\n add interface GigabitEthernet1/0/2\n#\nip service-set web type object\n service 0 protocol tcp source-port 1000 to 65535 destination-port 443\n#\n")
		for i := range n {
			write("ip address-set host-%d type object\n address 0 198.18.%d.%d mask 32\n#\n", i, i>>8, i&255)
		}
		write("security-policy\n")
		for i := range n {
			write(" rule name permit-%d\n  source-zone inside\n  destination-zone outside\n  source-address address-set host-%d\n  service web\n  action permit\n", i, i)
		}
		write(" default action deny\n#\n")
	case "netscreen":
		write("set zone inside\nset zone outside\nset interface ethernet0/1 zone inside\nset interface ethernet0/1 ip 198.18.0.1/15\nset interface ethernet0/2 zone outside\nset interface ethernet0/2 ip 203.0.113.1/24\nset service web protocol tcp src-port 1000-65535 dst-port 443-443\n")
		for i := range n {
			write("set address inside host-%d 198.18.%d.%d/32\n", i, i>>8, i&255)
		}
		for i := range n {
			write("set policy id %d from inside to outside host-%d Any web permit\nexit\n", i+1, i)
		}
	case "paloalto":
		write("set network interface ethernet ethernet1/1 layer3 ip 198.18.0.1/15\nset network interface ethernet ethernet1/2 layer3 ip 203.0.113.1/24\nset network virtual-router default interface [ ethernet1/1 ethernet1/2 ]\nset zone inside network layer3 ethernet1/1\nset zone outside network layer3 ethernet1/2\nset service web protocol tcp port 443\n")
		for i := range n {
			write("set address host-%d ip-netmask 198.18.%d.%d/32\n", i, i>>8, i&255)
		}
		for i := range n {
			for _, field := range []string{"from inside", "to outside", fmt.Sprintf("source host-%d", i), "destination any", "application any", "service web", "action allow"} {
				write("set rulebase security rules permit-%d %s\n", i, field)
			}
		}
	case "srx":
		write("set interfaces ge-0/0/0 unit 0 family inet address 198.18.0.1/15\nset interfaces ge-0/0/1 unit 0 family inet address 203.0.113.1/24\nset security zones security-zone inside interfaces ge-0/0/0.0\nset security zones security-zone outside interfaces ge-0/0/1.0\nset applications application web protocol tcp\nset applications application web source-port 1000-65535\nset applications application web destination-port 443\n")
		for i := range n {
			write("set security address-book global address host-%d 198.18.%d.%d/32\n", i, i>>8, i&255)
		}
		for i := range n {
			for _, field := range []string{fmt.Sprintf("match source-address host-%d", i), "match destination-address any", "match application web", "then permit"} {
				write("set security policies from-zone inside to-zone outside policy permit-%d %s\n", i, field)
			}
		}
	}
	return out.String()
}

func benchmarkFirewall(tb testing.TB, n int) *fm.Firewall {
	tb.Helper()
	fw, err := huawei.Parse(context.Background(), config.Source{Text: nativeConfig("huawei", n), Complete: true}, fm.Metadata{Device: "synthetic-benchmark"})
	if err != nil {
		tb.Fatal(err)
	}
	if !fw.Complete() {
		tb.Fatal(fw.Diagnostics())
	}
	return fw
}

func TestBenchmarkFixturesAreComplete(t *testing.T) {
	for _, vendor := range parsers {
		t.Run(vendor.name, func(t *testing.T) {
			fw, err := vendor.parse(context.Background(), config.Source{Text: nativeConfig(vendor.name, 10), Complete: true}, fm.Metadata{Device: "synthetic-benchmark", Software: "7.4.0"})
			if err != nil {
				t.Fatal(err)
			}
			if !fw.Complete() || len(fw.Rules()) < 10 {
				t.Fatal(fw.Diagnostics())
			}
		})
	}
}
