package firemon_test

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/traffic"
)

func TestRoutingTable_RecursivePreferenceAndMultipath(t *testing.T) {
	t.Parallel()
	cfg := sampleConfig()
	const vr = "trust-vr"
	hop := netip.MustParseAddr("192.0.2.9")
	dst := netip.MustParseAddr("198.51.100.7")
	prefix := mustPrefix("192.0.2.0/24")
	cfg.Routes = []firemon.Route{
		{VirtualRouter: vr, Destination: mustPrefix("198.51.100.0/24"), NextHop: hop},
		{VirtualRouter: vr, Destination: prefix, Interface: "eth0/0", Distance: 100},
		{VirtualRouter: vr, Destination: prefix, Interface: "eth0/0", Distance: 5, Metric: 50},
		{VirtualRouter: vr, Destination: prefix, Interface: "eth0/1", Distance: 5, Metric: 4},
	}
	for _, want := range [][]string{{"eth0/1"}, {"eth0/0", "eth0/1"}} {
		fw, err := firemon.Compile(cfg)
		if err != nil {
			t.Fatal(err)
		}
		table, _ := fw.RoutingTable(vr)
		for _, addr := range []netip.Addr{hop, dst} {
			egress, _ := table.Lookup(traffic.AddressRange(addr, addr))
			var ifaces []string
			for _, e := range egress {
				ifaces = append(ifaces, e.Interface)
			}
			slices.Sort(ifaces)
			if !slices.Equal(ifaces, want) {
				t.Errorf("lookup %s: interfaces %v, want %v", addr, ifaces, want)
			}
		}
		cfg.Routes = append(cfg.Routes, firemon.Route{VirtualRouter: vr, Destination: prefix, Interface: "eth0/0", Distance: 5, Metric: 4})
	}
}
