package hillstone_test

import (
	"net/netip"
	"testing"
)

func TestReopenedNetworkObjectsBindBeforeRoutes(t *testing.T) {
	fw := parse(t, "zone inside\nexit\nzone inside\nvrouter blue\nexit\ninterface eth0\nzone inside\nexit\ninterface eth0\nip address 192.0.2.1/24\nexit\nip vrouter blue\nip route 203.0.113.0/24 192.0.2.254\nexit\n")
	if !fw.Complete() || len(fw.Zones()) != 1 || len(fw.Interfaces()) != 1 || len(fw.Routes()) != 2 {
		t.Fatal("network declarations lost identity", fw.Diagnostics())
	}
	iface := fw.Interface("eth0")
	if iface.Zone() != fw.Zone("inside") || iface.Scope() != "blue" {
		t.Fatal("zone binding did not see completed declarations")
	}
	if got := iface.Record().Addresses; len(got) != 1 || got[0] != netip.MustParsePrefix("192.0.2.1/24") {
		t.Fatal("interface address missing", got)
	}
	for _, route := range fw.Routes() {
		if route.Interface() != iface {
			t.Fatal("route was not bound to the single interface object")
		}
	}
}
