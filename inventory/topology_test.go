package inventory_test

import (
	"context"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/inventory"
	"net/netip"
	"testing"
)

func TestTopologyPreservesAmbiguousAndUnlocatedIntervals(t *testing.T) {
	r := func(s string) flow.AddressRange { v, _ := flow.PrefixRange(netip.MustParsePrefix(s)); return v }
	top := inventory.Topology{Version: 1, Bindings: []inventory.Binding{
		{Device: "a", Revision: "r", Zone: "inside", Role: inventory.Protection, View: inventory.Original, Networks: []flow.AddressRange{r("192.0.2.0/25")}},
		{Device: "b", Revision: "r", Zone: "inside", Role: inventory.Protection, View: inventory.Original, Networks: []flow.AddressRange{r("192.0.2.64/26")}},
		{Device: "a", Revision: "r", Zone: "outside", Role: inventory.Ingress, View: inventory.Original, Networks: []flow.AddressRange{r("0.0.0.0/0")}},
	}}
	addresses, _ := flow.NewAddressSet(r("192.0.2.0/24"))
	parts, err := top.Locate(context.Background(), addresses, inventory.Selection{Role: inventory.Protection, View: inventory.Original}, 32)
	if err != nil || len(parts) != 3 {
		t.Fatal(parts, err)
	}
	counts := map[int]string{}
	for _, p := range parts {
		counts[len(p.Bindings)] = p.Addresses.Ranges()[0].First.String()
	}
	if counts[0] != "192.0.2.128" || counts[1] != "192.0.2.0" || counts[2] != "192.0.2.64" {
		t.Fatal(counts)
	}
}
func TestTopologyKeepsOverlappingVRFsDistinct(t *testing.T) {
	r, _ := flow.PrefixRange(netip.MustParsePrefix("10.0.0.0/8"))
	a, _ := flow.NewAddressSet(r)
	top := inventory.Topology{Version: 1, Bindings: []inventory.Binding{{Device: "a", Revision: "r", Zone: "a", VRF: "red", Role: inventory.Protection, View: inventory.Original, Networks: []flow.AddressRange{r}}, {Device: "a", Revision: "r", Zone: "b", VRF: "blue", Role: inventory.Protection, View: inventory.Original, Networks: []flow.AddressRange{r}}}}
	parts, err := top.Locate(context.Background(), a, inventory.Selection{Role: inventory.Protection, View: inventory.Original}, 32)
	if err != nil || len(parts) != 1 || len(parts[0].Bindings) != 2 {
		t.Fatal(parts, err)
	}
	vrf := "red"
	parts, err = top.Locate(context.Background(), a, inventory.Selection{Role: inventory.Protection, View: inventory.Original, VRF: &vrf}, 32)
	if err != nil || len(parts) != 1 || len(parts[0].Bindings) != 1 || parts[0].Bindings[0].Zone != "a" {
		t.Fatal(parts, err)
	}
}
