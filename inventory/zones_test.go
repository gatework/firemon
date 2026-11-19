package inventory_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/inventory"
)

// threeZoneBridge is a transparent firewall with three layer-2 zones: the
// peer of the protected zone is not unique, so only zone bindings locate
// the far end.
func threeZoneBridge(t *testing.T) *firemon.Firewall {
	t.Helper()
	cfg := &firemon.Config{
		Vendor:         firemon.VendorHillstone,
		Semantics:      firemon.Semantics{InterzoneAction: firemon.ActionDeny, IntrazoneAction: firemon.ActionDeny, DefaultVirtualRouter: "mgt-vr"},
		VirtualRouters: []firemon.VirtualRouter{{Name: "mgt-vr"}},
		Zones: []firemon.Zone{
			{Name: "l2-trust", Mode: firemon.ZoneModeLayer2}, {Name: "l2-untrust", Mode: firemon.ZoneModeLayer2},
			{Name: "l2-dmz", Mode: firemon.ZoneModeLayer2}, {Name: "mgt", Mode: firemon.ZoneModeLayer3, VirtualRouter: "mgt-vr"},
		},
		Interfaces: []firemon.Interface{
			{Name: "x24", Zone: "l2-trust"}, {Name: "x25", Zone: "l2-untrust"}, {Name: "x26", Zone: "l2-dmz"},
			{Name: "MGT0", Zone: "mgt", VirtualRouter: "mgt-vr", Addresses: []netip.Prefix{netip.MustParsePrefix("10.251.8.203/24")}},
		},
		Rules: []firemon.SecurityRule{
			{ID: "1", Action: firemon.ActionPermit, From: []string{"l2-trust"}, To: []string{"l2-dmz"}},
		},
	}
	fw, err := firemon.Compile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return fw
}

func TestInventory_ZoneBindingsLocateTheFarEnd(t *testing.T) {
	t.Parallel()
	pfx := func(s ...string) []netip.Prefix {
		out := make([]netip.Prefix, len(s))
		for i, x := range s {
			out[i] = netip.MustParsePrefix(x)
		}
		return out
	}
	members := []inventory.Member{{Name: "fw1", Firewall: threeZoneBridge(t), Active: true}}
	zones := []inventory.ZoneBinding{
		{Firewall: "fw1", Zone: "l2-trust", Networks: pfx("10.250.0.0/16"), Protected: true},
		{Firewall: "fw1", Zone: "l2-dmz", Networks: pfx("10.99.0.0/16")},
		{Firewall: "fw1", Zone: "l2-untrust", Networks: pfx("0.0.0.0/0")},
	}
	inv, err := inventory.New(members, inventory.Options{Now: func() time.Time { return now }, Zones: zones})
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		dst, want, verdict string
	}{
		{"10.99.1.1", "fw1(l2-trust>l2-dmz)", "allowed"},
		{"8.8.8.8", "fw1(l2-trust>l2-untrust)", "denied"},
	} {
		tr, err := inv.Locate(request("10.250.1.1", tt.dst, "tcp/443"))
		if err != nil {
			t.Fatal(err)
		}
		if got := names(tr); len(got) != 1 || got[0] != tt.want || tr.Verdict.String() != tt.verdict {
			t.Errorf("to %s: %v %s, want %s %s", tt.dst, got, tr.Verdict, tt.want, tt.verdict)
		}
	}
	// An unprotected binding does not make the firewall own the address.
	tr, err := inv.Locate(request("10.99.1.1", "8.8.8.8", "tcp/443"))
	if err != nil {
		t.Fatal(err)
	}
	if len(tr.Crossings) != 0 || tr.Excluded.Src.IsEmpty() {
		t.Errorf("neither end protected: %v excluded %+v", names(tr), tr.Excluded)
	}
}
