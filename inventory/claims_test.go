package inventory_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/gatework/firemon/inventory"
)

// A route toward another firewall of the inventory does not make the
// routing firewall the owner of the networks behind it.
func TestInventory_DerivedClaimsSkipRoutesToMembers(t *testing.T) {
	t.Parallel()
	tr, err := lab(t).Locate(request("10.5.0.1", "192.168.10.5", "tcp/22"))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range tr.Crossings {
		if c.Firewall == "edge" {
			t.Fatalf("edge owns 10.5.0.1 through its route to core: %v", names(tr))
		}
	}
}

// Zones named by the request locate the path: it crosses the firewall
// even though no interfaces are compared.
func TestInventory_RequestZonesCross(t *testing.T) {
	t.Parallel()
	req := request("10.1.0.5", "10.2.0.9", "tcp/22")
	req.FromZone, req.ToZone = "users", "servers"
	tr, err := lab(t).Locate(req)
	if err != nil {
		t.Fatal(err)
	}
	if got := names(tr); len(got) != 1 || got[0] != "core(users>servers)" {
		t.Fatalf("crossings %v", got)
	}
}

// A firewall that declares protected zones also owns what its routes reach
// through them, and nothing its routes reach through other zones.
func TestInventory_DerivedThroughProtectedZones(t *testing.T) {
	t.Parallel()
	core := firewall(t,
		[]link{{"c0", "transit", "10.0.0.2/30"}, {"c1", "users", "10.1.0.1/16"}, {"c2", "servers", "10.2.0.1/16"}},
		[]route{{"0.0.0.0/0", "10.0.0.1"}, {"10.9.0.0/16", "10.1.0.254"}, {"10.8.0.0/16", "10.2.0.254"}})
	inv, err := inventory.New([]inventory.Member{{Name: "core", Firewall: core}}, inventory.Options{
		Now:   func() time.Time { return now },
		Zones: []inventory.ZoneBinding{{Firewall: "core", Zone: "users", Networks: []netip.Prefix{netip.MustParsePrefix("10.1.0.0/16")}, Protected: true}},
	})
	if err != nil {
		t.Fatal(err)
	}
	tr, err := inv.Locate(request("10.9.0.5", "10.0.0.1", "tcp/22"))
	if err != nil || len(tr.Crossings) != 1 {
		t.Fatalf("10.9.0.5 is routed through the protected zone: %v %v excluded %+v", names(tr), err, tr.Excluded)
	}
	tr, err = inv.Locate(request("10.8.0.5", "10.0.0.1", "tcp/22"))
	if err != nil || len(tr.Crossings) != 0 {
		t.Fatalf("10.8.0.5 is routed through an unprotected zone: %v %v", names(tr), err)
	}
}
