package inventory_test

import "testing"

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
