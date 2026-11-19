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
