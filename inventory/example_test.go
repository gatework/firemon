package inventory_test

import (
	"fmt"
	"time"

	"github.com/gatework/firemon/inventory"
)

func ExampleInventory_Locate() {
	core, err := newFirewall(
		[]link{{"c0", "transit", "10.0.0.2/30"}, {"c1", "users", "10.1.0.1/16"}},
		[]route{{"0.0.0.0/0", "10.0.0.1"}})
	if err != nil {
		fmt.Println(err)
		return
	}
	edge, err := newFirewall(
		[]link{{"e0", "internet", "203.0.113.2/30"}, {"e1", "inside", "10.0.0.1/30"}},
		[]route{{"0.0.0.0/0", "203.0.113.1"}, {"10.0.0.0/8", "10.0.0.2"}})
	if err != nil {
		fmt.Println(err)
		return
	}
	inv, err := inventory.New([]inventory.Member{{Name: "core", Firewall: core}, {Name: "edge", Firewall: edge}},
		inventory.Options{Now: func() time.Time { return now }})
	if err != nil {
		fmt.Println(err)
		return
	}
	tr, err := inv.Locate(request("10.1.0.5", "8.8.8.8", "tcp/443"))
	if err != nil {
		fmt.Println(err)
		return
	}
	for _, c := range tr.Crossings {
		fmt.Println(c.Firewall, c.Paths[0].From, "->", c.Paths[0].To, c.Verdict)
	}
	// Output:
	// core users -> transit denied
	// edge inside -> internet denied
}
