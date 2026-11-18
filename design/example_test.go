package design_test

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/design"
	"github.com/gatework/firemon/traffic"
)

func ExamplePlanner_Plan() {
	cfg := &firemon.Config{
		Vendor:    firemon.VendorPaloAlto,
		Semantics: firemon.Semantics{InterzoneAction: firemon.ActionDeny},
		Zones:     []firemon.Zone{{Name: "inside"}, {Name: "outside"}},
		Addresses: []firemon.Address{{Name: "web", Entries: []firemon.AddressEntry{firemon.HostEntry(netip.MustParseAddr("192.0.2.10"))}}},
		Services:  []firemon.Service{{Name: "https", Entries: []firemon.ServiceEntry{firemon.PortEntry(traffic.ProtocolTCP, traffic.Port(443))}}},
		Rules: []firemon.SecurityRule{{
			ID: "web-access", From: []string{"inside"}, To: []string{"outside"}, Action: firemon.ActionPermit,
			Source:      []firemon.AddressRef{firemon.InlineAddress(firemon.PrefixEntry(netip.MustParsePrefix("10.0.1.0/24")))},
			Destination: []firemon.AddressRef{firemon.NamedAddress("web")}, Services: []string{"https"},
		}},
	}
	fw, err := firemon.Compile(cfg)
	if err != nil {
		fmt.Println(err)
		return
	}
	in := design.Intent{FromZone: "inside", ToZone: "outside"}
	in.Src, _ = traffic.ParseAddressSet("10.0.2.7")
	in.Dst, _ = traffic.ParseAddressSet("192.0.2.10")
	in.Service, _ = traffic.ParseServiceSet("tcp/443")
	plan, err := design.New(fw, design.Options{Now: func() time.Time { return time.Unix(0, 0) }}).Plan(in)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(plan.Status, plan.Verified)
	for _, c := range plan.Changes {
		fmt.Println(c)
	}
	// Output:
	// change true
	// add address Host_10.0.2.7 10.0.2.7
	// extend rule web-access source += Host_10.0.2.7
}
