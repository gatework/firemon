package firemon_test

import (
	"fmt"
	"net/netip"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/traffic"
)

func ExampleCompile() {
	cfg := &firemon.Config{
		Vendor: firemon.VendorPaloAlto,
		Zones:  []firemon.Zone{{Name: "inside"}, {Name: "outside"}},
		Addresses: []firemon.Address{{
			Name:    "dns",
			Entries: []firemon.AddressEntry{firemon.HostEntry(netip.MustParseAddr("192.0.2.53"))},
		}},
		Services: []firemon.Service{{
			Name:    "dns-udp",
			Entries: []firemon.ServiceEntry{firemon.PortEntry(traffic.ProtocolUDP, traffic.Port(53))},
		}},
		Rules: []firemon.SecurityRule{{
			ID: "allow-dns", From: []string{"inside"}, To: []string{"outside"},
			Destination: []firemon.AddressRef{firemon.NamedAddress("dns")},
			Services:    []string{"dns-udp"}, Action: firemon.ActionPermit,
		}},
	}
	fw, err := firemon.Compile(cfg)
	if err != nil {
		fmt.Println(err)
		return
	}
	r, _ := fw.Rule("allow-dns")
	fmt.Println(r.Match(), r.Decidable())
	// Output: any -> 192.0.2.53 udp/53 true
}
