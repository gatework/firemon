package query_test

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/query"
	"github.com/gatework/firemon/traffic"
)

func ExampleEngine_Query() {
	cfg := &firemon.Config{
		Vendor:    firemon.VendorPaloAlto,
		Semantics: firemon.Semantics{InterzoneAction: firemon.ActionDeny, IntrazoneAction: firemon.ActionPermit},
		Zones:     []firemon.Zone{{Name: "inside"}, {Name: "outside"}},
		Rules: []firemon.SecurityRule{
			{ID: "block-host", Source: []firemon.AddressRef{firemon.InlineAddress(firemon.HostEntry(netip.MustParseAddr("10.0.0.66")))}, Action: firemon.ActionDeny},
			{ID: "web", From: []string{"inside"}, To: []string{"outside"}, Action: firemon.ActionPermit},
		},
	}
	fw, err := firemon.Compile(cfg)
	if err != nil {
		fmt.Println(err)
		return
	}
	src, _ := traffic.ParseAddressSet("10.0.0.0/24")
	dst, _ := traffic.ParseAddressSet("192.0.2.10")
	web, _ := traffic.ParseServiceSet("tcp/443")
	e := query.New(fw, query.Options{Now: func() time.Time { return time.Unix(0, 0) }})
	res, err := e.Query(query.Request{Src: src, Dst: dst, Service: web, FromZone: "inside", ToZone: "outside"})
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(res.Verdict)
	for _, d := range res.Paths[0].Decisions {
		fmt.Println(d.Rule.ID(), d.Outcome, d.Space)
	}
	// Output:
	// partial
	// block-host deny 10.0.0.66 -> 192.0.2.10 tcp/443
	// web permit 10.0.0.0-10.0.0.65,10.0.0.67-10.0.0.255 -> 192.0.2.10 tcp/443
}
