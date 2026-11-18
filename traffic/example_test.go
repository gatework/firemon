package traffic_test

import (
	"fmt"

	"github.com/gatework/firemon/traffic"
)

func Example() {
	src, _ := traffic.ParseAddressSet("10.1.0.0/16")
	dst, _ := traffic.ParseAddressSet("192.168.1.10")
	svc, _ := traffic.ParseServiceSet("tcp/443")
	request := traffic.Space{Src: src, Dst: dst, Service: svc}

	webRule := traffic.Space{Src: traffic.AnyAddress(), Dst: dst, Service: svc}
	fmt.Println(webRule.ContainsSpace(request))

	remaining := traffic.NewRegion(request).Subtract(traffic.Space{Src: traffic.AnyIPv4(), Dst: dst, Service: svc})
	fmt.Println(remaining.IsEmpty())
	// Output:
	// true
	// true
}

func ExampleAddressSet_Relation() {
	a, _ := traffic.ParseAddressSet("10.0.0.0/24")
	b, _ := traffic.ParseAddressSet("10.0.0.128-10.0.1.5")
	fmt.Println(a.Relation(b))
	// Output: overlap
}
