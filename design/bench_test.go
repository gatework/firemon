package design_test

import (
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/design"
	"github.com/gatework/firemon/traffic"
)

// largeRules are n permit rules over distinct /24 sources, the shape of a
// large production rulebase.
func largeRules(n int) []firemon.SecurityRule {
	rules := make([]firemon.SecurityRule, 0, n)
	for i := range n {
		src := netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)}), 32)
		r := rule(strconv.Itoa(i+1), firemon.ActionPermit, "trust", "dmz",
			[]firemon.AddressRef{firemon.InlineAddress(firemon.PrefixEntry(src))}, []firemon.AddressRef{firemon.NamedAddress("web")}, "HTTPS")
		rules = append(rules, r)
	}
	return rules
}

func BenchmarkPlan(b *testing.B) {
	fw, err := firemon.Compile(lab(largeRules(2000)...))
	if err != nil {
		b.Fatal(err)
	}
	src, _ := traffic.ParseAddressSet("10.0.200.0/24")
	dst, _ := traffic.ParseAddressSet("172.16.0.10")
	svc, _ := traffic.ParseServiceSet("tcp/443")
	p := design.New(fw, design.Options{Now: func() time.Time { return now }})
	for b.Loop() {
		if _, err := p.Plan(design.Intent{Src: src, Dst: dst, Service: svc, Name: "bench"}); err != nil {
			b.Fatal(err)
		}
	}
}
