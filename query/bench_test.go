package query_test

import (
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/query"
	"github.com/gatework/firemon/traffic"
)

// largeConfig returns a firewall with n rules over distinct /24 sources and
// host destinations, the shape of a large production rulebase.
func largeConfig(n int) *firemon.Config {
	cfg := lab(firemon.AddressStageOriginal)
	for i := range n {
		src := netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 0}), 24)
		dst := netip.PrefixFrom(netip.AddrFrom4([4]byte{172, 16, 0, byte(i)}), 32)
		action := firemon.ActionPermit
		if i%7 == 0 {
			action = firemon.ActionDeny
		}
		cfg.Rules = append(cfg.Rules, firemon.SecurityRule{
			ID: strconv.Itoa(i + 1), From: []string{"trust"}, To: []string{"dmz"}, Action: action,
			Source:      []firemon.AddressRef{firemon.InlineAddress(firemon.PrefixEntry(src))},
			Destination: []firemon.AddressRef{firemon.InlineAddress(firemon.PrefixEntry(dst))},
			ServiceEntries: []firemon.ServiceEntry{
				firemon.PortEntry(traffic.ProtocolTCP, traffic.Port(uint16(1000+i%50))),
			},
		})
	}
	return cfg
}

func BenchmarkCompile(b *testing.B) {
	cfg := largeConfig(2000)
	for b.Loop() {
		if _, err := firemon.Compile(cfg); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkQuery(b *testing.B) {
	fw, err := firemon.Compile(largeConfig(2000))
	if err != nil {
		b.Fatal(err)
	}
	e := query.New(fw, query.Options{Now: func() time.Time { return at }})
	cases := []struct {
		name string
		src  string
		dst  string
		svc  string
	}{
		{"host", "10.0.5.9", "172.16.0.5", "tcp/1005"},
		{"subnet-to-subnet", "10.0.0.0/16", "172.16.0.0/24", "tcp/1000-1049"},
	}
	for _, c := range cases {
		b.Run(c.name, func(b *testing.B) {
			src, _ := traffic.ParseAddressSet(c.src)
			dst, _ := traffic.ParseAddressSet(c.dst)
			svc, _ := traffic.ParseServiceSet(c.svc)
			for b.Loop() {
				if _, err := e.Query(query.Request{Src: src, Dst: dst, Service: svc}); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
