package audit_test

import (
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/audit"
	"github.com/gatework/firemon/traffic"
)

func BenchmarkRun(b *testing.B) {
	cfg := &firemon.Config{Vendor: firemon.VendorHillstone}
	for i := range 2000 {
		src := netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 0}), 24)
		cfg.Rules = append(cfg.Rules, firemon.SecurityRule{
			ID: strconv.Itoa(i + 1), Action: firemon.ActionPermit,
			Source:         []firemon.AddressRef{firemon.InlineAddress(firemon.PrefixEntry(src))},
			ServiceEntries: []firemon.ServiceEntry{firemon.PortEntry(traffic.ProtocolTCP, traffic.Port(uint16(1000+i%50)))},
		})
	}
	fw, err := firemon.Compile(cfg)
	if err != nil {
		b.Fatal(err)
	}
	opts := audit.Options{Now: func() time.Time { return now }}
	for b.Loop() {
		audit.Run(fw, opts)
	}
}
