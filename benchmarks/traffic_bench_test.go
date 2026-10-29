package benchmarks_test

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/gatework/firemon/flow"
)

func algebraInputs(tb testing.TB, family, n int) (flow.Traffic, flow.Traffic) {
	tb.Helper()
	a, b := make([]flow.TrafficRegion, n), make([]flow.TrafficRegion, n)
	for i := range n {
		src, dst := host(i), netip.MustParseAddr("203.0.113.10")
		if family == 6 {
			src = netip.MustParseAddr(fmt.Sprintf("2001:db8::%x", i+1))
			dst = netip.MustParseAddr("2001:db8:1::1")
		}
		a[i] = flow.TrafficRegion{Source: flow.AddressRange{First: src, Last: src}, Destination: flow.AddressRange{First: dst, Last: dst},
			Protocol: flow.Interval{Low: 6, High: 6}, SourcePort: flow.Interval{Low: 1000, High: 65535},
			DestinationPort: flow.Interval{Low: 443, High: 443}, ICMPType: flow.Interval{High: 255}, ICMPCode: flow.Interval{High: 255}}
		b[i] = a[i]
		b[i].SourcePort = flow.Interval{Low: 32768, High: 65535}
		b[i].DestinationPort.High = 444
	}
	x, err := flow.NewTraffic(4096, a...)
	if err != nil {
		tb.Fatal(err)
	}
	y, err := flow.NewTraffic(4096, b...)
	if err != nil {
		tb.Fatal(err)
	}
	return x, y
}

func BenchmarkTraffic(b *testing.B) {
	for _, family := range []int{4, 6} {
		for _, n := range []int{16, 128} {
			a, other := algebraInputs(b, family, n)
			for _, op := range []struct {
				name string
				run  func(flow.Traffic, int) (flow.Traffic, error)
			}{{"union", a.Union}, {"intersection", a.Intersection}, {"difference", a.Difference}} {
				b.Run(fmt.Sprintf("%s/ipv%d/regions=%d", op.name, family, n), func(b *testing.B) {
					b.ReportAllocs()
					for b.Loop() {
						got, err := op.run(other, 4096)
						if err != nil || got.Empty() {
							b.Fatalf("traffic operation: %v", err)
						}
					}
				})
			}
		}
	}
}
