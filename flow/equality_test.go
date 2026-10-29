package flow_test

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/gatework/firemon/flow"
)

func TestAllTrafficFamiliesAndMaximumEndpoints(t *testing.T) {
	all, err := flow.AllTraffic(2)
	if err != nil || all.RegionCount() != 2 {
		t.Fatal(all, err)
	}
	for _, family := range [][2]string{{"0.0.0.0", "255.255.255.255"}, {"::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"}} {
		for _, source := range family {
			for _, destination := range family {
				for _, maximum := range []bool{false, true} {
					packet := box(source, destination)
					packet.Protocol, packet.SourcePort, packet.DestinationPort, packet.ICMPType, packet.ICMPCode = flow.Interval{}, flow.Interval{}, flow.Interval{}, flow.Interval{}, flow.Interval{}
					if maximum {
						packet.Protocol, packet.ICMPType, packet.ICMPCode = flow.Interval{Low: 255, High: 255}, flow.Interval{Low: 255, High: 255}, flow.Interval{Low: 255, High: 255}
						packet.SourcePort, packet.DestinationPort = flow.Interval{Low: 65535, High: 65535}, flow.Interval{Low: 65535, High: 65535}
					}
					hits := 0
					for _, region := range all.Regions() {
						// Point membership uses only field comparisons; no production algebra.
						if region.Source.First.BitLen() == packet.Source.First.BitLen() &&
							region.Source.First.Compare(packet.Source.First) <= 0 && region.Source.Last.Compare(packet.Source.First) >= 0 &&
							region.Destination.First.Compare(packet.Destination.First) <= 0 && region.Destination.Last.Compare(packet.Destination.First) >= 0 &&
							region.Protocol.Low <= packet.Protocol.Low && region.Protocol.High >= packet.Protocol.High &&
							region.SourcePort.Low <= packet.SourcePort.Low && region.SourcePort.High >= packet.SourcePort.High &&
							region.DestinationPort.Low <= packet.DestinationPort.Low && region.DestinationPort.High >= packet.DestinationPort.High &&
							region.ICMPType.Low <= packet.ICMPType.Low && region.ICMPType.High >= packet.ICMPType.High &&
							region.ICMPCode.Low <= packet.ICMPCode.Low && region.ICMPCode.High >= packet.ICMPCode.High {
							hits++
						}
					}
					if hits != 1 {
						t.Fatalf("endpoint %+v matched %d regions", packet, hits)
					}
				}
			}
		}
	}
	for _, limit := range []int{-1, 0, 1} {
		got, err := flow.AllTraffic(limit)
		if !errors.Is(err, flow.ErrBudget) || !got.Empty() {
			t.Fatalf("limit %d: %v %v", limit, got, err)
		}
	}
}

func TestTrafficEqualPreservesDifferenceDirectionAndBudget(t *testing.T) {
	a := box("192.0.2.1", "198.51.100.1")
	b := a
	b.Source.First, b.Source.Last = netip.MustParseAddr("192.0.2.3"), netip.MustParseAddr("192.0.2.3")
	c := a
	c.Source.First, c.Source.Last = netip.MustParseAddr("192.0.2.5"), netip.MustParseAddr("192.0.2.5")
	one, _ := flow.NewTraffic(2, a)
	two, _ := flow.NewTraffic(2, b, c)
	includesOne, _ := flow.NewTraffic(2, a, b)
	for _, tc := range []struct {
		name          string
		left, right   flow.Traffic
		limit         int
		equal, budget bool
	}{
		{"empty", flow.Traffic{}, flow.Traffic{}, 1, true, false},
		{"invalid budget", flow.Traffic{}, flow.Traffic{}, 0, false, true},
		{"idempotent", one, one, 1, true, false},
		{"left short circuit", one, two, 1, false, false},
		{"reverse budget", two, one, 1, false, true},
		{"right budget after containment", one, includesOne, 1, false, true},
		{"empty left still checks right", flow.Traffic{}, two, 1, false, true},
		{"unequal", one, two, 2, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			same, err := tc.left.Equal(tc.right, tc.limit)
			if same != tc.equal || errors.Is(err, flow.ErrBudget) != tc.budget || (err != nil && !tc.budget) {
				t.Fatal(same, err)
			}
		})
	}
}
