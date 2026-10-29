package flow_test

import (
	"errors"
	"net/netip"
	"reflect"
	"testing"

	"github.com/gatework/firemon/flow"
)

// Exhaust all 128 packets in a two-value, seven-dimensional domain. Integer
// membership is independent of the region splitting/normalization algorithm.
func FuzzTrafficAgainstPacketOracle(f *testing.F) {
	f.Add(uint64(0x123456789abcde), false)
	f.Add(uint64(0xfffffffffffffff), true)
	f.Fuzz(func(t *testing.T, seed uint64, ipv6 bool) {
		limit := int(seed%32) + 1
		addr := func(n uint16) netip.Addr {
			if ipv6 {
				return netip.AddrFrom16([16]byte{0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, byte(n)})
			}
			return netip.AddrFrom4([4]byte{192, 0, 2, byte(n)})
		}
		var bounds [4][7]flow.Interval
		var boxes [4]flow.TrafficRegion
		for n := range boxes {
			for axis := range bounds[n] {
				a, b := uint16(seed&1), uint16((seed>>1)&1)
				seed >>= 2
				bounds[n][axis] = flow.Interval{Low: min(a, b), High: max(a, b)}
			}
			v := bounds[n]
			boxes[n] = flow.TrafficRegion{Source: flow.AddressRange{First: addr(v[0].Low), Last: addr(v[0].High)}, Destination: flow.AddressRange{First: addr(v[1].Low), Last: addr(v[1].High)}, Protocol: v[2], SourcePort: v[3], DestinationPort: v[4], ICMPType: v[5], ICMPCode: v[6]}
		}
		x, err := flow.NewTraffic(4096, boxes[:2]...)
		if err != nil {
			t.Fatal(err)
		}
		y, err := flow.NewTraffic(4096, boxes[2:]...)
		if err != nil {
			t.Fatal(err)
		}
		beforeX, beforeY := x.Regions(), y.Regions()
		canonical, canonicalErr := flow.NewTraffic(limit, append(x.Regions(), y.Regions()...)...)
		bounded, boundedErr := x.Union(y, limit)
		if !errors.Is(canonicalErr, boundedErr) || !reflect.DeepEqual(canonical.Regions(), bounded.Regions()) {
			t.Fatalf("union changed construction or budget at limit %d: %v / %v", limit, canonicalErr, boundedErr)
		}

		diff, err := x.Difference(y, 4096)
		if err != nil {
			t.Fatal(err)
		}
		union, err := x.Union(y, 4096)
		if err != nil {
			t.Fatal(err)
		}
		intersection, err := x.Intersection(y, 4096)
		if err != nil {
			t.Fatal(err)
		}
		contains := func(b flow.TrafficRegion, packet int) bool {
			values := [7]uint16{}
			for axis := range values {
				values[axis] = uint16((packet >> axis) & 1)
			}
			if addr(values[0]).Compare(b.Source.First) < 0 || addr(values[0]).Compare(b.Source.Last) > 0 || addr(values[1]).Compare(b.Destination.First) < 0 || addr(values[1]).Compare(b.Destination.Last) > 0 {
				return false
			}
			axes := [5]flow.Interval{b.Protocol, b.SourcePort, b.DestinationPort, b.ICMPType, b.ICMPCode}
			for axis, v := range axes {
				if values[axis+2] < v.Low || values[axis+2] > v.High {
					return false
				}
			}
			return true
		}
		for packet := range 128 {
			inX, inY := contains(boxes[0], packet) || contains(boxes[1], packet), contains(boxes[2], packet) || contains(boxes[3], packet)
			for _, tc := range []struct {
				got  flow.Traffic
				want bool
			}{{diff, inX && !inY}, {union, inX || inY}, {intersection, inX && inY}} {
				matches := 0
				for _, b := range tc.got.Regions() {
					if contains(b, packet) {
						matches++
					}
				}
				if (matches == 1) != tc.want || matches > 1 {
					t.Fatalf("packet %d: got %d matches, want %v", packet, matches, tc.want)
				}
			}
		}
		if !reflect.DeepEqual(beforeX, x.Regions()) || !reflect.DeepEqual(beforeY, y.Regions()) {
			t.Fatal("operand mutated")
		}
	})
}
