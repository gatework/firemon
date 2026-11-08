package flow_test

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"testing"

	"github.com/gatework/firemon/flow"
)

func BenchmarkAddressSet(b *testing.B) {
	for _, family := range []string{"ipv4", "ipv6"} {
		addr := func(n uint32) netip.Addr {
			if family == "ipv4" {
				var bytes [4]byte
				binary.BigEndian.PutUint32(bytes[:], n)
				return netip.AddrFrom4(bytes)
			}
			bytes := [16]byte{0x20, 0x01, 0x0d, 0xb8}
			binary.BigEndian.PutUint32(bytes[12:], n)
			return netip.AddrFrom16(bytes)
		}
		for _, count := range []int{128, 1024} {
			for _, shape := range []struct {
				name          string
				offset, width uint32
			}{
				{name: "disjoint", offset: 6, width: 1},
				{name: "overlap", offset: 2, width: 5},
				{name: "contained", offset: 1, width: 3},
			} {
				left, right := make([]flow.AddressRange, count), make([]flow.AddressRange, count)
				for i := range count {
					n := uint32(i) * 8
					left[i] = flow.AddressRange{First: addr(n), Last: addr(n + 5)}
					right[i] = flow.AddressRange{First: addr(n + shape.offset), Last: addr(n + shape.offset + shape.width)}
				}
				x, y := set(b, left...), set(b, right...)
				name := fmt.Sprintf("%s/%s/%d", family, shape.name, count)
				b.Run("difference/"+name, func(b *testing.B) {
					b.ReportAllocs()
					for b.Loop() {
						x.Difference(y)
					}
				})
				b.Run("intersection/"+name, func(b *testing.B) {
					b.ReportAllocs()
					for b.Loop() {
						x.Intersection(y)
					}
				})
				b.Run("contains/"+name, func(b *testing.B) {
					b.ReportAllocs()
					for b.Loop() {
						x.Contains(y)
					}
				})
			}
		}
	}
}
