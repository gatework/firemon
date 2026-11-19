package traffic

import (
	"math/rand/v2"
	"net/netip"
	"testing"

	"go4.org/netipx"
)

// reference computes a set operation with the set builder only.
func reference(a, b AddressSet, op func(*netipx.IPSetBuilder, *netipx.IPSet)) AddressSet {
	var bld netipx.IPSetBuilder
	a.addTo(&bld)
	other := b.ips
	if other == nil {
		var empty netipx.IPSetBuilder
		other, _ = empty.IPSet()
	}
	op(&bld, other)
	return build(&bld)
}

// TestSetOps_FastPathsAgree compares Intersect, Subtract and ContainsSet,
// which settle common cases on the ranges, with the set builder.
func TestSetOps_FastPathsAgree(t *testing.T) {
	t.Parallel()
	rng := rand.New(rand.NewPCG(1, 2))
	random := func() AddressSet {
		var b netipx.IPSetBuilder
		for range rng.IntN(4) {
			from := netip.AddrFrom4([4]byte{10, 0, byte(rng.IntN(4)), byte(rng.IntN(256))})
			to := from
			for range rng.IntN(300) {
				to = to.Next()
			}
			b.AddRange(netipx.IPRangeFrom(from, to))
		}
		return build(&b)
	}
	for range 20000 {
		a, b := random(), random()
		if got, want := a.Intersect(b), reference(a, b, (*netipx.IPSetBuilder).Intersect); !got.Equal(want) {
			t.Fatalf("%s ∩ %s = %s, want %s", a, b, got, want)
		}
		if got, want := a.Subtract(b), reference(a, b, (*netipx.IPSetBuilder).RemoveSet); !got.Equal(want) {
			t.Fatalf("%s - %s = %s, want %s", a, b, got, want)
		}
		if got, want := a.ContainsSet(b), reference(b, a, (*netipx.IPSetBuilder).RemoveSet).IsEmpty(); got != want {
			t.Fatalf("%s ⊇ %s = %v, want %v", a, b, got, want)
		}
	}
}

// TestRegion_UnionAgreesWithAdd: Union and NewRegion, built in one slice,
// hold the same packets as adding spaces one by one, and stay disjoint.
func TestRegion_UnionAgreesWithAdd(t *testing.T) {
	t.Parallel()
	rng := rand.New(rand.NewPCG(3, 4))
	space := func() Space {
		lo := byte(rng.IntN(200))
		src := AddressRange(netip.AddrFrom4([4]byte{10, 0, 0, lo}), netip.AddrFrom4([4]byte{10, 0, 0, lo + byte(rng.IntN(50))}))
		dst := AddressRange(netip.AddrFrom4([4]byte{10, 1, 0, lo}), netip.AddrFrom4([4]byte{10, 1, 0, lo + byte(rng.IntN(50))}))
		port := uint16(rng.IntN(100))
		return Space{Src: src, Dst: dst, Service: PortService(ProtocolTCP, PortRange{Low: port, High: port + uint16(rng.IntN(20))})}
	}
	for range 500 {
		var spaces []Space
		for range rng.IntN(8) {
			spaces = append(spaces, space())
		}
		var added Region
		for _, s := range spaces {
			added = added.Add(s)
		}
		half := len(spaces) / 2
		for _, got := range []Region{NewRegion(spaces...), NewRegion(spaces[:half]...).Union(NewRegion(spaces[half:]...))} {
			if !got.SubtractRegion(added).IsEmpty() || !added.SubtractRegion(got).IsEmpty() {
				t.Fatalf("union %s, added %s", got, added)
			}
			for i, a := range got.spaces {
				for _, b := range got.spaces[i+1:] {
					if a.Overlaps(b) {
						t.Fatalf("spaces overlap: %s and %s", a, b)
					}
				}
			}
		}
	}
}
