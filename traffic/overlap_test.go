package traffic

import (
	"math/rand/v2"
	"net/netip"
	"testing"
)

// The linear overlap walk agrees with the pairwise netipx test on random
// sets of both families.
func TestAddressSet_OverlapsMatchesPairwise(t *testing.T) {
	t.Parallel()
	rng := rand.New(rand.NewPCG(1, 2))
	set := func() AddressSet {
		var ps []netip.Prefix
		for range rng.IntN(6) {
			if rng.IntN(4) == 0 {
				var b [16]byte
				b[0], b[15] = 0x20, byte(rng.IntN(256))
				ps = append(ps, netip.PrefixFrom(netip.AddrFrom16(b), 120+rng.IntN(9)))
				continue
			}
			a := netip.AddrFrom4([4]byte{10, byte(rng.IntN(4)), byte(rng.IntN(256)), byte(rng.IntN(256))})
			ps = append(ps, netip.PrefixFrom(a, 16+rng.IntN(17)))
		}
		return NewAddressSet(ps...)
	}
	for range 20000 {
		a, b := set(), set()
		want := !a.IsEmpty() && !b.IsEmpty() && ipSet(a).Overlaps(ipSet(b))
		if got := a.Overlaps(b); got != want {
			t.Fatalf("%s overlaps %s: %v, want %v", a, b, got, want)
		}
	}
}
