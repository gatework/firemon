package firemon

import (
	"math/big"
	"math/rand/v2"
	"net/netip"
	"testing"

	"github.com/gatework/firemon/flow"
)

// referenceDistance and referenceMapped are the unbounded-precision relations
// that the fixed-width arithmetic must reproduce exactly.
func referenceDistance(r flow.AddressRange) *big.Int {
	first, last := r.First.As16(), r.Last.As16()
	return new(big.Int).Sub(new(big.Int).SetBytes(last[:]), new(big.Int).SetBytes(first[:]))
}

func referenceMapped(m Mapping, addr netip.Addr) *big.Int {
	first, target, input := m.Original.First.As16(), m.Translated.First.As16(), addr.As16()
	n := new(big.Int).SetBytes(target[:])
	if m.Mode == Constant {
		return n
	}
	return n.Add(n, new(big.Int).Sub(new(big.Int).SetBytes(input[:]), new(big.Int).SetBytes(first[:])))
}

func randomAddr(r *rand.Rand, edges []netip.Addr) netip.Addr {
	if r.IntN(3) == 0 {
		return edges[r.IntN(len(edges))]
	}
	var b [16]byte
	for i := range b {
		b[i] = byte(r.Uint32())
	}
	if r.IntN(2) == 0 {
		return netip.AddrFrom4([4]byte(b[:4]))
	}
	return netip.AddrFrom16(b)
}

func ordered(a, b netip.Addr) flow.AddressRange {
	if b.Less(a) {
		a, b = b, a
	}
	return flow.AddressRange{First: a, Last: b}
}

func TestMappingArithmeticMatchesUnboundedPrecision(t *testing.T) {
	edges := []netip.Addr{
		netip.MustParseAddr("0.0.0.0"),
		netip.MustParseAddr("255.255.255.255"),
		netip.MustParseAddr("::"),
		netip.MustParseAddr("::1"),
		netip.MustParseAddr("::ffff:ffff:ffff"),
		netip.MustParseAddr("0:0:0:1::"),
		netip.MustParseAddr("0:0:0:0:ffff:ffff:ffff:ffff"),
		netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe"),
		netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
	}
	r := rand.New(rand.NewPCG(1, 2))
	var equalDistances, equalMappings int
	for range 20000 {
		a := ordered(randomAddr(r, edges), randomAddr(r, edges))
		b := ordered(randomAddr(r, edges), randomAddr(r, edges))
		if a.Valid() && b.Valid() {
			got := distance(a) == distance(b)
			expected := referenceDistance(a).Cmp(referenceDistance(b)) == 0
			if got != expected {
				t.Fatalf("distance equality of %v and %v: got %v, expected %v", a, b, got, expected)
			}
			if got {
				equalDistances++
			}
		}
		randomMapping := func(original flow.AddressRange) Mapping {
			translated := ordered(randomAddr(r, edges), randomAddr(r, edges))
			return Mapping{Original: original, Translated: translated, Mode: MappingMode(r.IntN(4))}
		}
		ma, mb := randomMapping(a), randomMapping(b)
		overlap, ok := a.Intersection(b)
		if !ok {
			continue
		}
		for _, endpoint := range []netip.Addr{overlap.First, overlap.Last} {
			got := mappedNumber(ma, endpoint) == mappedNumber(mb, endpoint)
			expected := referenceMapped(ma, endpoint).Cmp(referenceMapped(mb, endpoint)) == 0
			if got != expected {
				t.Fatalf("mapped equality at %v for %+v and %+v: got %v, expected %v", endpoint, ma, mb, got, expected)
			}
			if got {
				equalMappings++
			}
		}
	}
	if equalDistances == 0 || equalMappings == 0 {
		t.Fatalf("vacuous comparison: %d equal distances, %d equal mappings", equalDistances, equalMappings)
	}
	t.Logf("%d equal distances, %d equal mappings", equalDistances, equalMappings)
}

// A target plus offset beyond the address space must stay distinct from the
// wrapped real address it would alias in 128-bit arithmetic.
func TestMappedAddressKeepsCarryDistinct(t *testing.T) {
	top := netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
	zero := netip.MustParseAddr("::")
	one := netip.MustParseAddr("::1")
	overflowing := Mapping{
		Original:   flow.AddressRange{First: zero, Last: one},
		Translated: flow.AddressRange{First: top, Last: top},
		Mode:       Offset,
	}
	wrapped := Mapping{
		Original:   flow.AddressRange{First: one, Last: one},
		Translated: flow.AddressRange{First: zero, Last: zero},
		Mode:       Offset,
	}
	if mappedNumber(overflowing, one) == mappedNumber(wrapped, one) {
		t.Fatal("2^128 aliased address zero")
	}
	if referenceMapped(overflowing, one).Cmp(referenceMapped(wrapped, one)) == 0 {
		t.Fatal("reference relation changed")
	}
}
