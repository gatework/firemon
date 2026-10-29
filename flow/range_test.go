package flow_test

import (
	"net/netip"
	"testing"

	"github.com/gatework/firemon/flow"
)

func address(s string) netip.Addr    { return netip.MustParseAddr(s) }
func iprange(a, b string) flow.Range { return flow.Range{First: address(a), Last: address(b)} }
func set(t *testing.T, rs ...flow.Range) flow.Set {
	t.Helper()
	s, err := flow.NewSet(rs...)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSetNormalizesAndSubtractsWithoutEnumerating(t *testing.T) {
	a := set(t, iprange("192.0.2.128", "192.0.2.255"), iprange("192.0.2.0", "192.0.2.127"))
	if len(a.Ranges()) != 1 {
		t.Fatal(a.Ranges())
	}
	b := set(t, iprange("192.0.2.64", "192.0.2.191"))
	got := a.Difference(b).Ranges()
	if len(got) != 2 || got[0] != iprange("192.0.2.0", "192.0.2.63") || got[1] != iprange("192.0.2.192", "192.0.2.255") {
		t.Fatal(got)
	}
	if !a.Contains(b) || b.Contains(a) {
		t.Fatal("subset reversed")
	}
	rs := a.Ranges()
	rs[0].Last = address("192.0.2.0")
	if !a.Contains(b) {
		t.Fatal("mutable slice escaped")
	}
}
func TestRangeRejectsMixedFamilyAndPreservesIPv6Maximum(t *testing.T) {
	if _, err := flow.NewSet(iprange("0.0.0.0", "::1")); err == nil {
		t.Fatal("mixed range accepted")
	}
	r, err := flow.PrefixRange(netip.MustParsePrefix("::/0"))
	if err != nil {
		t.Fatal(err)
	}
	if r.Last != address("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff") {
		t.Fatal(r)
	}
	a := set(t, r)
	b := set(t, iprange("::1", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"))
	got := a.Difference(b).Ranges()
	if len(got) != 1 || got[0] != iprange("::", "::") {
		t.Fatal(got)
	}
}
func FuzzSetAgainstByteOracle(f *testing.F) {
	f.Add(uint8(0), uint8(255), uint8(64), uint8(191))
	f.Fuzz(func(t *testing.T, a, b, c, d uint8) {
		if a > b {
			a, b = b, a
		}
		if c > d {
			c, d = d, c
		}
		addr := func(n uint8) netip.Addr { return netip.AddrFrom4([4]byte{192, 0, 2, n}) }
		x := set(t, flow.Range{First: addr(a), Last: addr(b)})
		y := set(t, flow.Range{First: addr(c), Last: addr(d)})
		diff, intersection, union := x.Difference(y), x.Intersection(y), x.Union(y)
		for i := 0; i < 256; i++ {
			inX, inY := i >= int(a) && i <= int(b), i >= int(c) && i <= int(d)
			if diff.ContainsAddr(addr(uint8(i))) != (inX && !inY) || intersection.ContainsAddr(addr(uint8(i))) != (inX && inY) || union.ContainsAddr(addr(uint8(i))) != (inX || inY) {
				t.Fatalf("wrong membership at %d", i)
			}
		}
	})
}
