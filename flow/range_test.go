package flow_test

import (
	"errors"
	"net/netip"
	"slices"
	"testing"

	"github.com/gatework/firemon/flow"
)

func address(s string) netip.Addr { return netip.MustParseAddr(s) }
func iprange(a, b string) flow.AddressRange {
	return flow.AddressRange{First: address(a), Last: address(b)}
}
func set(t testing.TB, rs ...flow.AddressRange) flow.AddressSet {
	t.Helper()
	s, err := flow.NewAddressSet(rs...)
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

func TestAddressSetIterationPreservesOrderAndOwnership(t *testing.T) {
	want := []flow.AddressRange{
		iprange("192.0.2.0", "192.0.2.127"),
		iprange("198.51.100.1", "198.51.100.1"),
		iprange("::ffff:192.0.2.1", "::ffff:192.0.2.1"),
		iprange("2001:db8::", "2001:db8::ffff"),
	}
	s := set(t, want...)
	for _, stop := range []int{1, 3, len(want)} {
		var got []flow.AddressRange
		for r := range s.All() {
			got = append(got, r)
			if len(got) == stop {
				break
			}
		}
		if !slices.Equal(got, want[:stop]) {
			t.Fatalf("stop %d: %v", stop, got)
		}
		got[0] = flow.AddressRange{}
		if !slices.Equal(slices.Collect(s.All()), want) {
			t.Fatal("iteration or output mutation changed the set")
		}
	}
	for range (flow.AddressSet{}).All() {
		t.Fatal("empty set yielded a range")
	}
}
func TestRangeRejectsMixedFamilyAndPreservesIPv6Maximum(t *testing.T) {
	if _, err := flow.NewAddressSet(iprange("0.0.0.0", "::1")); err == nil {
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

func TestAddressSetRejectsInvalidRanges(t *testing.T) {
	for _, r := range []flow.AddressRange{
		{},
		iprange("192.0.2.2", "192.0.2.1"),
		iprange("2001:db8::2", "2001:db8::1"),
		iprange("fe80::1%eth0", "fe80::2%eth0"),
	} {
		if _, err := flow.NewAddressSet(r); !errors.Is(err, flow.ErrRange) {
			t.Fatalf("range %v: got %v, want ErrRange", r, err)
		}
	}
}

func TestAddressSetPreservesFamiliesAndCopies(t *testing.T) {
	v4 := iprange("192.0.2.0", "192.0.2.127")
	mapped := iprange("::ffff:192.0.2.0", "::ffff:192.0.2.127")
	v6 := iprange("2001:db8::", "2001:db8::7f")
	input := []flow.AddressRange{v6, mapped, v4}
	original := set(t, input...)
	copied := original
	input[0] = flow.AddressRange{}
	exported := copied.Ranges()
	exported[0] = flow.AddressRange{}

	more := set(t,
		iprange("192.0.2.128", "192.0.2.255"),
		iprange("::ffff:192.0.2.128", "::ffff:192.0.2.255"),
		iprange("2001:db8::80", "2001:db8::ff"),
	)
	union := copied.Union(more)
	intersection := union.Intersection(copied)
	difference := union.Difference(copied)
	want := []flow.AddressRange{v4, mapped, v6}
	for _, got := range []flow.AddressSet{original, copied, intersection} {
		if !slices.Equal(got.Ranges(), want) {
			t.Fatalf("input ownership or family order changed: %v", got.Ranges())
		}
	}
	if !slices.Equal(difference.Ranges(), more.Ranges()) || !union.Contains(copied) || copied.Contains(union) {
		t.Fatal("mixed-family set operation changed membership")
	}
	if set(t, mapped).ContainsAddr(v4.First) || set(t, v4).ContainsAddr(mapped.First) {
		t.Fatal("IPv4-mapped IPv6 was collapsed into IPv4")
	}
	if copied.ContainsAddr(netip.Addr{}) || copied.ContainsAddr(address("2001:db8::1%eth0")) {
		t.Fatal("invalid or scoped address matched")
	}
	var empty flow.AddressSet
	if !empty.Empty() || !empty.Contains(empty) || !copied.Contains(empty) || empty.Contains(copied) {
		t.Fatal("zero-value set semantics changed")
	}
}

func TestAddressSetPreservesIPv4Boundaries(t *testing.T) {
	all := set(t,
		iprange("128.0.0.0", "255.255.255.255"),
		iprange("0.0.0.0", "127.255.255.255"),
	)
	want := []flow.AddressRange{iprange("0.0.0.0", "255.255.255.255")}
	if !slices.Equal(all.Ranges(), want) {
		t.Fatal(all.Ranges())
	}
	edges := set(t, iprange("0.0.0.0", "0.0.0.0"), iprange("255.255.255.255", "255.255.255.255"))
	got := all.Difference(edges)
	want = []flow.AddressRange{iprange("0.0.0.1", "255.255.255.254")}
	if !slices.Equal(got.Ranges(), want) || !all.Difference(all).Empty() {
		t.Fatal("boundary subtraction wrapped", got.Ranges())
	}
	if !slices.Equal(got.Union(edges).Ranges(), all.Ranges()) {
		t.Fatal("boundary union lost addresses")
	}
}

func TestAddressSetOrderedOperations(t *testing.T) {
	for _, tc := range []struct {
		name                string
		source, excluded    []flow.AddressRange
		difference, overlap []flow.AddressRange
		contains            bool
	}{
		{
			name:       "exclusion crosses gaps",
			source:     []flow.AddressRange{iprange("::", "::4"), iprange("::8", "::c"), iprange("::10", "::18")},
			excluded:   []flow.AddressRange{iprange("::2", "::12")},
			difference: []flow.AddressRange{iprange("::", "::1"), iprange("::13", "::18")},
			overlap:    []flow.AddressRange{iprange("::2", "::4"), iprange("::8", "::c"), iprange("::10", "::12")},
		},
		{
			name:       "exclusions split one interval",
			source:     []flow.AddressRange{iprange("::", "::10")},
			excluded:   []flow.AddressRange{iprange("::", "::1"), iprange("::4", "::6"), iprange("::f", "::10")},
			difference: []flow.AddressRange{iprange("::2", "::3"), iprange("::7", "::e")},
			overlap:    []flow.AddressRange{iprange("::", "::1"), iprange("::4", "::6"), iprange("::f", "::10")},
			contains:   true,
		},
		{
			name:       "ipv6 endpoints",
			source:     []flow.AddressRange{iprange("::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")},
			excluded:   []flow.AddressRange{iprange("::", "::"), iprange("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")},
			difference: []flow.AddressRange{iprange("::1", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe")},
			overlap:    []flow.AddressRange{iprange("::", "::"), iprange("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")},
			contains:   true,
		},
		{
			name:       "family boundary",
			source:     []flow.AddressRange{iprange("255.255.255.254", "255.255.255.255"), iprange("::", "::1"), iprange("::ffff:192.0.2.0", "::ffff:192.0.2.2")},
			excluded:   []flow.AddressRange{iprange("255.255.255.255", "255.255.255.255"), iprange("::", "::"), iprange("192.0.2.0", "192.0.2.2")},
			difference: []flow.AddressRange{iprange("255.255.255.254", "255.255.255.254"), iprange("::1", "::1"), iprange("::ffff:192.0.2.0", "::ffff:192.0.2.2")},
			overlap:    []flow.AddressRange{iprange("255.255.255.255", "255.255.255.255"), iprange("::", "::")},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source, excluded := set(t, tc.source...), set(t, tc.excluded...)
			beforeSource, beforeExcluded := source.Ranges(), excluded.Ranges()
			difference, overlap := source.Difference(excluded), source.Intersection(excluded)
			if got := difference.Ranges(); !slices.Equal(got, tc.difference) {
				t.Fatalf("difference: %v, want %v", got, tc.difference)
			}
			if got := overlap.Ranges(); !slices.Equal(got, tc.overlap) {
				t.Fatalf("intersection: %v, want %v", got, tc.overlap)
			}
			if source.Contains(excluded) != tc.contains {
				t.Fatalf("containment: want %v", tc.contains)
			}
			for _, result := range []flow.AddressSet{difference, overlap, source.Difference(flow.AddressSet{}), source.Intersection(source)} {
				owned := result.Ranges()
				for i := range owned {
					owned[i] = flow.AddressRange{}
				}
			}
			if !slices.Equal(source.Ranges(), beforeSource) || !slices.Equal(excluded.Ranges(), beforeExcluded) {
				t.Fatal("operation or exported result mutated an input")
			}
		})
	}
}

func FuzzAddressSetOracle(f *testing.F) {
	f.Add([]byte{0, 0, 0, 31, 1, 0, 10, 20, 0, 1, 0, 31, 1, 1, 10, 20, 0, 2, 0, 31, 1, 2, 10, 20})
	f.Add([]byte{0, 2, 0, 4, 0, 2, 8, 12, 0, 2, 16, 24, 1, 2, 2, 18})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		data = data[:min(len(data), 256)]
		addr := func(family, n int) netip.Addr {
			switch family {
			case 0:
				return netip.AddrFrom4([4]byte{192, 0, 2, byte(n)})
			case 1:
				return netip.AddrFrom16([16]byte{10: 0xff, 11: 0xff, 12: 192, 14: 2, 15: byte(n)})
			default:
				return netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 15: byte(n)})
			}
		}
		var ranges [2][]flow.AddressRange
		var model [2][3][32]bool
		for i := 0; i+3 < len(data); i += 4 {
			side, family := int(data[i]%2), int(data[i+1]%3)
			lo, hi := int(data[i+2]%32), int(data[i+3]%32)
			if lo > hi {
				lo, hi = hi, lo
			}
			ranges[side] = append(ranges[side], flow.AddressRange{First: addr(family, lo), Last: addr(family, hi)})
			for n := lo; n <= hi; n++ {
				model[side][family][n] = true
			}
		}
		x, y := set(t, ranges[0]...), set(t, ranges[1]...)
		difference, overlap, union := x.Difference(y), x.Intersection(y), x.Union(y)
		contains := true
		for family := range 3 {
			for n := range 32 {
				a, b := model[0][family][n], model[1][family][n]
				if b && !a {
					contains = false
				}
				address := addr(family, n)
				if difference.ContainsAddr(address) != (a && !b) || overlap.ContainsAddr(address) != (a && b) || union.ContainsAddr(address) != (a || b) {
					t.Fatalf("wrong membership for %v", address)
				}
			}
		}
		if x.Contains(y) != contains {
			t.Fatal("wrong containment")
		}
		for _, result := range []flow.AddressSet{difference, overlap, union} {
			rs := result.Ranges()
			for i, r := range rs {
				if !r.Valid() || i > 0 && (rs[i-1].Last.Compare(r.First) >= 0 || rs[i-1].Last.Next() == r.First) {
					t.Fatal("result is not normalized", rs)
				}
			}
		}
	})
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
		x := set(t, flow.AddressRange{First: addr(a), Last: addr(b)})
		y := set(t, flow.AddressRange{First: addr(c), Last: addr(d)})
		diff, intersection, union := x.Difference(y), x.Intersection(y), x.Union(y)
		for i := range 256 {
			inX, inY := i >= int(a) && i <= int(b), i >= int(c) && i <= int(d)
			if diff.ContainsAddr(addr(uint8(i))) != (inX && !inY) || intersection.ContainsAddr(addr(uint8(i))) != (inX && inY) || union.ContainsAddr(addr(uint8(i))) != (inX || inY) {
				t.Fatalf("wrong membership at %d", i)
			}
		}
	})
}
