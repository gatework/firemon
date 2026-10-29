// Package flow implements exact address and packet-set algebra without enumerating addresses.
package flow

import (
	"errors"
	"net/netip"
	"slices"
)

var ErrRange = errors.New("invalid address range")

// Range is a closed interval in one address family. Scoped IPv6 addresses are not configuration ranges.
type Range struct{ First, Last netip.Addr }

func (r Range) Valid() bool {
	return r.First.IsValid() && r.Last.IsValid() && r.First.Zone() == "" && r.Last.Zone() == "" && r.First.BitLen() == r.Last.BitLen() && r.First.Compare(r.Last) <= 0
}
func (r Range) Contains(a netip.Addr) bool {
	return r.Valid() && a.Zone() == "" && a.BitLen() == r.First.BitLen() && r.First.Compare(a) <= 0 && a.Compare(r.Last) <= 0
}
func (r Range) Intersection(s Range) (Range, bool) {
	if !r.Valid() || !s.Valid() || r.First.BitLen() != s.First.BitLen() {
		return Range{}, false
	}
	lo, hi := r.First, r.Last
	if s.First.Compare(lo) > 0 {
		lo = s.First
	}
	if s.Last.Compare(hi) < 0 {
		hi = s.Last
	}
	return Range{lo, hi}, lo.Compare(hi) <= 0
}
func PrefixRange(p netip.Prefix) (Range, error) {
	if !p.IsValid() || p.Addr().Zone() != "" {
		return Range{}, ErrRange
	}
	p = p.Masked()
	first := p.Addr()
	if first.Is4() {
		b := first.As4()
		for i := p.Bits(); i < 32; i++ {
			b[i/8] |= 1 << uint(7-i%8)
		}
		return Range{first, netip.AddrFrom4(b)}, nil
	}
	b := first.As16()
	for i := p.Bits(); i < 128; i++ {
		b[i/8] |= 1 << uint(7-i%8)
	}
	return Range{first, netip.AddrFrom16(b)}, nil
}

// Set is normalized, immutable and may contain separate IPv4 and IPv6 intervals. Its zero value is empty.
type Set struct{ ranges []Range }

func NewSet(rs ...Range) (Set, error) {
	for _, r := range rs {
		if !r.Valid() {
			return Set{}, ErrRange
		}
	}
	return normalize(slices.Clone(rs)), nil
}
func normalize(rs []Range) Set {
	slices.SortFunc(rs, func(a, b Range) int {
		if c := a.First.Compare(b.First); c != 0 {
			return c
		}
		return a.Last.Compare(b.Last)
	})
	out := make([]Range, 0, len(rs))
	for _, r := range rs {
		if len(out) > 0 {
			p := &out[len(out)-1]
			next := p.Last.Next()
			if p.First.BitLen() == r.First.BitLen() && (r.First.Compare(p.Last) <= 0 || next.IsValid() && next == r.First) {
				if r.Last.Compare(p.Last) > 0 {
					p.Last = r.Last
				}
				continue
			}
		}
		out = append(out, r)
	}
	return Set{ranges: out}
}

// RangeCount returns the normalized interval count without copying ranges.
func (s Set) RangeCount() int { return len(s.ranges) }

func (s Set) Ranges() []Range { return slices.Clone(s.ranges) }
func (s Set) Empty() bool     { return len(s.ranges) == 0 }
func (s Set) ContainsAddr(a netip.Addr) bool {
	for _, r := range s.ranges {
		if r.Contains(a) {
			return true
		}
	}
	return false
}
func (s Set) Contains(t Set) bool { return t.Difference(s).Empty() }
func (s Set) Union(t Set) Set     { return normalize(append(s.Ranges(), t.ranges...)) }
func (s Set) Intersection(t Set) Set {
	var out []Range
	for _, a := range s.ranges {
		for _, b := range t.ranges {
			if r, ok := a.Intersection(b); ok {
				out = append(out, r)
			}
		}
	}
	return normalize(out)
}
func (s Set) Difference(t Set) Set {
	out := s.Ranges()
	for _, b := range t.ranges {
		var next []Range
		for _, a := range out {
			x, ok := a.Intersection(b)
			if !ok {
				next = append(next, a)
				continue
			}
			if a.First.Compare(x.First) < 0 {
				next = append(next, Range{a.First, x.First.Prev()})
			}
			if x.Last.Compare(a.Last) < 0 {
				next = append(next, Range{x.Last.Next(), a.Last})
			}
		}
		out = next
	}
	return Set{ranges: out}
}
