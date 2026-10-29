// Package flow implements exact address and packet-set algebra without enumerating addresses.
package flow

import (
	"errors"
	"net/netip"
	"slices"
)

var ErrRange = errors.New("invalid address range")

// AddressRange is a closed interval in one address family. Scoped IPv6 addresses are not configuration ranges.
type AddressRange struct{ First, Last netip.Addr }

func (r AddressRange) Valid() bool {
	return r.First.IsValid() && r.Last.IsValid() && r.First.Zone() == "" && r.Last.Zone() == "" && r.First.BitLen() == r.Last.BitLen() && r.First.Compare(r.Last) <= 0
}
func (r AddressRange) Contains(a netip.Addr) bool {
	return r.Valid() && a.Zone() == "" && a.BitLen() == r.First.BitLen() && r.First.Compare(a) <= 0 && a.Compare(r.Last) <= 0
}
func (r AddressRange) Intersection(s AddressRange) (AddressRange, bool) {
	if !r.Valid() || !s.Valid() || r.First.BitLen() != s.First.BitLen() {
		return AddressRange{}, false
	}
	lo, hi := r.First, r.Last
	if s.First.Compare(lo) > 0 {
		lo = s.First
	}
	if s.Last.Compare(hi) < 0 {
		hi = s.Last
	}
	return AddressRange{lo, hi}, lo.Compare(hi) <= 0
}
func PrefixRange(p netip.Prefix) (AddressRange, error) {
	if !p.IsValid() || p.Addr().Zone() != "" {
		return AddressRange{}, ErrRange
	}
	p = p.Masked()
	first := p.Addr()
	if first.Is4() {
		b := first.As4()
		for i := p.Bits(); i < 32; i++ {
			b[i/8] |= 1 << uint(7-i%8)
		}
		return AddressRange{first, netip.AddrFrom4(b)}, nil
	}
	b := first.As16()
	for i := p.Bits(); i < 128; i++ {
		b[i/8] |= 1 << uint(7-i%8)
	}
	return AddressRange{first, netip.AddrFrom16(b)}, nil
}

// AddressSet is normalized, immutable and may contain separate IPv4 and IPv6 intervals. Its zero value is empty.
type AddressSet struct{ ranges []AddressRange }

func NewAddressSet(rs ...AddressRange) (AddressSet, error) {
	for _, r := range rs {
		if !r.Valid() {
			return AddressSet{}, ErrRange
		}
	}
	return normalize(slices.Clone(rs)), nil
}
func normalize(rs []AddressRange) AddressSet {
	slices.SortFunc(rs, func(a, b AddressRange) int {
		if c := a.First.Compare(b.First); c != 0 {
			return c
		}
		return a.Last.Compare(b.Last)
	})
	out := make([]AddressRange, 0, len(rs))
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
	return AddressSet{ranges: out}
}

// RangeCount returns the normalized interval count without copying ranges.
func (s AddressSet) RangeCount() int { return len(s.ranges) }

func (s AddressSet) Ranges() []AddressRange { return slices.Clone(s.ranges) }
func (s AddressSet) Empty() bool            { return len(s.ranges) == 0 }
func (s AddressSet) ContainsAddr(a netip.Addr) bool {
	for _, r := range s.ranges {
		if r.Contains(a) {
			return true
		}
	}
	return false
}
func (s AddressSet) Contains(t AddressSet) bool    { return t.Difference(s).Empty() }
func (s AddressSet) Union(t AddressSet) AddressSet { return normalize(append(s.Ranges(), t.ranges...)) }
func (s AddressSet) Intersection(t AddressSet) AddressSet {
	var out []AddressRange
	for _, a := range s.ranges {
		for _, b := range t.ranges {
			if r, ok := a.Intersection(b); ok {
				out = append(out, r)
			}
		}
	}
	return normalize(out)
}
func (s AddressSet) Difference(t AddressSet) AddressSet {
	out := s.Ranges()
	for _, b := range t.ranges {
		var next []AddressRange
		for _, a := range out {
			x, ok := a.Intersection(b)
			if !ok {
				next = append(next, a)
				continue
			}
			if a.First.Compare(x.First) < 0 {
				next = append(next, AddressRange{a.First, x.First.Prev()})
			}
			if x.Last.Compare(a.Last) < 0 {
				next = append(next, AddressRange{x.Last.Next(), a.Last})
			}
		}
		out = next
	}
	return AddressSet{ranges: out}
}
