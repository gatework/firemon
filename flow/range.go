// Package flow implements exact address and packet-set algebra without enumerating addresses.
package flow

import (
	"encoding/binary"
	"errors"
	"iter"
	"net/netip"
	"slices"

	"github.com/gatework/set"
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
type AddressSet struct {
	v4 set.Set[uint32]
	v6 []AddressRange
}

func NewAddressSet(rs ...AddressRange) (AddressSet, error) {
	for _, r := range rs {
		if !r.Valid() {
			return AddressSet{}, ErrRange
		}
	}
	return normalize(rs), nil
}

// normalize owns its storage. Callers must validate ranges first: the integer
// set accepts reversed endpoints, while firewall address ranges reject them.
func normalize(rs []AddressRange) AddressSet {
	v4 := make([]set.Range[uint32], 0)
	v6 := make([]AddressRange, 0)
	for _, r := range rs {
		if r.First.Is4() {
			v4 = append(v4, set.Range[uint32]{Min: ipv4Number(r.First), Max: ipv4Number(r.Last)})
		} else {
			v6 = append(v6, r)
		}
	}
	return AddressSet{v4: *set.New(v4...), v6: normalizeIPv6(v6)}
}

// normalizeIPv6 sorts an owned slice; IPv4-mapped addresses remain IPv6.
func normalizeIPv6(rs []AddressRange) []AddressRange {
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
			if r.First.Compare(p.Last) <= 0 || next.IsValid() && next == r.First {
				if r.Last.Compare(p.Last) > 0 {
					p.Last = r.Last
				}
				continue
			}
		}
		out = append(out, r)
	}
	return out
}

// RangeCount returns the normalized interval count without copying ranges.
func (s AddressSet) RangeCount() int { return s.v4.Len() + len(s.v6) }

// All visits normalized ranges as values, IPv4 before IPv6, without allocating
// a detached slice. Stopping iteration does not change the immutable set.
func (s AddressSet) All() iter.Seq[AddressRange] {
	return func(yield func(AddressRange) bool) {
		for r := range s.v4.All() {
			if !yield(AddressRange{First: ipv4Address(r.Min), Last: ipv4Address(r.Max)}) {
				return
			}
		}
		for _, r := range s.v6 {
			if !yield(r) {
				return
			}
		}
	}
}

func (s AddressSet) Ranges() []AddressRange {
	if s.v4.IsEmpty() {
		return slices.Clone(s.v6)
	}
	out := make([]AddressRange, 0, s.RangeCount())
	return slices.AppendSeq(out, s.All())
}

func (s AddressSet) Empty() bool { return s.v4.IsEmpty() && len(s.v6) == 0 }

func (s AddressSet) ContainsAddr(a netip.Addr) bool {
	if a.Is4() {
		return s.v4.Contains(ipv4Number(a))
	}
	for _, r := range s.v6 {
		if r.Contains(a) {
			return true
		}
	}
	return false
}

func (s AddressSet) Contains(t AddressSet) bool {
	if !s.v4.IsSuperset(&t.v4) {
		return false
	}
	i := 0
	for _, r := range t.v6 {
		for i < len(s.v6) && s.v6[i].Last.Compare(r.First) < 0 {
			i++
		}
		if i == len(s.v6) || s.v6[i].First.Compare(r.First) > 0 || s.v6[i].Last.Compare(r.Last) < 0 {
			return false
		}
	}
	return true
}

func (s AddressSet) Union(t AddressSet) AddressSet {
	return AddressSet{
		v4: *s.v4.Union(&t.v4),
		v6: normalizeIPv6(append(slices.Clone(s.v6), t.v6...)),
	}
}

func (s AddressSet) Intersection(t AddressSet) AddressSet {
	var out []AddressRange
	for i, j := 0, 0; i < len(s.v6) && j < len(t.v6); {
		a, b := s.v6[i], t.v6[j]
		first, last := a.First, a.Last
		if b.First.Compare(first) > 0 {
			first = b.First
		}
		if b.Last.Compare(last) < 0 {
			last = b.Last
		}
		if first.Compare(last) <= 0 {
			out = append(out, AddressRange{first, last})
		}
		if a.Last.Compare(b.Last) < 0 {
			i++
		} else {
			j++
		}
	}
	// Ordered, disjoint inputs produce ordered, disjoint intersections.
	return AddressSet{v4: *s.v4.Intersection(&t.v4), v6: out}
}

func (s AddressSet) Difference(t AddressSet) AddressSet {
	if s.Empty() || t.Empty() {
		return s
	}
	// The integer set has no difference operation. Subtract closed address
	// intervals directly, preserving both families and endpoint bounds.
	out := subtract(s.Ranges(), t.Ranges())
	if len(out) == 0 {
		return AddressSet{}
	}
	var v4 []set.Range[uint32]
	for _, r := range out {
		if !r.First.Is4() {
			break
		}
		v4 = append(v4, set.Range[uint32]{Min: ipv4Number(r.First), Max: ipv4Number(r.Last)})
	}
	var v6 []AddressRange
	if len(out) > len(v4) {
		v6 = out[len(v4):]
		if len(v4) > 0 {
			// Do not retain converted IPv4 ranges in the IPv6 backing array.
			v6 = slices.Clone(v6)
		}
	}
	return AddressSet{v4: *set.New(v4...), v6: v6}
}

// subtract walks normalized intervals once, preserving their order and gaps.
// An exclusion may span several input intervals, so retain it until exhausted.
func subtract(rs, excluded []AddressRange) []AddressRange {
	var out []AddressRange
	j := 0
	for _, r := range rs {
		first := r.First
		for j < len(excluded) && excluded[j].Last.Compare(first) < 0 {
			j++
		}
		for j < len(excluded) && excluded[j].First.Compare(r.Last) <= 0 {
			b := excluded[j]
			if first.Compare(b.First) < 0 {
				out = append(out, AddressRange{first, b.First.Prev()})
			}
			if b.Last.Compare(r.Last) >= 0 {
				first = netip.Addr{}
				break
			}
			first = b.Last.Next()
			j++
		}
		if first.IsValid() {
			out = append(out, AddressRange{first, r.Last})
		}
	}
	return out
}

func ipv4Number(a netip.Addr) uint32 {
	b := a.As4()
	return binary.BigEndian.Uint32(b[:])
}

func ipv4Address(n uint32) netip.Addr {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], n)
	return netip.AddrFrom4(b)
}
