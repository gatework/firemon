package traffic

import (
	"math"
	"strconv"
	"strings"

	"github.com/gatework/set"
)

// PortRange is an inclusive range of 16-bit numbers: TCP, UDP and SCTP ports,
// or an ICMP type and code encoded as type<<8 | code.
type PortRange struct {
	Low  uint16 `json:"low"`
	High uint16 `json:"high"`
}

// AnyPort covers every port number.
var AnyPort = PortRange{Low: 0, High: math.MaxUint16}

// Port returns the single-port range p..p.
func Port(p uint16) PortRange { return PortRange{Low: p, High: p} }

// IsAny reports whether r covers every port.
func (r PortRange) IsAny() bool { return r == AnyPort }

// String writes "80", "80-90" or "any".
func (r PortRange) String() string {
	switch {
	case r.IsAny():
		return "any"
	case r.Low == r.High:
		return strconv.Itoa(int(r.Low))
	default:
		return strconv.Itoa(int(r.Low)) + "-" + strconv.Itoa(int(r.High))
	}
}

// PortSet is an immutable set of 16-bit numbers. The zero value is empty.
type PortSet struct {
	s *set.Set[uint16] // nil means empty; never mutated after construction
}

// NewPortSet returns the union of ranges. Reversed endpoints are swapped.
func NewPortSet(ranges ...PortRange) PortSet {
	if len(ranges) == 0 {
		return PortSet{}
	}
	rs := make([]set.Range[uint16], len(ranges))
	for i, r := range ranges {
		rs[i] = set.Range[uint16]{Min: r.Low, Max: r.High}
	}
	return PortSet{s: set.New(rs...)}
}

// AllPorts returns the set of every port number.
func AllPorts() PortSet { return NewPortSet(AnyPort) }

// Union returns the ports in p or o.
func (p PortSet) Union(o PortSet) PortSet {
	switch {
	case p.IsEmpty():
		return o
	case o.IsEmpty():
		return p
	}
	return PortSet{s: p.s.Union(o.s)}
}

// Intersect returns the ports in both p and o.
func (p PortSet) Intersect(o PortSet) PortSet {
	if p.IsEmpty() || o.IsEmpty() {
		return PortSet{}
	}
	return normalized(p.s.Intersection(o.s))
}

// Subtract returns the ports in p that are not in o.
func (p PortSet) Subtract(o PortSet) PortSet {
	if p.IsEmpty() || o.IsEmpty() {
		return p
	}
	return normalized(p.s.Intersection(complement(o.s)))
}

// IsEmpty reports whether p holds no port.
func (p PortSet) IsEmpty() bool { return p.s == nil || p.s.IsEmpty() }

// IsAll reports whether p holds every port.
func (p PortSet) IsAll() bool { return !p.IsEmpty() && p.s.Equal(AllPorts().s) }

// Equal reports whether p and o hold the same ports.
func (p PortSet) Equal(o PortSet) bool {
	if p.IsEmpty() || o.IsEmpty() {
		return p.IsEmpty() == o.IsEmpty()
	}
	return p.s.Equal(o.s)
}

// Contains reports whether port is in p.
func (p PortSet) Contains(port uint16) bool { return p.s != nil && p.s.Contains(port) }

// ContainsSet reports whether every port of o is in p.
func (p PortSet) ContainsSet(o PortSet) bool { return o.Subtract(p).IsEmpty() }

// Ranges returns the disjoint ranges of p in ascending order.
func (p PortSet) Ranges() []PortRange {
	if p.IsEmpty() {
		return nil
	}
	out := make([]PortRange, 0, p.s.Len())
	for r := range p.s.All() {
		out = append(out, PortRange{Low: r.Min, High: r.Max})
	}
	return out
}

// String writes the ranges joined by commas, "any" or "none".
func (p PortSet) String() string {
	switch {
	case p.IsEmpty():
		return "none"
	case p.IsAll():
		return "any"
	}
	parts := make([]string, 0, p.s.Len())
	for _, r := range p.Ranges() {
		parts = append(parts, r.String())
	}
	return strings.Join(parts, ",")
}

func normalized(s *set.Set[uint16]) PortSet {
	if s.IsEmpty() {
		return PortSet{}
	}
	return PortSet{s: s}
}

// complement returns every uint16 not in s.
func complement(s *set.Set[uint16]) *set.Set[uint16] {
	out := set.New[uint16]()
	next := uint32(0)
	for r := range s.All() {
		if uint32(r.Min) > next {
			out.Add(uint16(next), r.Min-1)
		}
		next = uint32(r.Max) + 1
	}
	if next <= math.MaxUint16 {
		out.Add(uint16(next), math.MaxUint16)
	}
	return out
}
