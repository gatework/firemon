package traffic

import (
	"slices"
	"strings"
)

// Region is a finite union of pairwise disjoint spaces. The zero value is
// empty. Operations return new regions and never modify their receiver.
//
// The number of spaces grows with each subtraction (at most three pieces
// per overlapping space), so callers evaluating long rule lists bound it
// with Len.
type Region struct {
	spaces []Space
}

// NewRegion returns the union of spaces.
func NewRegion(spaces ...Space) Region {
	var r Region
	for _, s := range spaces {
		r = r.Add(s)
	}
	return r
}

// Add returns r plus s, keeping the spaces disjoint.
func (r Region) Add(s Space) Region {
	pieces := []Space{s}
	for _, existing := range r.spaces {
		pieces = subtractAll(pieces, existing)
	}
	out := slices.Clip(r.spaces)
	for _, p := range pieces {
		if !p.IsEmpty() {
			out = append(out, p)
		}
	}
	return Region{spaces: out}
}

// AppendDisjoint returns r plus s without checking overlap. The caller
// guarantees that s is disjoint from every space of r; evaluation uses it
// for pieces split from one partition, where Add's subtraction is wasted.
func (r Region) AppendDisjoint(s Space) Region {
	if s.IsEmpty() {
		return r
	}
	return Region{spaces: append(slices.Clip(r.spaces), s)}
}

// DisjointRegion returns the region of spaces the caller guarantees to be
// pairwise disjoint, such as the pieces of one partition, without Add's
// subtraction. Empty spaces are dropped.
func DisjointRegion(spaces ...Space) Region {
	out := make([]Space, 0, len(spaces))
	for _, s := range spaces {
		if !s.IsEmpty() {
			out = append(out, s)
		}
	}
	return Region{spaces: out}
}

// Union returns the packets in r or o.
func (r Region) Union(o Region) Region {
	for _, s := range o.spaces {
		r = r.Add(s)
	}
	return r
}

// Subtract returns r minus s.
func (r Region) Subtract(s Space) Region {
	return Region{spaces: subtractAll(r.spaces, s)}
}

// SubtractRegion returns r minus every space of o.
func (r Region) SubtractRegion(o Region) Region {
	out := r.spaces
	for _, s := range o.spaces {
		out = subtractAll(out, s)
	}
	return Region{spaces: out}
}

// Intersect returns the packets of r that are also in s.
func (r Region) Intersect(s Space) Region {
	var out []Space
	for _, x := range r.spaces {
		if i := x.Intersect(s); !i.IsEmpty() {
			out = append(out, i)
		}
	}
	return Region{spaces: out}
}

// ContainsSpace reports whether every packet of s is in r.
func (r Region) ContainsSpace(s Space) bool {
	return NewRegion(s).SubtractRegion(r).IsEmpty()
}

// IsEmpty reports whether r holds no packet.
func (r Region) IsEmpty() bool { return len(r.spaces) == 0 }

// Len returns the number of disjoint spaces in r.
func (r Region) Len() int { return len(r.spaces) }

// Spaces returns a copy of the disjoint spaces of r.
func (r Region) Spaces() []Space { return slices.Clone(r.spaces) }

// Overlaps reports whether some packet of the region is in s.
func (r Region) Overlaps(s Space) bool {
	for _, x := range r.spaces {
		if x.Overlaps(s) {
			return true
		}
	}
	return false
}

// Bounds returns the smallest space containing the region: the union of
// its spaces in each dimension.
func (r Region) Bounds() Space {
	// Addresses are unioned in one pass: pairwise unions rebuild the set
	// once per space, quadratic on regions of many spaces.
	srcs, dsts := make([]AddressSet, len(r.spaces)), make([]AddressSet, len(r.spaces))
	var b Space
	for i, s := range r.spaces {
		srcs[i], dsts[i] = s.Src, s.Dst
		b.Service = b.Service.Union(s.Service)
	}
	b.Src, b.Dst = UnionAll(srcs...), UnionAll(dsts...)
	return b
}

// String writes the spaces separated by "; ".
func (r Region) String() string {
	if r.IsEmpty() {
		return "none"
	}
	parts := make([]string, len(r.spaces))
	for i, s := range r.spaces {
		parts[i] = s.String()
	}
	return strings.Join(parts, "; ")
}

// subtractAll returns spaces minus s. Spaces s does not touch are shared,
// not copied: when s touches none, the input itself is returned, which
// regions may do since they never modify their spaces.
func subtractAll(spaces []Space, s Space) []Space {
	first := slices.IndexFunc(spaces, s.Overlaps)
	if first < 0 {
		return spaces
	}
	out := make([]Space, first, len(spaces)+2)
	copy(out, spaces[:first])
	for _, x := range spaces[first:] {
		out = x.appendSubtract(out, s)
	}
	return out
}
