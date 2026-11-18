package traffic

import (
	"slices"

	"github.com/gatework/set"
)

// lattice is the set algebra a stripe value supports. The zero value of V
// must be the empty set.
type lattice[V any] interface {
	Union(o V) V
	Intersect(o V) V
	Subtract(o V) V
	Equal(o V) bool
	IsEmpty() bool
}

// band maps the inclusive key interval [lo, hi] to one value.
type band[K set.Integer, V lattice[V]] struct {
	lo, hi K
	v      V
}

// stripes is a canonical piecewise-constant map from keys to sets: bands are
// sorted, disjoint, hold non-empty values, and adjacent bands with equal
// values are merged. Two stripes are equal exactly when their bands are.
type stripes[K set.Integer, V lattice[V]] []band[K, V]

// combine applies op to the values of a and b over every elementary
// interval of their union of boundaries and returns the canonical result.
// A key missing from one side contributes the zero (empty) value.
func combine[K set.Integer, V lattice[V]](a, b stripes[K, V], op func(x, y V) V) stripes[K, V] {
	cuts := make([]uint64, 0, 2*(len(a)+len(b)))
	for _, s := range [...]stripes[K, V]{a, b} {
		for _, bd := range s {
			cuts = append(cuts, uint64(bd.lo), uint64(bd.hi)+1)
		}
	}
	slices.Sort(cuts)
	cuts = slices.Compact(cuts)
	var out stripes[K, V]
	for i := 0; i+1 < len(cuts); i++ {
		lo, hi := K(cuts[i]), K(cuts[i+1]-1)
		v := op(a.at(lo), b.at(lo))
		out = out.appendBand(lo, hi, v)
	}
	return out
}

// at returns the value covering key k, or the zero value.
func (s stripes[K, V]) at(k K) V {
	i, found := slices.BinarySearchFunc(s, k, func(bd band[K, V], k K) int {
		switch {
		case bd.hi < k:
			return -1
		case bd.lo > k:
			return 1
		default:
			return 0
		}
	})
	if !found {
		var zero V
		return zero
	}
	return s[i].v
}

// appendBand appends [lo, hi] -> v, dropping empty values and merging with a
// preceding adjacent band of equal value. Bands must arrive in key order.
func (s stripes[K, V]) appendBand(lo, hi K, v V) stripes[K, V] {
	if v.IsEmpty() {
		return s
	}
	if n := len(s); n > 0 && s[n-1].hi+1 == lo && s[n-1].hi < hi && s[n-1].v.Equal(v) {
		s[n-1].hi = hi
		return s
	}
	return append(s, band[K, V]{lo: lo, hi: hi, v: v})
}

func (s stripes[K, V]) union(o stripes[K, V]) stripes[K, V] {
	return combine(s, o, func(x, y V) V { return x.Union(y) })
}

func (s stripes[K, V]) intersect(o stripes[K, V]) stripes[K, V] {
	return combine(s, o, func(x, y V) V { return x.Intersect(y) })
}

func (s stripes[K, V]) subtract(o stripes[K, V]) stripes[K, V] {
	return combine(s, o, func(x, y V) V { return x.Subtract(y) })
}

func (s stripes[K, V]) equal(o stripes[K, V]) bool {
	return slices.EqualFunc(s, o, func(x, y band[K, V]) bool {
		return x.lo == y.lo && x.hi == y.hi && x.v.Equal(y.v)
	})
}
