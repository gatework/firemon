package traffic

// Space is the product of source addresses, destination addresses and
// services: the shape matched by one rule. A space is empty when any of its
// dimensions is empty.
type Space struct {
	Src     AddressSet
	Dst     AddressSet
	Service ServiceSet
}

// AnySpace returns the space of every packet.
func AnySpace() Space {
	return Space{Src: AnyAddress(), Dst: AnyAddress(), Service: AnyService()}
}

// IsEmpty reports whether the space holds no packet.
func (s Space) IsEmpty() bool {
	return s.Src.IsEmpty() || s.Dst.IsEmpty() || s.Service.IsEmpty()
}

// Intersect returns the packets in both s and o.
func (s Space) Intersect(o Space) Space {
	return Space{Src: s.Src.Intersect(o.Src), Dst: s.Dst.Intersect(o.Dst), Service: s.Service.Intersect(o.Service)}
}

// Overlaps reports whether s and o share a packet. It checks the address
// dimensions without allocating before intersecting services.
func (s Space) Overlaps(o Space) bool {
	return s.Src.Overlaps(o.Src) && s.Dst.Overlaps(o.Dst) && s.Service.Overlaps(o.Service)
}

// ContainsSpace reports whether every packet of o is in s.
func (s Space) ContainsSpace(o Space) bool {
	return o.IsEmpty() || (s.Src.ContainsSet(o.Src) && s.Dst.ContainsSet(o.Dst) && s.Service.ContainsSet(o.Service))
}

// Equal reports whether s and o hold the same packets.
func (s Space) Equal(o Space) bool {
	if s.IsEmpty() || o.IsEmpty() {
		return s.IsEmpty() == o.IsEmpty()
	}
	return s.Src.Equal(o.Src) && s.Dst.Equal(o.Dst) && s.Service.Equal(o.Service)
}

// Subtract returns s minus o as at most three disjoint spaces:
// the sources outside o; then the shared sources with destinations outside
// o; then the shared sources and destinations with services outside o.
func (s Space) Subtract(o Space) []Space { return s.appendSubtract(nil, o) }

// String writes "src -> dst service".
func (s Space) String() string {
	return s.Src.String() + " -> " + s.Dst.String() + " " + s.Service.String()
}

// appendSubtract appends s minus o to dst, so that subtracting from many
// spaces fills one slice.
func (s Space) appendSubtract(dst []Space, o Space) []Space {
	if s.IsEmpty() {
		return dst
	}
	if !s.Src.Overlaps(o.Src) || !s.Dst.Overlaps(o.Dst) || !s.Service.Overlaps(o.Service) {
		return append(dst, s)
	}
	inter := s.Intersect(o)
	if inter.IsEmpty() {
		return append(dst, s)
	}
	for _, p := range [...]Space{
		{Src: s.Src.Subtract(o.Src), Dst: s.Dst, Service: s.Service},
		{Src: inter.Src, Dst: s.Dst.Subtract(o.Dst), Service: s.Service},
		{Src: inter.Src, Dst: inter.Dst, Service: s.Service.Subtract(o.Service)},
	} {
		if !p.IsEmpty() {
			dst = append(dst, p)
		}
	}
	return dst
}
