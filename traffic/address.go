package traffic

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"

	"go4.org/netipx"
)

// ErrInvalidAddress reports text that is not an address, prefix or range.
var ErrInvalidAddress = errors.New("traffic: invalid address")

// AddressSet is an immutable set of IPv4 and IPv6 addresses. The zero value
// is the empty set.
type AddressSet struct {
	// rs are the set's ranges in canonical form: sorted, disjoint and
	// merged (no two adjacent), empty exactly when the set is. Every
	// operation walks them in linear time; equal sets have equal ranges.
	rs []netipx.IPRange
}

// AnyAddress returns the set of every IPv4 and IPv6 address.
func AnyAddress() AddressSet { return anyAddress() }

// AnyIPv4 returns the set of every IPv4 address.
func AnyIPv4() AddressSet { return anyIPv4() }

// AnyIPv6 returns the set of every IPv6 address.
func AnyIPv6() AddressSet { return anyIPv6() }

// The constant sets are built once: AddressSet values are immutable, so
// sharing them is safe and evaluation loops do not rebuild them.
var (
	anyAddress = sync.OnceValue(func() AddressSet {
		return NewAddressSet(netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0"))
	})
	anyIPv4 = sync.OnceValue(func() AddressSet { return NewAddressSet(netip.MustParsePrefix("0.0.0.0/0")) })
	anyIPv6 = sync.OnceValue(func() AddressSet { return NewAddressSet(netip.MustParsePrefix("::/0")) })
)

// NewAddressSet returns the union of prefixes. Invalid prefixes are ignored;
// callers that accept untrusted text use ParseAddressSet instead.
func NewAddressSet(prefixes ...netip.Prefix) AddressSet {
	var b netipx.IPSetBuilder
	for _, p := range prefixes {
		if p.IsValid() {
			b.AddPrefix(unmapPrefix(p).Masked())
		}
	}
	return build(&b)
}

// AddressRange returns the inclusive range from..to. It returns the empty set
// when the endpoints are invalid, of different families, or reversed.
func AddressRange(from, to netip.Addr) AddressSet {
	r := netipx.IPRangeFrom(from.Unmap(), to.Unmap())
	if !r.IsValid() {
		return AddressSet{}
	}
	var b netipx.IPSetBuilder
	b.AddRange(r)
	return build(&b)
}

// ParseAddressSet parses a comma-separated list of addresses ("10.0.0.1"),
// prefixes ("10.0.0.0/8"), ranges ("10.0.0.1-10.0.0.9") and the keyword
// "any". Whitespace around items is ignored. An empty list is an error.
func ParseAddressSet(text string) (AddressSet, error) {
	var b netipx.IPSetBuilder
	items := 0
	for item := range strings.SplitSeq(text, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		items++
		if err := addAddressText(&b, item); err != nil {
			return AddressSet{}, err
		}
	}
	if items == 0 {
		return AddressSet{}, fmt.Errorf("%w: empty list", ErrInvalidAddress)
	}
	return build(&b), nil
}

// Union returns the addresses in s or o.
func (s AddressSet) Union(o AddressSet) AddressSet {
	switch {
	case len(o.rs) == 0:
		return s
	case len(s.rs) == 0:
		return o
	}
	return UnionAll(s, o)
}

// UnionAll returns the union of sets, built once rather than pairwise.
func UnionAll(sets ...AddressSet) AddressSet {
	var all []netipx.IPRange
	for _, s := range sets {
		all = append(all, s.rs...)
	}
	slices.SortFunc(all, func(a, b netipx.IPRange) int { return a.From().Compare(b.From()) })
	return AddressSet{rs: merged(all)}
}

// merged coalesces ranges sorted by start into canonical form.
func merged(rs []netipx.IPRange) []netipx.IPRange {
	var out []netipx.IPRange
	for _, r := range rs {
		if n := len(out); n > 0 {
			last := out[n-1]
			if !last.To().Less(r.From()) || last.To().Next() == r.From() {
				if last.To().Less(r.To()) {
					out[n-1] = netipx.IPRangeFrom(last.From(), r.To())
				}
				continue
			}
		}
		out = append(out, r)
	}
	return out
}

// Intersect returns the addresses in both s and o.
func (s AddressSet) Intersect(o AddressSet) AddressSet {
	switch {
	case s.IsEmpty() || o.IsEmpty() || !s.Overlaps(o):
		return AddressSet{}
	case covers(o.rs, s.rs):
		return s
	case covers(s.rs, o.rs):
		return o
	}
	// Pieces of distinct ranges of a merged list stay apart: the result
	// is canonical as built.
	var out []netipx.IPRange
	a, b := s.rs, o.rs
	for i, j := 0, 0; i < len(a) && j < len(b); {
		lo, hi := maxAddr(a[i].From(), b[j].From()), minAddr(a[i].To(), b[j].To())
		if !hi.Less(lo) {
			out = append(out, netipx.IPRangeFrom(lo, hi))
		}
		if a[i].To().Less(b[j].To()) {
			i++
		} else {
			j++
		}
	}
	return AddressSet{rs: out}
}

// Subtract returns the addresses in s that are not in o.
func (s AddressSet) Subtract(o AddressSet) AddressSet {
	switch {
	case s.IsEmpty() || o.IsEmpty() || !s.Overlaps(o):
		return s
	case covers(o.rs, s.rs):
		return AddressSet{}
	}
	var out []netipx.IPRange
	b, j := o.rs, 0
	for _, r := range s.rs {
		for j < len(b) && b[j].To().Less(r.From()) {
			j++
		}
		cur, done := r.From(), false
		for k := j; k < len(b) && !r.To().Less(b[k].From()); k++ {
			if cur.Less(b[k].From()) {
				out = append(out, netipx.IPRangeFrom(cur, b[k].From().Prev()))
			}
			if !b[k].To().Less(r.To()) {
				done = true
				break
			}
			cur = maxAddr(cur, b[k].To().Next())
		}
		if !done {
			out = append(out, netipx.IPRangeFrom(cur, r.To()))
		}
	}
	return AddressSet{rs: out}
}

func maxAddr(a, b netip.Addr) netip.Addr {
	if a.Less(b) {
		return b
	}
	return a
}

func minAddr(a, b netip.Addr) netip.Addr {
	if a.Less(b) {
		return a
	}
	return b
}

// IsEmpty reports whether s holds no address.
func (s AddressSet) IsEmpty() bool { return len(s.rs) == 0 }

// Equal reports whether s and o hold the same addresses.
func (s AddressSet) Equal(o AddressSet) bool { return slices.Equal(s.rs, o.rs) }

// Contains reports whether addr is in s. IPv4-mapped IPv6 addresses are
// treated as IPv4.
func (s AddressSet) Contains(addr netip.Addr) bool {
	addr = addr.Unmap()
	i, _ := slices.BinarySearchFunc(s.rs, addr, func(r netipx.IPRange, a netip.Addr) int { return r.To().Compare(a) })
	return i < len(s.rs) && !addr.Less(s.rs[i].From())
}

// ContainsSet reports whether every address of o is in s.
func (s AddressSet) ContainsSet(o AddressSet) bool { return o.IsEmpty() || covers(s.rs, o.rs) }

// covers reports whether every range of b lies within a range of a. Both
// are sorted, disjoint and merged (adjacent ranges are one), so a range of
// b inside a's union lies inside one range of a; one walk, no allocation.
func covers(a, b []netipx.IPRange) bool {
	i := 0
	for _, r := range b {
		for i < len(a) && a[i].To().Less(r.From()) {
			i++
		}
		if i == len(a) || r.From().Less(a[i].From()) || a[i].To().Less(r.To()) {
			return false
		}
	}
	return true
}

// Overlaps reports whether s and o share at least one address.
func (s AddressSet) Overlaps(o AddressSet) bool {
	// Both range lists are sorted and disjoint: advance whichever range
	// ends first until two ranges meet, in linear time.
	a, b := s.rs, o.rs
	if len(a) == 0 || len(b) == 0 || a[len(a)-1].To().Less(b[0].From()) || b[len(b)-1].To().Less(a[0].From()) {
		return false // the spans do not meet: most pairs end here
	}
	for i, j := 0, 0; i < len(a) && j < len(b); {
		switch {
		case a[i].To().Less(b[j].From()):
			i++
		case b[j].To().Less(a[i].From()):
			j++
		default:
			return true
		}
	}
	return false
}

// Relation classifies s against o.
func (s AddressSet) Relation(o AddressSet) Relation {
	return relate(s.Equal(o), s.ContainsSet(o), o.ContainsSet(s), s.Overlaps(o))
}

// Prefixes returns the minimal list of prefixes covering s, in address order.
func (s AddressSet) Prefixes() []netip.Prefix {
	var out []netip.Prefix
	for _, r := range s.rs {
		out = r.AppendPrefixes(out)
	}
	return out
}

// Ranges returns the minimal list of ranges covering s, in address order.
func (s AddressSet) Ranges() []netipx.IPRange {
	return slices.Clone(s.rs)
}

// Single returns the only address of s, or false when s is not one address.
func (s AddressSet) Single() (netip.Addr, bool) {
	r := s.Ranges()
	if len(r) != 1 || r[0].From() != r[0].To() {
		return netip.Addr{}, false
	}
	return r[0].From(), true
}

// String formats s canonically: ranges in address order, each written as a
// prefix when aligned and as "from-to" otherwise, joined by commas. The
// empty set is "none" and the full IPv4 plus IPv6 space is "any".
func (s AddressSet) String() string {
	if s.IsEmpty() {
		return "none"
	}
	if s.Equal(AnyAddress()) {
		return "any"
	}
	parts := make([]string, 0, len(s.rs))
	for _, r := range s.rs {
		parts = append(parts, FormatRange(r))
	}
	return strings.Join(parts, ",")
}

// MarshalText implements encoding.TextMarshaler with the String form.
func (s AddressSet) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// FormatRange writes r as an address, a prefix or "from-to".
func FormatRange(r netipx.IPRange) string {
	if r.From() == r.To() {
		return r.From().String()
	}
	if p, ok := r.Prefix(); ok {
		return p.String()
	}
	return r.From().String() + "-" + r.To().String()
}

func (s AddressSet) addTo(b *netipx.IPSetBuilder) {
	for _, r := range s.rs {
		b.AddRange(r)
	}
}

func addAddressText(b *netipx.IPSetBuilder, item string) error {
	if strings.EqualFold(item, "any") {
		AnyAddress().addTo(b)
		return nil
	}
	if from, to, ok := strings.Cut(item, "-"); ok {
		r, err := netipx.ParseIPRange(strings.TrimSpace(from) + "-" + strings.TrimSpace(to))
		if err != nil {
			return fmt.Errorf("%w: %q", ErrInvalidAddress, item)
		}
		b.AddRange(netipx.IPRangeFrom(r.From().Unmap(), r.To().Unmap()))
		return nil
	}
	if strings.Contains(item, "/") {
		p, err := netip.ParsePrefix(item)
		if err != nil {
			return fmt.Errorf("%w: %q", ErrInvalidAddress, item)
		}
		b.AddPrefix(unmapPrefix(p).Masked())
		return nil
	}
	a, err := netip.ParseAddr(item)
	if err != nil {
		return fmt.Errorf("%w: %q", ErrInvalidAddress, item)
	}
	b.Add(a.Unmap())
	return nil
}

// build finalizes b. Every caller adds only valid prefixes, ranges and sets,
// so netipx cannot report an error; a failure is a programming defect.
func build(b *netipx.IPSetBuilder) AddressSet {
	ips, err := b.IPSet()
	if err != nil {
		panic("traffic: invalid address set: " + err.Error())
	}
	return AddressSet{rs: ips.Ranges()}
}

// unmapPrefix turns an IPv4-mapped IPv6 prefix (::ffff:a.b.c.d/96+n) into
// the IPv4 prefix a.b.c.d/n.
func unmapPrefix(p netip.Prefix) netip.Prefix {
	if !p.Addr().Is4In6() || p.Bits() < 96 {
		return p
	}
	return netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
}
