package hillstone

import (
	"net/netip"
	"slices"
	"strings"

	"github.com/gatework/firemon"
)

// addressDraft collects one StoneOS address book entry across its forward
// declaration and definition. StoneOS has no separate group type: an
// address with member lines becomes a firemon.AddressGroup.
type addressDraft struct {
	name        string
	description string
	entries     []firemon.AddressEntry
	members     []string
	invalid     []string
	predefined  bool
}

func (d *addressDraft) isGroup() bool { return len(d.members) > 0 }

func (d *addressDraft) address() firemon.Address {
	return firemon.Address{Name: d.name, Description: d.description, Entries: slices.Clone(d.entries), Predefined: d.predefined, Invalid: slices.Clone(d.invalid)}
}

func (d *addressDraft) group() firemon.AddressGroup {
	return firemon.AddressGroup{
		Name: d.name, Description: d.description, Members: slices.Clone(d.members),
		Entries: slices.Clone(d.entries), Predefined: d.predefined, Invalid: slices.Clone(d.invalid),
	}
}

// address parses: address "NAME" [ipv6] [predefined]
//
//	ip A/LEN | ip A MASK | range A B | host "FQDN" [vrouter "VR"]
//	exclude ip ... | exclude range ... | member "NAME" | description "TEXT"
func (s *state) address(b block, head *words) {
	name := head.next()
	d := s.addresses.upsert(name, func() addressDraft { return addressDraft{name: name} })
	for !head.done() {
		if head.next() == "predefined" {
			d.predefined = true
		}
	}
	for _, l := range b.body {
		w := newWords(l.Text)
		kw := w.next()
		exclude := kw == "exclude"
		if exclude {
			kw = w.next()
		}
		switch kw {
		case "ip", "range", "host":
			e, ok := addressEntry(kw, w)
			if !ok {
				s.diagnose(l, "invalid address")
				d.invalid = append(d.invalid, strings.TrimSpace(l.Text))
				continue
			}
			e.Exclude = exclude
			d.entries = append(d.entries, e)
		case "member":
			d.members = append(d.members, w.next())
		case "description":
			d.description = w.next()
		default:
			continue
		}
		s.mark(l)
	}
}

// addressEntry parses the operand after ip, range or host.
func addressEntry(kind string, w *words) (firemon.AddressEntry, bool) {
	switch kind {
	case "ip":
		p, ok := parsePrefix(w.next(), w.peek())
		return firemon.PrefixEntry(p), ok
	case "range":
		from, err1 := netip.ParseAddr(w.next())
		to, err2 := netip.ParseAddr(w.next())
		return firemon.RangeEntry(from, to), err1 == nil && err2 == nil && from.Is4() == to.Is4() && !to.Less(from)
	case "host":
		name := w.next()
		return firemon.FQDNEntry(name), name != ""
	default:
		return firemon.AddressEntry{}, false
	}
}

// parsePrefix accepts "A/LEN" or "A" followed by a dotted mask.
func parsePrefix(text, mask string) (netip.Prefix, bool) {
	if p, err := netip.ParsePrefix(text); err == nil {
		return p.Masked(), true
	}
	addr, err := netip.ParseAddr(text)
	if err != nil {
		return netip.Prefix{}, false
	}
	if m, err := netip.ParseAddr(mask); err == nil && m.Is4() && addr.Is4() {
		bits, ok := maskBits(mask)
		if !ok {
			return netip.Prefix{}, false // non-contiguous mask
		}
		return netip.PrefixFrom(addr, bits).Masked(), true
	}
	if bits, ok := maskBits(mask); ok && addr.Is4() {
		return netip.PrefixFrom(addr, bits).Masked(), true
	}
	return netip.PrefixFrom(addr, addr.BitLen()), true
}

// maskBits converts a contiguous dotted netmask to a prefix length.
func maskBits(mask string) (int, bool) {
	m, err := netip.ParseAddr(mask)
	if err != nil || !m.Is4() {
		return 0, false
	}
	b := m.As4()
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	ones := 0
	for v&0x80000000 != 0 {
		ones++
		v <<= 1
	}
	return ones, v == 0
}

// interfacePrefix parses an interface address: "A/LEN" or "A MASK". The
// host bits are kept.
func interfacePrefix(addr, mask string) (netip.Prefix, bool) {
	if p, err := netip.ParsePrefix(addr); err == nil {
		return p, true
	}
	a, err := netip.ParseAddr(addr)
	if err != nil {
		return netip.Prefix{}, false
	}
	bits, ok := maskBits(mask)
	if !ok {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(a, bits), true
}
