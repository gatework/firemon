package firemon

import (
	"encoding/binary"
	"fmt"
	"math/bits"
	"net/netip"

	"github.com/gatework/firemon/flow"
)

func (f *Firewall) validateMatch(owner ID, m Match) {
	if !m.ZoneRelation.known() {
		f.issue(owner, "unsupported-match", "unknown zone relation")
	}
	for _, zones := range [][]ID{m.FromZones, m.ToZones} {
		for _, id := range zones {
			if f.zones[id] == nil {
				f.issue(owner, "missing-zone", string(id))
			}
		}
	}
	for _, reason := range m.Unsupported {
		f.issue(owner, "unsupported-match", reason)
	}
	if len(m.Applications) > 0 || len(m.Users) > 0 {
		f.issue(owner, "extended-match", "application/user match needs native evidence")
	}
	if m.Schedule != "" && f.schedules[m.Schedule] == nil {
		f.issue(owner, "missing-schedule", string(m.Schedule))
	}
}

func (z ZoneRelation) known() bool {
	switch z {
	case AnyZoneRelation, SameZone, DifferentZones:
		return true
	default:
		return false
	}
}

func validateService(t ServiceTerm) error {
	const octet, port = 255, 65535
	bounded := []struct {
		interval flow.Interval
		limit    uint16
	}{
		{t.Protocol, octet},
		{t.SourcePort, port},
		{t.DestinationPort, port},
		{t.ICMPType, octet},
		{t.ICMPCode, octet},
	}
	for _, b := range bounded {
		if b.interval.Low > b.interval.High || b.interval.High > b.limit {
			return fmt.Errorf("%w: invalid service interval", ErrGraph)
		}
	}
	return nil
}

// addressNumber is an address's unsigned 128-bit value; IPv4 uses its
// IPv4-mapped IPv6 form, so both families share one number space.
type addressNumber struct{ hi, lo uint64 }

func numberOf(a netip.Addr) addressNumber {
	b := a.As16()
	return addressNumber{hi: binary.BigEndian.Uint64(b[:8]), lo: binary.BigEndian.Uint64(b[8:])}
}

// minus returns x-y. Callers guarantee y <= x.
func (x addressNumber) minus(y addressNumber) addressNumber {
	lo, borrow := bits.Sub64(x.lo, y.lo, 0)
	hi, _ := bits.Sub64(x.hi, y.hi, borrow)
	return addressNumber{hi: hi, lo: lo}
}

// mappedAddress is an exact 129-bit translated value. A target plus offset may
// exceed the address space before mapping sizes are validated, so the carry
// keeps such values distinct instead of wrapping onto a real address.
type mappedAddress struct {
	carry uint64
	addressNumber
}

func (x addressNumber) plus(y addressNumber) mappedAddress {
	lo, carry := bits.Add64(x.lo, y.lo, 0)
	hi, carry := bits.Add64(x.hi, y.hi, carry)
	return mappedAddress{carry: carry, hi: hi, lo: lo}
}

// distance is Last-First of a valid range.
func distance(r flow.AddressRange) addressNumber { return numberOf(r.Last).minus(numberOf(r.First)) }

func (f *Firewall) validateMappings(owner ID, mappings []Mapping) error {
	for i, a := range mappings {
		for _, b := range mappings[:i] {
			overlap, ok := a.Original.Intersection(b.Original)
			if !ok || a.Mode == UnknownMapping || b.Mode == UnknownMapping {
				continue
			}
			if !a.Translated.Valid() || !b.Translated.Valid() {
				continue
			}
			for _, endpoint := range []netip.Addr{overlap.First, overlap.Last} {
				if mappedNumber(a, endpoint) != mappedNumber(b, endpoint) {
					return fmt.Errorf("%w: conflicting static mappings", ErrGraph)
				}
			}
		}
	}
	for _, m := range mappings {
		isSameFamily := m.Original.First.BitLen() == m.Translated.First.BitLen()
		if !m.Original.Valid() || !m.Translated.Valid() || !isSameFamily {
			return fmt.Errorf("%w: invalid nat address interval", ErrGraph)
		}
		switch m.Mode {
		case UnknownMapping:
			f.issue(owner, "unknown-mapping", "NAT relation not declared")
		case Identity:
			if m.Original != m.Translated {
				return fmt.Errorf("%w: identity relation changes addresses", ErrGraph)
			}
		case Offset:
			if distance(m.Original) != distance(m.Translated) {
				return fmt.Errorf("%w: unequal offset mapping sizes", ErrGraph)
			}
		case Constant:
			if m.Translated.First != m.Translated.Last {
				return fmt.Errorf("%w: constant relation requires single target", ErrGraph)
			}
		default:
			return fmt.Errorf("%w: invalid nat mapping mode", ErrGraph)
		}
	}
	return nil
}

func (f *Firewall) validatePorts(owner ID, mappings []PortMapping) error {
	for _, m := range mappings {
		if m.Original.Low > m.Original.High || m.Translated.Low > m.Translated.High {
			return fmt.Errorf("%w: invalid nat port interval", ErrGraph)
		}
		switch m.Mode {
		case UnknownMapping:
			f.issue(owner, "unknown-port-mapping", "port relation not declared")
		case Identity:
			if m.Original != m.Translated {
				return fmt.Errorf("%w: nonidentity port mapping", ErrGraph)
			}
		case Offset:
			if m.Original.High-m.Original.Low != m.Translated.High-m.Translated.Low {
				return fmt.Errorf("%w: unequal port offset sizes", ErrGraph)
			}
		case Constant:
			if m.Translated.Low != m.Translated.High {
				return fmt.Errorf("%w: port constant is not singular", ErrGraph)
			}
		default:
			return fmt.Errorf("%w: unknown port mapping enum", ErrGraph)
		}
	}
	return nil
}

// mappedNumber translates addr, which lies within m.Original.
func mappedNumber(m Mapping, addr netip.Addr) mappedAddress {
	target := numberOf(m.Translated.First)
	if m.Mode == Constant {
		return mappedAddress{addressNumber: target}
	}
	return target.plus(numberOf(addr).minus(numberOf(m.Original.First)))
}
