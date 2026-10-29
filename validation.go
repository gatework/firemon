package firemon

import (
	"fmt"
	"math/big"
	"net/netip"
	"slices"

	"github.com/gatework/firemon/flow"
)

func (f *Firewall) validateMatch(owner ID, m Match) {
	if m.ZoneRelation != AnyZoneRelation && m.ZoneRelation != SameZone && m.ZoneRelation != DifferentZones {
		f.issue(owner, "unsupported-match", "unknown zone relation")
	}
	for _, id := range append(slices.Clone(m.FromZones), m.ToZones...) {
		if f.zones[id] == nil {
			f.issue(owner, "missing-zone", string(id))
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

func validateService(t ServiceTerm) error {
	for i, r := range []flow.Interval{t.Protocol, t.SourcePort, t.DestinationPort, t.ICMPType, t.ICMPCode} {
		max := uint16(65535)
		if i == 0 || i > 2 {
			max = 255
		}
		if r.Low > r.High || r.High > max {
			return fmt.Errorf("%w: invalid service interval", ErrGraph)
		}
	}
	return nil
}

func distance(r flow.AddressRange) *big.Int {
	first, last := r.First.As16(), r.Last.As16()
	return new(big.Int).Sub(new(big.Int).SetBytes(last[:]), new(big.Int).SetBytes(first[:]))
}

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
				if mappedNumber(a, endpoint).Cmp(mappedNumber(b, endpoint)) != 0 {
					return fmt.Errorf("%w: conflicting static mappings", ErrGraph)
				}
			}
		}
	}
	for _, m := range mappings {
		if !m.Original.Valid() || !m.Translated.Valid() || m.Original.First.BitLen() != m.Translated.First.BitLen() {
			return fmt.Errorf("%w: invalid NAT address interval", ErrGraph)
		}
		switch m.Mode {
		case UnknownMapping:
			f.issue(owner, "unknown-mapping", "NAT relation not declared")
		case Identity:
			if m.Original != m.Translated {
				return fmt.Errorf("%w: identity relation changes addresses", ErrGraph)
			}
		case Offset:
			if distance(m.Original).Cmp(distance(m.Translated)) != 0 {
				return fmt.Errorf("%w: unequal offset mapping sizes", ErrGraph)
			}
		case Constant:
			if m.Translated.First != m.Translated.Last {
				return fmt.Errorf("%w: constant relation requires single target", ErrGraph)
			}
		default:
			return fmt.Errorf("%w: invalid NAT mapping mode", ErrGraph)
		}
	}
	return nil
}

func (f *Firewall) validatePorts(owner ID, mappings []PortMapping) error {
	for _, m := range mappings {
		if m.Original.Low > m.Original.High || m.Translated.Low > m.Translated.High {
			return fmt.Errorf("%w: invalid NAT port interval", ErrGraph)
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

func mappedNumber(m Mapping, addr netip.Addr) *big.Int {
	first, target, input := m.Original.First.As16(), m.Translated.First.As16(), addr.As16()
	n := new(big.Int).SetBytes(target[:])
	if m.Mode == Constant {
		return n
	}
	return n.Add(n, new(big.Int).Sub(new(big.Int).SetBytes(input[:]), new(big.Int).SetBytes(first[:])))
}
