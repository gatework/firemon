package hillstone

import (
	"fmt"
	"strings"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
)

func (p *parser) selector(r *fm.RuleRecord, w []string, d *fm.Data) bool {
	if len(w) < 2 {
		return false
	}
	m := &r.Match
	switch w[0] {
	case "src-zone", "dst-zone":
		if len(w) != 2 {
			return false
		}
		if w[0] == "src-zone" {
			m.AnyFromZone = strings.EqualFold(w[1], "any")
			if !m.AnyFromZone {
				m.FromZones = append(m.FromZones, fm.ID(w[1]))
				if r.Scope == "" {
					r.Scope = p.topology.zoneVRF[fm.ID(w[1])]
				}
			}
		} else {
			m.AnyToZone = strings.EqualFold(w[1], "any")
			if !m.AnyToZone {
				m.ToZones = append(m.ToZones, fm.ID(w[1]))
			}
		}
		return true
	case "src-addr", "dst-addr":
		if len(w) != 2 {
			return false
		}
		if w[0] == "src-addr" {
			if strings.EqualFold(w[1], "any") {
				m.AnySource = true
			} else {
				m.Sources = append(m.Sources, p.catalog.addressRef(w[1]))
			}
		} else {
			if strings.EqualFold(w[1], "any") {
				m.AnyDestination = true
			} else {
				m.Destinations = append(m.Destinations, p.catalog.addressRef(w[1]))
			}
		}
		return true
	case "service":
		if len(w) != 2 {
			return false
		}
		if strings.EqualFold(w[1], "any") {
			m.AnyService = true
		} else {
			m.Services = append(m.Services, p.catalog.serviceRef(w[1]))
		}
		return true
	case "src-ip", "dst-ip", "src-range", "dst-range":
		value := w[1]
		if strings.HasSuffix(w[0], "-range") {
			if len(w) != 3 {
				return false
			}
			value += "-" + w[2]
		} else if len(w) != 2 {
			return false
		}
		addr, err := literal(value)
		if err != nil {
			return false
		}
		// Inline values belong to this rule and have no device declaration name.
		id := fm.ID(fmt.Sprintf("$rule:%s:%d", r.ID, len(d.Addresses)))
		for p.catalog.addresses[id] != fm.UnknownObject {
			id += "_"
		}
		p.catalog.addresses[id] = fm.AddressObject
		d.Addresses = append(d.Addresses, fm.AddressRecord{Object: fm.Object{ID: id, Scope: r.Scope, Inline: true}, Ranges: []flow.AddressRange{addr}})
		ref := fm.AddressRef{Kind: fm.AddressObject, ID: id}
		if strings.HasPrefix(w[0], "src-") {
			m.Sources = append(m.Sources, ref)
		} else {
			m.Destinations = append(m.Destinations, ref)
		}
		return true
	}
	return false
}
