package paloalto

import (
	"net/netip"
	"slices"
	"strconv"

	fm "github.com/gatework/firemon"
)

type interfaceDraft struct {
	record    fm.InterfaceRecord
	ipv6      bool
	addresses map[netip.Prefix]bool
}

func (d interfaceDraft) value() fm.InterfaceRecord {
	r := d.record
	if d.ipv6 {
		prefixes := make([]netip.Prefix, 0, len(d.addresses))
		for prefix, enabled := range d.addresses {
			if enabled {
				prefixes = append(prefixes, prefix)
			}
		}
		slices.SortFunc(prefixes, func(a, b netip.Prefix) int { return a.Compare(b) })
		r.Addresses = append(r.Addresses, prefixes...)
	}
	return r
}

// interfacePath resolves the declared interface, including logical units.
// Interface families differ in syntax, while addresses and bindings share one draft.
func interfacePath(w []string) (string, []string, bool) {
	if len(w) < 4 {
		return "", nil, false
	}
	w = w[2:]
	switch w[0] {
	case "ethernet", "aggregate-ethernet":
		name := w[1]
		w = w[2:]
		if len(w) > 0 && (w[0] == "layer3" || w[0] == "layer2") {
			w = w[1:]
			if len(w) >= 2 && w[0] == "units" {
				name, w = w[1], w[2:]
			}
		}
		return name, w, true
	case "tunnel", "loopback", "vlan":
		if len(w) < 3 || w[1] != "units" {
			return "", nil, false
		}
		return w[2], w[3:], true
	}
	return "", nil, false
}

func (p *parser) iface(t *topology, row row) bool {
	name, fields, valid := interfacePath(row.words)
	if !valid || name == "" {
		return false
	}
	d := t.interfaces[name]
	r := &d.record
	if r.ID == "" {
		r.Object = object(name, row)
	} else {
		r.Spans = append(r.Spans, row.source.Span)
	}
	ok := len(fields) == 0
	if len(fields) > 0 {
		switch fields[0] {
		case "ip":
			ok = len(fields) > 1
			for _, value := range values(fields[1:]) {
				prefix, err := hostPrefix(value)
				if err != nil {
					prefix = p.prefixes[fm.ID(value)]
				}
				if !prefix.IsValid() || !prefix.Addr().Is4() {
					ok = false
					continue
				}
				if !slices.Contains(r.Addresses, prefix) {
					r.Addresses = append(r.Addresses, prefix)
				}
			}
		case "ipv6":
			if len(fields) == 3 && fields[1] == "enabled" && (fields[2] == "yes" || fields[2] == "no") {
				d.ipv6 = fields[2] == "yes"
				ok = true
			}
			if len(fields) >= 3 && fields[1] == "address" {
				prefix, err := hostPrefix(fields[2])
				enabled := slices.Equal(fields[3:], []string{"enable-on-interface", "yes"})
				disabled := slices.Equal(fields[3:], []string{"enable-on-interface", "no"})
				if err == nil && prefix.Addr().Is6() && (len(fields) == 3 || enabled || disabled) {
					if d.addresses == nil {
						d.addresses = make(map[netip.Prefix]bool)
					}
					if len(fields) > 3 {
						d.addresses[prefix] = enabled
					}
					ok = true
				}
			}
		case "comment", "interface-management-profile":
			ok = len(fields) == 2
		case "tag":
			if len(fields) == 2 {
				n, err := strconv.ParseUint(fields[1], 10, 12)
				ok = err == nil && n > 0 && n < 4095
			}
		}
	}
	if !ok {
		r.Unsupported = append(r.Unsupported, "unsupported interface field")
	}
	t.interfaces[name] = d
	return ok
}
