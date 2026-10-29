package fortinet

import (
	"context"
	"net/netip"
	"slices"
	"strconv"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
)

func prefix(values []string) (netip.Prefix, bool) {
	if len(values) != 2 {
		return netip.Prefix{}, false
	}
	a, e := netip.ParseAddr(values[0])
	if e != nil || !a.Is4() {
		return netip.Prefix{}, false
	}
	m, e := netip.ParseAddr(values[1])
	if e != nil || !m.Is4() {
		return netip.Prefix{}, false
	}
	bits, zero := 0, false
	for _, b := range m.As4() {
		for bit := 7; bit >= 0; bit-- {
			if b&(1<<bit) == 0 {
				zero = true
			} else {
				if zero {
					return netip.Prefix{}, false
				}
				bits++
			}
		}
	}
	return netip.PrefixFrom(a, bits), true
}
func (p *parser) network(ctx context.Context, s *config.Session) error {
	tx := s.Cursor().Begin()
	defer tx.Rollback()
	var d fm.Data
	err := p.each(ctx, tx, "system interface", func(b *config.Block) {
		// Global interfaces carry their own VDOM. Inspect only this selector
		// before interpreting fields, so another domain's syntax stays opaque.
		defaultDomain := p.interfaceDomains[b]
		domain := defaultDomain
		declarations := 0
		for _, r := range b.Members {
			if len(r.Words) >= 2 && r.Words[0] == "set" && r.Words[1] == "vdom" {
				declarations++
				if len(r.Words) == 3 {
					domain = r.Words[2]
				} else {
					domain = ""
				}
			}
		}
		if declarations <= 1 && domain != "" && domain != p.vdom {
			ignoreBlock(tx, b, "interface belongs to a different VDOM")
			return
		}
		name := b.Header.Words[1]
		r := fm.InterfaceRecord{Object: object(name, name, p.vdom)}
		f := readFields(tx, b, &r.Object)
		if f.one("vdom", defaultDomain) != p.vdom {
			f.invalid("vdom")
		}
		if f.one("vrf", "0") != "0" {
			f.invalid("nondefault interface VRF")
		}
		mode := f.choice("mode", "static", "static", "dhcp", "pppoe")
		if mode != "static" {
			f.invalid("runtime interface address")
		}
		if v := f.list("ip"); len(v) > 0 {
			if address, ok := prefix(v); ok {
				if !address.Addr().IsUnspecified() {
					r.Addresses = []netip.Prefix{address}
				} else if address.Bits() != 0 {
					f.invalid("unspecified interface address")
				}
			} else {
				f.invalid("ip")
			}
		}
		r.Disabled = f.choice("status", "up", "up", "down") == "down"
		f.choice("type", "physical", "physical", "vlan", "aggregate", "loopback", "tunnel", "hard-switch")
		// The logical VLAN interface owns its own addresses and routes.
		f.one("interface", "")
		if id := f.one("vlanid", ""); id != "" {
			n, e := strconv.ParseUint(id, 10, 12)
			if e != nil || n == 0 {
				f.invalid("vlanid")
			}
		}
		f.ignore("alias", "description", "allowaccess", "role", "snmp-index")
		f.finish()
		d.Interfaces = append(d.Interfaces, r)
		p.interfaces[r.ID] = r
	})
	if err != nil {
		return err
	}
	members := make(map[fm.ID]fm.ID)
	err = p.each(ctx, tx, "system zone", func(b *config.Block) {
		name := b.Header.Words[1]
		z := fm.ZoneRecord{Object: object(name, name, p.vdom)}
		f := readFields(tx, b, &z.Object)
		for _, name := range f.list("interface") {
			id := fm.ID(name)
			if _, ok := p.interfaces[id]; !ok {
				f.invalid("missing zone interface")
			}
			if old, ok := members[id]; ok && old != z.ID {
				f.invalid("interface in multiple zones")
			}
			members[id] = z.ID
		}
		if f.choice("intrazone", "deny", "deny", "allow") == "allow" {
			p.intraAllow = append(p.intraAllow, z.ID)
		}
		f.ignore("description")
		f.finish()
		p.zones[z.ID] = z
		d.Zones = append(d.Zones, z)
	})
	if err != nil {
		return err
	}
	for i := range d.Interfaces {
		r := &d.Interfaces[i]
		r.Zone = members[r.ID]
		if r.Zone == "" {
			r.Zone = r.ID
			if _, exists := p.zones[r.ID]; exists {
				r.Unsupported = append(r.Unsupported, "interface and zone name collision")
			} else {
				z := fm.ZoneRecord{Object: object(string(r.ID), r.Name, p.vdom)}
				d.Zones = append(d.Zones, z)
				p.zones[z.ID] = z
			}
		}
		p.interfaces[r.ID] = *r
	}
	return p.commit(s, tx, d)
}

func (p *parser) routes(ctx context.Context, s *config.Session) error {
	tx := s.Cursor().Begin()
	defer tx.Rollback()
	var d fm.Data
	for _, iface := range p.data.Interfaces {
		if iface.Disabled {
			continue
		}
		for _, a := range iface.Addresses {
			r := fm.RouteRecord{Object: object("", "", p.vdom), Destination: a.Masked(), Interface: iface.ID, Direct: true}
			r.Unsupported = slices.Clone(iface.Unsupported)
			r.ID = config.RouteID(r)
			d.Routes = append(d.Routes, r)
		}
	}
	err := p.each(ctx, tx, "router static", func(b *config.Block) {
		name := b.Header.Words[1]
		r := fm.RouteRecord{Object: object(name, name, p.vdom), Destination: netip.MustParsePrefix("0.0.0.0/0")}
		f := readFields(tx, b, &r.Object)
		if id, e := strconv.ParseUint(name, 10, 32); e != nil || id == 0 {
			f.invalid("route ID")
		}
		if v := f.list("dst"); len(v) > 0 {
			if dest, ok := prefix(v); ok && dest == dest.Masked() {
				r.Destination = dest
			} else {
				f.invalid("dst")
			}
		}
		r.Interface = fm.ID(f.one("device", ""))
		if v := f.one("gateway", ""); v != "" {
			if a, e := netip.ParseAddr(v); e == nil && a.Is4() {
				if !a.IsUnspecified() {
					r.NextHop = a
				}
			} else {
				f.invalid("gateway")
			}
		}
		distance, e := strconv.ParseUint(f.one("distance", "10"), 10, 8)
		if e != nil || distance == 0 {
			f.invalid("distance")
		}
		priority, e := strconv.ParseUint(f.one("priority", "0"), 10, 16)
		if e != nil {
			f.invalid("priority")
		}
		r.Metric = uint32(distance<<16 | priority)
		enabled := f.choice("status", "enable", "enable", "disable") == "enable"
		if f.choice("blackhole", "disable", "disable", "enable") == "enable" {
			f.invalid("blackhole route")
		}
		f.ignore("comment")
		f.finish()
		if enabled {
			d.Routes = append(d.Routes, r)
		}
	})
	if err != nil {
		return err
	}
	return p.commit(s, tx, d)
}

func (p *parser) policyZones(f *fields, key string) ([]fm.ID, bool) {
	names := f.list(key)
	if len(names) == 1 && names[0] == "any" {
		return nil, true
	}
	var result []fm.ID
	selected := make(map[fm.ID]bool)
	explicit := make(map[fm.ID]bool)
	for _, name := range names {
		id := fm.ID(name)
		if _, ok := p.zones[id]; ok {
			explicit[id] = true
		} else if iface, ok := p.interfaces[id]; ok {
			selected[id] = true
			id = iface.Zone
		} else {
			f.invalid("unknown " + key)
		}
		if !slices.Contains(result, id) {
			result = append(result, id)
		}
	}
	for _, iface := range p.data.Interfaces {
		if slices.Contains(result, iface.Zone) && !explicit[iface.Zone] && !selected[iface.ID] {
			f.invalid("partial interface coverage in zone")
		}
	}
	if len(result) == 0 {
		f.invalid("missing " + key)
	}
	return result, false
}
