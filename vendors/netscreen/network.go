package netscreen

import (
	"context"
	"net/netip"

	"slices"
	"strconv"
	"strings"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
)

func (p *parser) network(ctx context.Context, s *config.Builder) error {
	tx := s.Begin()
	defer tx.Rollback()
	var zones catalog[fm.ZoneRecord]
	var ifaces catalog[fm.InterfaceRecord]
	zone := func(name string) *fm.ZoneRecord {
		z := zones.get(name)
		if z.ID == "" {
			z.Object = object(fm.ID(name), name, "trust-vr")
			z.AddressScope = addressScope(name)
			p.intraBlocked[z.ID] = strings.EqualFold(name, "Untrust")
		}
		return z
	}
	for _, r := range p.rows {
		if err := ctx.Err(); err != nil {
			return err
		}
		w := r.Words
		if len(w) == 0 || strings.HasPrefix(w[0], "#") {
			tx.Ignore("blank line or comment", r.Lines()...)
			continue
		}
		if r.scope == "router" {
			if slices.Equal(w, []string{"exit"}) || begins(w, "set", "vrouter") && (len(w) == 3 || len(w) == 4 && w[2] == "name") || slices.Equal(w, []string{"set", "default-vrouter"}) {
				tx.Parse(r.Lines()...)
			}
			continue
		}
		if r.scope != "root" {
			continue
		}
		if len(w) == 4 && (w[0] == "set" || w[0] == "unset") && w[1] == "zone" && w[3] == "block" {
			z := zone(w[2])
			p.intraBlocked[z.ID] = w[0] == "set"
			touch(&z.Object, r)
			tx.Parse(r.Lines()...)
			continue
		}
		if len(w) == 4 && begins(w, "set", "zone", "name") {
			touch(&zone(w[3]).Object, r)
			tx.Parse(r.Lines()...)
			continue
		}
		if len(w) == 3 && begins(w, "set", "hostname") {
			tx.Ignore("device display name", r.Lines()...)
			continue
		}
		if len(w) == 4 && begins(w, "set", "vrouter") && w[3] == "default-vrouter" {
			tx.Parse(r.Lines()...)
			continue
		}
		if begins(w, "set", "zone") && len(w) >= 3 {
			if len(w) == 3 {
				touch(&zone(w[2]).Object, r)
				tx.Parse(r.Lines()...)
			}
			if len(w) == 5 && w[3] == "vrouter" {
				z := zone(w[2])
				z.Scope = w[4]
				touch(&z.Object, r)
				tx.Parse(r.Lines()...)
			}
			continue
		}
		if !begins(w, "set", "interface") || len(w) < 4 {
			continue
		}
		name, rest := w[2], w[3:]
		if len(rest) == 4 && rest[0] == "tag" && rest[2] == "zone" {
			if _, e := strconv.ParseUint(rest[1], 10, 12); e != nil {
				continue
			}
			rest = rest[2:]
		}
		if rest[0] == "mip" || rest[0] == "vip" || rest[0] == "dip" {
			continue
		}
		iface := ifaces.get(name)
		iface.ID, iface.Name = fm.ID(name), name
		valid := false
		switch {
		case len(rest) == 2 && rest[0] == "zone":
			if iface.Zone != "" && iface.Zone != fm.ID(rest[1]) {
				iface.Unsupported = append(iface.Unsupported, "conflicting interface zone")
			}
			iface.Zone = zone(rest[1]).ID
			valid = true
		case len(rest) > 1 && rest[0] == "ip":
			a, n, ok := prefix(rest[1:])
			if ok && (len(rest) == n+1 || len(rest) == n+2 && rest[n+1] == "secondary") {
				iface.Addresses = unique(iface.Addresses, a)
				valid = true
			}
		case len(rest) == 1 && rest[0] == "shutdown":
			iface.Disabled = true
			valid = true
		case len(rest) == 1 && rest[0] == "route":
			valid = true
		case len(rest) == 2 && rest[0] == "description":
			valid = true
		}
		if valid {
			touch(&iface.Object, r)
			tx.Parse(r.Lines()...)
		} else {
			iface.Unsupported = append(iface.Unsupported, "unsupported interface attribute")
		}
	}
	d := fm.Data{}
	for _, name := range zones.names {
		d.Zones = append(d.Zones, *zones.entries[name])
	}
	for _, name := range ifaces.names {
		v := *ifaces.entries[name]
		v.Scope = "trust-vr"
		if z := zones.entries[string(v.Zone)]; z != nil {
			v.Scope = z.Scope
		}
		d.Interfaces = append(d.Interfaces, v)
	}
	tx.Emit(d)
	return s.Commit(tx)
}

func (p *parser) routes(ctx context.Context, s *config.Builder) error {
	tx := s.Begin()
	defer tx.Rollback()
	var routes catalog[fm.RouteRecord]
	for _, i := range p.builder.Interfaces() {
		for _, a := range i.Addresses {
			if i.Disabled {
				continue
			}
			r := fm.RouteRecord{Object: object("", "", i.Scope), Destination: a.Masked(), Interface: i.ID, Direct: true}
			r.Spans = i.Spans
			r.ID = config.RouteID(r)
			*routes.get(string(r.ID)) = r
		}
	}
	for _, row := range p.rows {
		if err := ctx.Err(); err != nil {
			return err
		}
		if row.scope != "root" && row.scope != "router" {
			continue
		}
		w := row.Words
		vrf := row.vrf
		if begins(w, "set", "vrouter") && len(w) > 4 && w[3] == "route" {
			vrf = w[2]
			w = append([]string{"set"}, w[3:]...)
		}
		if !begins(w, "set", "route") || len(w) < 4 {
			continue
		}
		dst, e := netip.ParsePrefix(w[2])
		if e != nil || !dst.Addr().Is4() || dst != dst.Masked() {
			continue
		}
		r := fm.RouteRecord{Object: object("", "", vrf), Destination: dst, Metric: 1}
		valid := true
		seen := make(map[string]bool)
		for rest := w[3:]; len(rest) > 0; rest = rest[2:] {
			if len(rest) < 2 || seen[rest[0]] {
				valid = false
				break
			}
			seen[rest[0]] = true
			switch rest[0] {
			case "interface":
				r.Interface = fm.ID(rest[1])
			case "gateway":
				r.NextHop, e = netip.ParseAddr(rest[1])
				valid = valid && e == nil && r.NextHop.Is4()
			case "metric":
				var n uint64
				n, e = strconv.ParseUint(rest[1], 10, 32)
				r.Metric = uint32(n)
				valid = valid && e == nil
			case "tag":
				_, e = strconv.ParseUint(rest[1], 10, 32)
				valid = valid && e == nil
			default:
				valid = false
			}
		}
		if !valid || r.Interface == "" && !r.NextHop.IsValid() {
			continue
		}
		touch(&r.Object, row)
		r.ID = config.RouteID(r)
		*routes.get(string(r.ID)) = r
		tx.Parse(row.Lines()...)
	}
	d := fm.Data{}
	for _, name := range routes.names {
		d.Routes = append(d.Routes, *routes.entries[name])
	}
	tx.Emit(d)
	return s.Commit(tx)
}
