package srx

import (
	"context"

	"net/netip"

	"strconv"
	"strings"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
)

func (p *parser) network(ctx context.Context, s *config.Builder) error {
	tx := s.Begin()
	defer tx.Rollback()
	var ifaces catalog[fm.InterfaceRecord]
	var zones catalog[fm.ZoneRecord]
	disabled := make(map[string]bool)
	for _, row := range p.rows {
		if err := ctx.Err(); err != nil {
			return err
		}
		w := row.Words
		if scope, rest, ok := bookPath(w); ok && scope != "" && strings.HasPrefix(scope, "book:") && len(rest) == 3 && rest[0] == "attach" && rest[1] == "zone" {

			p.books[rest[2]] = unique(p.books[rest[2]], scope)
			continue
		}
		if len(w) == 0 || len(w) > 0 && strings.HasPrefix(w[0], "#") {
			tx.Ignore("empty line or comment", row.Lines()...)
			continue
		}
		if begins(w, "set", "system", "host-name") && len(w) == 4 {
			tx.Ignore("device display name", row.Lines()...)
			continue
		}
		if begins(w, "set", "routing-instances") && len(w) == 5 && w[3] == "instance-type" && w[4] == "virtual-router" {
			tx.Parse(row.Lines()...)
			continue
		}
		if begins(w, "set", "routing-instances") && len(w) == 5 && w[3] == "interface" {
			r := ifaces.get(w[4])
			r.ID, r.Name = fm.ID(w[4]), w[4]
			if r.Scope != "" && r.Scope != w[2] {
				r.Unsupported = append(r.Unsupported, "interface assigned to multiple routing instances")
			}
			r.Scope = w[2]
			touch(&r.Object, row)
			tx.Parse(row.Lines()...)
			continue
		}
		if begins(w, "set", "interfaces") {
			if len(w) == 4 && w[3] == "disable" {
				disabled[w[2]] = true
				tx.Parse(row.Lines()...)
				continue
			}
			if len(w) < 6 || w[3] != "unit" {
				continue
			}
			name := w[2] + "." + w[4]
			r := ifaces.get(name)
			r.ID, r.Name = fm.ID(name), name
			ok := false
			switch {
			case len(w) == 9 && w[5] == "family" && (w[6] == "inet" || w[6] == "inet6") && w[7] == "address":
				a, err := netip.ParsePrefix(w[8])
				if err == nil && (w[6] == "inet") == a.Addr().Is4() {
					r.Addresses = unique(r.Addresses, a)
					ok = true
				}
			case len(w) == 6 && w[5] == "disable":
				r.Disabled = true
				ok = true
			case len(w) == 7 && w[5] == "description":
				ok = true
			}
			if ok {
				touch(&r.Object, row)
				tx.Parse(row.Lines()...)
			} else {
				r.Unsupported = append(r.Unsupported, "unsupported interface declaration")
			}
			continue
		}
		if begins(w, "set", "security", "zones", "security-zone") && len(w) >= 5 {
			z := zones.get(w[4])
			z.ID, z.Name = fm.ID(w[4]), w[4]
			switch {
			case len(w) == 5:
				touch(&z.Object, row)
				tx.Parse(row.Lines()...)
			case len(w) == 7 && w[5] == "description":
				touch(&z.Object, row)
				tx.Parse(row.Lines()...)
			case len(w) == 7 && w[5] == "interfaces":
				r := ifaces.get(w[6])
				r.ID, r.Name = fm.ID(w[6]), w[6]
				if r.Zone != "" && r.Zone != z.ID {
					r.Unsupported = append(r.Unsupported, "interface assigned to multiple security zones")
				}
				r.Zone = z.ID
				touch(&r.Object, row)
				touch(&z.Object, row)
				tx.Parse(row.Lines()...)
			case len(w) >= 7 && w[5] == "address-book":
				z.AddressScope = "zone:" + w[4]
			}
		}
	}
	d := fm.Data{}
	for _, name := range zones.names {
		if attached := p.books[name]; len(attached) == 1 && zones.entries[name].AddressScope == "" {
			zones.entries[name].AddressScope = attached[0]
		}
		d.Zones = append(d.Zones, *zones.entries[name])
	}
	for _, name := range ifaces.names {
		r := *ifaces.entries[name]
		physical, _, _ := strings.Cut(name, ".")
		r.Disabled = r.Disabled || disabled[physical]
		d.Interfaces = append(d.Interfaces, r)
		for _, a := range r.Addresses {
			route := fm.RouteRecord{Object: fm.Object{Scope: r.Scope}, Destination: a.Masked(), Interface: r.ID, Direct: true}
			route.ID = config.RouteID(route)
			d.Routes = append(d.Routes, route)
		}
	}
	tx.Emit(d)
	return s.Commit(tx)
}

func (p *parser) routes(ctx context.Context, s *config.Builder) error {
	tx := s.Begin()
	defer tx.Rollback()
	var routes catalog[routeDraft]
	for _, row := range p.rows {
		if err := ctx.Err(); err != nil {
			return err
		}
		w := row.Words
		if !begins(w, "set") {
			continue
		}
		w = w[1:]
		scope := ""
		if len(w) > 2 && w[0] == "routing-instances" {
			scope = w[1]
			w = w[2:]
		}
		if !begins(w, "routing-options", "static", "route") || len(w) < 6 {
			continue
		}
		dst, err := netip.ParsePrefix(w[3])
		if err != nil {
			continue
		}
		r := routes.get(scope + "\x00" + dst.Masked().String())
		r.object.Scope = scope
		r.destination = dst.Masked()
		ok := false
		switch w[4] {
		case "next-hop":
			if hops, valid := list(w[5:]); valid {
				for _, hop := range hops {
					r.hops = unique(r.hops, hop)
				}
				ok = true
			}
		case "preference":
			if len(w) == 6 {
				n, e := strconv.ParseUint(w[5], 10, 32)
				if e == nil {
					r.metric = uint32(n)
					ok = true
				}
			}
		}
		if ok {
			touch(&r.object, row)
			tx.Parse(row.Lines()...)
		} else {
			r.object.Unsupported = append(r.object.Unsupported, "unsupported static route attribute")
		}
	}
	d := fm.Data{}
	for _, name := range routes.names {
		r := routes.entries[name]
		if len(r.hops) == 0 {
			r.hops = []string{""}
		}
		for _, hop := range r.hops {
			record := fm.RouteRecord{Object: r.object, Destination: r.destination, Metric: r.metric}
			if ip, err := netip.ParseAddr(hop); err == nil {
				record.NextHop = ip
			} else {
				record.Interface = fm.ID(hop)
			}
			record.ID = config.RouteID(record)
			d.Routes = append(d.Routes, record)
		}
	}
	tx.Emit(d)
	if err := s.Commit(tx); err != nil {
		return err
	}
	return nil
}
