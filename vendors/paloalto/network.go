package paloalto

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strconv"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
)

func (p *parser) network(_ context.Context, s *config.Builder) error {
	tx := s.Begin()
	interfaces := make(map[string]fm.InterfaceRecord)
	zones := make(map[string]fm.ZoneRecord)
	routes := make(map[string]fm.RouteRecord)
	bindings := make(map[string]string)
	vrfs := make(map[string]string)
	for _, row := range p.rows {
		w := row.words
		if len(w) < 3 {
			continue
		}
		ok := false
		if w[0] == "zone" && len(w) >= 6 && w[2] == "network" && w[3] == "layer3" {
			name := w[1]
			zones[name] = fm.ZoneRecord{Object: object(name, row)}
			for _, i := range values(w[4:]) {
				bindings[i] = name
			}
			ok = true
		}
		if w[0] == "zone" && len(w) == 5 && w[2] == "network" && w[3] == "layer3" {
			name := w[1]
			zones[name] = fm.ZoneRecord{Object: object(name, row)}
			bindings[w[4]] = name
			ok = true
		}
		if len(w) >= 8 && slices.Equal(w[:3], []string{"network", "interface", "ethernet"}) && w[4] == "layer3" && w[5] == "ip" {
			name := w[3]
			r := interfaces[name]
			if r.ID == "" {
				r.Object = object(name, row)
			}
			for _, value := range values(w[6:]) {
				prefix, err := hostPrefix(value)
				if err != nil {
					prefix = p.prefixes[fm.ID(value)]
				}
				if !prefix.IsValid() {
					r.Unsupported = append(r.Unsupported, "unresolved interface address")
				} else {
					r.Addresses = append(r.Addresses, prefix)
				}
			}
			interfaces[name] = r
			ok = true
		}
		if len(w) == 7 && slices.Equal(w[:3], []string{"network", "interface", "ethernet"}) && w[4] == "layer3" && w[5] == "ip" {
			name := w[3]
			r := interfaces[name]
			if r.ID == "" {
				r.Object = object(name, row)
			}
			prefix, err := hostPrefix(w[6])
			if err != nil {
				prefix = p.prefixes[fm.ID(w[6])]
			}
			if !prefix.IsValid() {
				r.Unsupported = append(r.Unsupported, "unresolved interface address")
			} else {
				r.Addresses = append(r.Addresses, prefix)
			}
			interfaces[name] = r
			ok = true
		}
		if len(w) >= 5 && w[0] == "network" && w[1] == "virtual-router" {
			vrf := w[2]
			if w[3] == "interface" {
				for _, i := range values(w[4:]) {
					vrfs[i] = vrf
				}
				ok = true
			}
			if len(w) >= 9 && slices.Equal(w[3:6], []string{"routing-table", "ip", "static-route"}) {
				name := w[6]
				key := fmt.Sprintf("static:%q:%q", vrf, name)
				r := routes[key]
				if r.ID == "" {
					r.Object = object(name, row)
					r.ID = fm.ID(key)
					r.Scope = vrf
				}
				switch w[7] {
				case "destination":
					if v, err := hostPrefix(w[8]); err == nil {
						r.Destination = v.Masked()
						ok = true
					}
				case "interface":
					r.Interface = fm.ID(w[8])
					ok = true
				case "nexthop":
					if len(w) == 10 && w[8] == "ip-address" {
						if v, err := netip.ParseAddr(w[9]); err == nil {
							r.NextHop = v
							ok = true
						}
					}
				case "metric":
					if n, err := strconv.ParseUint(w[8], 10, 32); err == nil {
						r.Metric = uint32(n)
						ok = true
					}
				}
				if !ok {
					r.Unsupported = append(r.Unsupported, "unsupported route field")
				}
				routes[key] = r
			}
		}
		if ok {
			tx.Parse(row.source.Lines()...)
		}
	}
	d := fm.Data{}
	for _, name := range keys(zones) {
		d.Zones = append(d.Zones, zones[name])
	}
	for _, name := range keys(interfaces) {
		r := interfaces[name]
		r.Zone = fm.ID(bindings[name])
		r.Scope = vrfs[name]
		d.Interfaces = append(d.Interfaces, r)
		for i, prefix := range r.Addresses {
			d.Routes = append(d.Routes, fm.RouteRecord{Object: fm.Object{ID: fm.ID(fmt.Sprintf("connected:%s:%d", name, i)), Scope: r.Scope}, Destination: prefix.Masked(), Interface: r.ID, Direct: true})
		}
	}
	for _, name := range keys(routes) {
		r := routes[name]
		if !r.Destination.IsValid() {
			d.Diagnostics = append(d.Diagnostics, fm.Diagnostic{Object: r.ID, Code: "incomplete-route"})
			continue
		}
		d.Routes = append(d.Routes, r)
	}
	tx.Emit(d)
	if err := s.Commit(tx); err != nil {
		return err
	}
	return nil
}
