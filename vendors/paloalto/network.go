package paloalto

import (
	"context"
	"fmt"
	"slices"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
)

type binding struct {
	zone, vrf string
	conflict  bool
}

type topology struct {
	interfaces map[string]interfaceDraft
	zones      map[string]fm.ZoneRecord
	routes     map[string]fm.RouteRecord
	bindings   map[string]binding
}

func (p *parser) network(ctx context.Context, s *config.Builder) error {
	t := topology{
		interfaces: make(map[string]interfaceDraft),
		zones:      make(map[string]fm.ZoneRecord),
		routes:     make(map[string]fm.RouteRecord),
		bindings:   make(map[string]binding),
	}
	tx := s.Begin()
	defer tx.Rollback()
	for _, row := range p.rows {
		if err := ctx.Err(); err != nil {
			return err
		}
		w := row.words
		if len(w) == 0 {
			continue
		}
		ok := false
		switch {
		case w[0] == "zone":
			ok = t.zone(row)
		case len(w) > 2 && slices.Equal(w[:2], []string{"network", "interface"}):
			ok = p.iface(&t, row)
		case len(w) > 2 && slices.Equal(w[:2], []string{"network", "virtual-router"}):
			ok = t.router(row)
		}
		if ok {
			tx.Parse(row.source.Lines()...)
		}
	}
	d := fm.Data{}
	for _, name := range keys(t.zones) {
		d.Zones = append(d.Zones, t.zones[name])
	}
	for _, name := range keys(t.interfaces) {
		r := t.interfaces[name].value()
		b := t.bindings[name]
		r.Zone, r.Scope = fm.ID(b.zone), b.vrf
		if b.conflict {
			r.Unsupported = append(r.Unsupported, "ambiguous zone or virtual router binding")
		}
		d.Interfaces = append(d.Interfaces, r)
		for i, prefix := range r.Addresses {
			d.Routes = append(d.Routes, fm.RouteRecord{Object: fm.Object{ID: fm.ID(fmt.Sprintf("connected:%s:%d", name, i)), Scope: r.Scope}, Destination: prefix.Masked(), Interface: r.ID, Direct: true})
		}
	}
	for _, name := range keys(t.routes) {
		r := t.routes[name]
		if !r.Destination.IsValid() {
			d.Diagnostics = append(d.Diagnostics, fm.Diagnostic{Object: r.ID, Code: "incomplete-route"})
			continue
		}
		d.Routes = append(d.Routes, r)
	}
	tx.Emit(d)
	return s.Commit(tx)
}

func (t *topology) zone(row row) bool {
	w := row.words
	if len(w) < 4 || w[2] != "network" {
		return false
	}
	r := t.zones[w[1]]
	if r.ID == "" {
		r.Object = object(w[1], row)
	} else {
		r.Spans = append(r.Spans, row.source.Span)
	}
	ok := slices.Contains([]string{"layer2", "layer3", "virtual-wire", "tap"}, w[3])
	if ok {
		for _, name := range values(w[4:]) {
			b := t.bindings[name]
			if b.zone != "" && b.zone != w[1] {
				b.conflict = true
			} else {
				b.zone = w[1]
			}
			t.bindings[name] = b
		}
	} else {
		r.Unsupported = append(r.Unsupported, "unsupported zone field "+w[3])
	}
	t.zones[w[1]] = r
	return ok
}
