package asa

import (
	"context"
	"fmt"

	"net/netip"

	"strconv"
	"strings"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
)

func (p *parser) interfaces(_ context.Context, s *config.Builder) error {
	tx := s.Begin()
	d := fm.Data{}
	for _, b := range p.blocks {
		if b.kind != "interface" {
			continue
		}
		r := fm.InterfaceRecord{Object: object(b)}
		tx.Parse(b.header.Lines()...)
		for _, line := range b.members {
			w := line.Words
			ok := false
			if len(w) == 2 && w[0] == "nameif" {
				r.Zone = fm.ID(w[1])
				p.aliases[w[1]] = r.ID
				d.Zones = append(d.Zones, fm.ZoneRecord{Object: fm.Object{ID: r.Zone, Name: w[1]}})
				ok = true
			}
			if len(w) == 4 && w[0] == "ip" && w[1] == "address" {
				if v, err := prefix(w[2], w[3]); err == nil {
					r.Addresses = append(r.Addresses, v)
					ok = true
				}
			}
			if len(w) == 1 && w[0] == "shutdown" {
				r.Disabled = true
				ok = true
			}
			if len(w) == 2 && w[0] == "security-level" {
				if n, err := strconv.ParseUint(w[1], 10, 8); err == nil && n <= 100 {
					r.SecurityLevel, r.SecurityLevelKnown, ok = uint8(n), true, true
				}
			}
			if w[0] == "description" {
				ok = true
			}
			if ok {
				tx.Parse(line.Lines()...)
			} else {
				r.Unsupported = append(r.Unsupported, "unsupported interface member")
			}
		}
		d.Interfaces = append(d.Interfaces, r)
		for i, v := range r.Addresses {
			d.Routes = append(d.Routes, fm.RouteRecord{Object: fm.Object{ID: fm.ID(fmt.Sprintf("connected:%s:%d", r.ID, i))}, Destination: v.Masked(), Interface: r.ID, Direct: true})
		}
	}
	for _, line := range p.lines {
		if len(line.Words) == 0 || strings.HasPrefix(line.Words[0], "!") {
			tx.Ignore("ASA block separator/comment", line.Lines()...)
		}
	}
	tx.Emit(d)
	if err := s.Commit(tx); err != nil {
		return err
	}
	return nil
}

func (p *parser) routes(_ context.Context, s *config.Builder) error {
	tx := s.Begin()
	d := fm.Data{}
	for _, line := range p.lines {
		w := line.Words
		if len(w) == 6 && w[0] == "access-group" && w[3] == "interface" {
			continue
		}
		if len(w) == 5 && w[0] == "access-group" && w[3] == "interface" {
			iface := p.aliases[w[4]]
			d.RuleBindings = append(d.RuleBindings, fm.RuleBindingRecord{Object: fm.Object{ID: fm.ID("binding:" + w[1] + ":" + w[2] + ":" + w[4])}, RuleSet: w[1], Direction: w[2], Interface: iface, Zone: fm.ID(w[4])})
			tx.Parse(line.Lines()...)
		}
		if len(w) >= 5 && len(w) <= 6 && w[0] == "route" {
			v, err := prefix(w[2], w[3])
			hop, e := netip.ParseAddr(w[4])
			if err != nil || e != nil {
				continue
			}
			r := fm.RouteRecord{Object: fm.Object{Spans: []fm.Span{line.Span}}, Destination: v.Masked(), NextHop: hop, Interface: p.aliases[w[1]]}
			if len(w) == 6 {
				n, e := strconv.ParseUint(w[5], 10, 32)
				if e != nil {
					continue
				}
				r.Metric = uint32(n)
			}
			r.ID = config.RouteID(r)
			d.Routes = append(d.Routes, r)
			tx.Parse(line.Lines()...)
		}
	}
	tx.Emit(d)
	if err := s.Commit(tx); err != nil {
		return err
	}
	return nil
}
