package huawei

import (
	"context"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
)

var interfacePattern = regexp.MustCompile(`(?i)^(?:[a-z][a-z-]*|[1-9][0-9]*ge)[0-9]+(?:[/.:-][0-9]+)*$`)

func interfaceName(w []string) (string, bool) {
	if len(w) < 1 || len(w) > 2 {
		return "", false
	}
	v := strings.Join(w, "")
	return v, interfacePattern.MatchString(v)
}
func ipv4(v string) (netip.Addr, bool) { a, err := netip.ParseAddr(v); return a, err == nil && a.Is4() }
func prefix(w []string) (netip.Prefix, bool) {
	if len(w) != 2 {
		return netip.Prefix{}, false
	}
	a, ok := ipv4(w[0])
	if !ok {
		return netip.Prefix{}, false
	}
	bits, err := strconv.Atoi(w[1])
	if err != nil {
		mask, ok := ipv4(w[1])
		if !ok {
			return netip.Prefix{}, false
		}
		bits = 0
		zero := false
		for _, b := range mask.As4() {
			for n := 7; n >= 0; n-- {
				if b&(1<<n) == 0 {
					zero = true
				} else {
					if zero {
						return netip.Prefix{}, false
					}
					bits++
				}
			}
		}
	}
	if bits < 0 || bits > 32 {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(a, bits), true
}
func number(v string, min, max uint64) (uint64, bool) {
	n, e := strconv.ParseUint(v, 10, 64)
	return n, e == nil && n >= min && n <= max
}
func (p *parser) network(ctx context.Context, s *config.Session) error {
	tx := s.Cursor.Begin()
	defer tx.Rollback()
	var d fm.Data
	groups, err := p.grouped("interface", func(w []string) (string, string, error) {
		name, ok := interfaceName(w[1:])
		if !ok {
			return "", "", fmt.Errorf("invalid interface")
		}
		return name, "interface", nil
	})
	if err != nil {
		return err
	}
	indices := make(map[fm.ID]int)
	for _, g := range groups {
		r := fm.InterfaceRecord{Object: object(g.name)}
		err := walk(ctx, tx, &r.Object, g, func(row config.Statement) bool {
			w := row.Words
			switch {
			case has(w, "ip", "address") && len(w) == 4:
				a, ok := prefix(w[2:])
				if !ok || a.Addr().IsUnspecified() {
					return false
				}
				r.Addresses = []netip.Prefix{a}
				return true
			case has(w, "ip", "binding", "vpn-instance") && len(w) == 4 && len(w[3]) <= 31 && w[3] != "_public_":
				r.Scope = w[3]
				r.Addresses = nil
				return true
			case len(w) == 1 && w[0] == "shutdown":
				r.Disabled = true
				return true
			case len(w) == 2 && has(w, "undo", "shutdown"):
				r.Disabled = false
				return true
			case w[0] == "description" && len(w) > 1:
				return true
			}
			return false
		})
		if err != nil {
			return err
		}
		indices[r.ID] = len(d.Interfaces)
		d.Interfaces = append(d.Interfaces, r)
	}
	groups, err = p.grouped("zone", func(w []string) (string, string, error) {
		rest := w[2:]
		if len(rest) == 2 && rest[0] == "name" {
			rest = rest[1:]
		}
		if len(rest) != 1 || rest[0] == "" {
			return "", "", fmt.Errorf("invalid zone")
		}
		return strings.ToLower(rest[0]), "zone", nil
	})
	if err != nil {
		return err
	}
	for _, g := range groups {
		z := fm.ZoneRecord{Object: object(g.name)}
		err := walk(ctx, tx, &z.Object, g, func(row config.Statement) bool {
			w := row.Words
			if has(w, "add", "interface") {
				name, ok := interfaceName(w[2:])
				if !ok {
					return false
				}
				i, ok := indices[fm.ID(name)]
				if !ok {
					return false
				}
				if d.Interfaces[i].Zone != "" && d.Interfaces[i].Zone != z.ID {
					return false
				}
				d.Interfaces[i].Zone = z.ID
				return true
			}
			if len(w) == 3 && has(w, "set", "priority") {
				_, ok := number(w[2], 1, 100)
				return ok
			}
			return w[0] == "description" && len(w) > 1
		})
		if err != nil {
			return err
		}
		d.Zones = append(d.Zones, z)
	}
	return p.commit(s, tx, d)
}
func (p *parser) routes(ctx context.Context, s *config.Session) error {
	tx := s.Cursor.Begin()
	defer tx.Rollback()
	var d fm.Data
	seen := make(map[fm.ID]bool)
	add := func(r fm.RouteRecord) {
		r.ID = config.RouteID(r)
		if !seen[r.ID] {
			d.Routes = append(d.Routes, r)
			seen[r.ID] = true
		}
	}
	for _, iface := range p.data.Interfaces {
		if iface.Disabled {
			continue
		}
		for _, a := range iface.Addresses {
			r := fm.RouteRecord{Object: fm.Object{Scope: iface.Scope, Unsupported: slices.Clone(iface.Unsupported)}, Destination: a.Masked(), Interface: iface.ID, Direct: true}
			add(r)
		}
	}
	preference := uint32(60)
	for _, row := range p.lines {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !has(row.Words, "ip", "route-static") {
			continue
		}
		w := row.Words[2:]
		if len(w) == 2 && w[0] == "default-preference" {
			if n, ok := number(w[1], 1, 255); ok {
				preference = uint32(n)
				tx.Parse(row.Lines()...)
			}
			continue
		}
		r, ok := staticRoute(w, preference)
		if !ok {
			continue
		}
		r.Spans = []fm.Span{row.Span}
		add(r)
		tx.Parse(row.Lines()...)
	}
	return p.commit(s, tx, d)
}
func staticRoute(w []string, preference uint32) (fm.RouteRecord, bool) {
	r := fm.RouteRecord{Metric: preference}
	if len(w) >= 2 && w[0] == "vpn-instance" {
		r.Scope = w[1]
		w = w[2:]
	}
	if len(w) < 3 {
		return r, false
	}
	dest, ok := prefix(w[:2])
	if !ok || dest != dest.Masked() {
		return r, false
	}
	r.Destination = dest
	w = w[2:]
	if a, ok := ipv4(w[0]); ok {
		r.NextHop = a
		w = w[1:]
	} else {
		n := 1
		name, ok := interfaceName(w[:1])
		if !ok && len(w) >= 2 {
			name, ok = interfaceName(w[:2])
			n = 2
		}
		if !ok {
			return r, false
		}
		r.Interface = fm.ID(name)
		w = w[n:]
		if len(w) > 0 {
			if a, ok := ipv4(w[0]); ok {
				r.NextHop = a
				w = w[1:]
			}
		}
	}
	seen := make(map[string]bool)
	for len(w) > 0 {
		if len(w) < 2 || seen[w[0]] {
			return r, false
		}
		seen[w[0]] = true
		switch w[0] {
		case "preference":
			n, ok := number(w[1], 1, 255)
			if !ok {
				return r, false
			}
			r.Metric = uint32(n)
		case "tag":
			if _, ok := number(w[1], 1, 1<<32-1); !ok {
				return r, false
			}
		case "description":
			return r, true
		default:
			return r, false
		}
		w = w[2:]
	}
	return r, true
}
