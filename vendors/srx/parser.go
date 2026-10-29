// Package srx parses Junos display-set configuration through targeted stages.
package srx

import (
	"context"
	"fmt"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/flow"
)

type catalog[T any] struct {
	names   []string
	entries map[string]*T
}

func (c *catalog[T]) get(name string) *T {
	if c.entries == nil {
		c.entries = make(map[string]*T)
	}
	if c.entries[name] == nil {
		c.names = append(c.names, name)
		c.entries[name] = new(T)
	}
	return c.entries[name]
}

type parser struct {
	rows      []config.Statement
	data      fm.Data
	books     map[string][]string // attached books by zone
	addresses map[fm.ID]fm.AddressRef
}

type Parser struct{ Limits config.Limits }

func Parse(ctx context.Context, source config.Source, metadata fm.Metadata) (*fm.Firewall, error) {
	return (Parser{}).Parse(ctx, source, metadata)
}

func (native Parser) Parse(ctx context.Context, source config.Source, metadata fm.Metadata) (*fm.Firewall, error) {
	metadata.Vendor, metadata.ParserVersion = "srx", "srx-go-1"
	cursor, err := config.NewCursor(ctx, source, native.Limits)
	if err != nil {
		return nil, err
	}
	rows, err := config.Statements(ctx, cursor)
	if err != nil {
		return nil, err
	}
	p := &parser{rows: rows, books: make(map[string][]string)}
	s, err := config.NewSession(cursor, metadata)
	if err != nil {
		return nil, err
	}
	stages := []config.Stage{
		{Name: "interfaces-zones", Run: p.network},
		{Name: "routes", Requires: []string{"interfaces-zones"}, Run: p.routes},
		{Name: "objects", Requires: []string{"routes"}, Run: p.objects},
		{Name: "policies", Requires: []string{"objects"}, Run: p.policies},
		{Name: "nat", Requires: []string{"policies", "routes"}, Run: p.nat},
	}
	if err := s.Run(ctx, stages); err != nil {
		return nil, err
	}
	return fm.Seal(s.Data())
}

func begins(words []string, prefix ...string) bool {
	return len(words) >= len(prefix) && slices.Equal(words[:len(prefix)], prefix)
}
func nativeID(kind string, parts ...string) fm.ID {
	for i := range parts {
		parts[i] = url.PathEscape(parts[i])
	}
	return fm.ID(kind + ":" + strings.Join(parts, "/"))
}
func addressID(scope, name string) fm.ID {
	if scope == "" {
		return fm.ID(name)
	}
	return nativeID("address", scope, name)
}
func touch(object *fm.Object, row config.Statement) { object.Spans = append(object.Spans, row.Span) }
func unique[T comparable](values []T, value T) []T {
	if !slices.Contains(values, value) {
		return append(values, value)
	}
	return values
}

// A display-set leaf has one argument or a fully delimited native list. Unknown
// punctuation is retained as pending rather than silently stripped.
func list(words []string) ([]string, bool) {
	if len(words) == 1 && words[0] != "[" && words[0] != "]" {
		return words, true
	}
	if len(words) < 3 || words[0] != "[" || words[len(words)-1] != "]" {
		return nil, false
	}
	for _, w := range words[1 : len(words)-1] {
		if w == "[" || w == "]" {
			return nil, false
		}
	}
	return words[1 : len(words)-1], true
}
func prefix(value string) (netip.Prefix, error) {
	if strings.Contains(value, "/") {
		return netip.ParsePrefix(value)
	}
	a, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}
func addressRange(value string) (flow.AddressRange, error) {
	p, err := prefix(value)
	if err != nil {
		return flow.AddressRange{}, err
	}
	if p != p.Masked() {
		return flow.AddressRange{}, fmt.Errorf("unaligned address prefix %s", p)
	}
	return flow.PrefixRange(p)
}
func ports(value string) (flow.Interval, bool) {
	if value == "any" {
		return flow.Interval{High: 65535}, true
	}
	ends := strings.Split(value, "-")
	if len(ends) > 2 {
		return flow.Interval{}, false
	}
	a, err := strconv.ParseUint(ends[0], 10, 16)
	if err != nil {
		return flow.Interval{}, false
	}
	b := a
	if len(ends) == 2 {
		b, err = strconv.ParseUint(ends[1], 10, 16)
	}
	return flow.Interval{Low: uint16(a), High: uint16(b)}, err == nil && a <= b
}
func protocol(value string) (uint16, bool) {
	switch value {
	case "tcp":
		return 6, true
	case "udp":
		return 17, true
	case "icmp":
		return 1, true
	case "icmp6":
		return 58, true
	case "sctp":
		return 132, true
	case "gre":
		return 47, true
	case "esp":
		return 50, true
	case "ah":
		return 51, true
	}
	n, err := strconv.ParseUint(value, 10, 8)
	return uint16(n), err == nil
}
func diagnostic(code, message string) fm.Diagnostic {
	return fm.Diagnostic{Code: code, Message: message}
}

func (p *parser) network(ctx context.Context, s *config.Session) error {
	tx := s.Cursor().Begin()
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
			// Record context before emitting zones; the object stage owns the
			// declaration's evidence and validates the referenced zone.
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

type routeDraft struct {
	object      fm.Object
	destination netip.Prefix
	hops        []string
	metric      uint32
}

func (p *parser) routes(ctx context.Context, s *config.Session) error {
	tx := s.Cursor().Begin()
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
	p.data = s.Data()
	return nil
}
