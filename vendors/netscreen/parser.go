// Package netscreen parses ScreenOS captures using scoped, ordered passes.
package netscreen

import (
	"context"
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

type row struct {
	config.Statement
	scope, owner, vrf string
}
type parser struct {
	rows         []row
	data         fm.Data
	addresses    map[fm.ID]fm.AddressRef
	services     map[string]fm.ServiceRef
	rules        catalog[fm.RuleRecord]
	policyNAT    map[fm.ID]policyNAT
	intraBlocked map[fm.ID]bool
}

func Parse(ctx context.Context, source config.Source, metadata fm.Metadata) (*fm.Firewall, error) {
	metadata.Vendor, metadata.ParserVersion = "netscreen", "screenos-go-1"
	cursor, err := config.NewCursor(source, config.Limits{})
	if err != nil {
		return nil, err
	}
	statements, err := config.Statements(ctx, cursor)
	if err != nil {
		return nil, err
	}
	p := &parser{rows: scopeRows(statements), policyNAT: make(map[fm.ID]policyNAT), intraBlocked: make(map[fm.ID]bool)}
	s := config.NewSession(cursor, metadata)
	stages := []config.Stage{
		{Name: "interfaces-zones", Run: p.network},
		{Name: "routes", Requires: []string{"interfaces-zones"}, Run: p.routes},
		{Name: "objects", Requires: []string{"routes"}, Run: p.objects},
		{Name: "interface-nat", Requires: []string{"objects", "routes"}, Run: p.interfaceNAT},
		{Name: "policies", Requires: []string{"interface-nat"}, Run: p.policies},
		{Name: "policy-nat", Requires: []string{"policies"}, Run: p.embeddedNAT},
	}
	if err := s.Run(ctx, stages); err != nil {
		return nil, err
	}
	return fm.Seal(s.Data())
}

// A policy continuation and a virtual-router body own their commands. Root-like
// text in either body or an unsupported virtual system cannot create objects.
func scopeRows(statements []config.Statement) []row {
	out := make([]row, 0, len(statements))
	scope, owner, vrf, defaultVR := "root", "", "trust-vr", "trust-vr"
	for _, s := range statements {
		w := s.Words
		if scope == "root" && begins(w, "set", "vsys") {
			scope = "unsupported"
		}
		if scope != "unsupported" && scope != "router" && begins(w, "set", "policy", "id") && len(w) >= 4 {
			scope, owner = "policy", w[3]
		}
		if scope == "root" && begins(w, "set", "vrouter") {
			if len(w) == 3 {
				scope, owner, vrf = "router", w[2], w[2]
			}
			if len(w) == 4 && w[2] == "name" {
				scope, owner, vrf = "router", w[3], w[3]
			}
			if len(w) == 4 && w[3] == "default-vrouter" {
				defaultVR = w[2]
			}
		}
		routeVR := defaultVR
		if scope == "router" {
			routeVR = vrf
		}
		out = append(out, row{Statement: s, scope: scope, owner: owner, vrf: routeVR})
		if scope == "router" && slices.Equal(w, []string{"set", "default-vrouter"}) {
			defaultVR = vrf
		}
		if slices.Equal(w, []string{"exit"}) && scope != "unsupported" {
			scope, owner = "root", ""
		}
	}
	return out
}
func begins(w []string, prefix ...string) bool {
	return len(w) >= len(prefix) && slices.Equal(w[:len(prefix)], prefix)
}
func unique[T comparable](in []T, v T) []T {
	if !slices.Contains(in, v) {
		return append(in, v)
	}
	return in
}
func nativeID(kind string, parts ...string) fm.ID {
	for i := range parts {
		parts[i] = url.PathEscape(parts[i])
	}
	return fm.ID(kind + ":" + strings.Join(parts, "/"))
}
func addressScope(zone string) string {
	if zone == "Global" {
		return ""
	}
	return "zone:" + zone
}
func addressID(scope, name string) fm.ID {
	if scope == "" {
		return fm.ID(name)
	}
	return nativeID("address", scope, name)
}
func touch(o *fm.Object, r row) { o.Spans = append(o.Spans, r.Span) }
func object(id fm.ID, name, scope string) fm.Object {
	return fm.Object{ID: id, Name: name, Scope: scope}
}

func prefix(w []string) (netip.Prefix, int, bool) {
	if len(w) == 0 {
		return netip.Prefix{}, 0, false
	}
	if strings.Contains(w[0], "/") {
		p, e := netip.ParsePrefix(w[0])
		return p, 1, e == nil && p.Addr().Is4()
	}
	a, e := netip.ParseAddr(w[0])
	if e != nil || !a.Is4() || len(w) < 2 {
		return netip.Prefix{}, 0, false
	}
	mask, e := netip.ParseAddr(w[1])
	if e != nil || !mask.Is4() {
		return netip.Prefix{}, 0, false
	}
	bytes := mask.As4()
	bits, zero := 0, false
	for _, b := range bytes {
		for bit := 7; bit >= 0; bit-- {
			if b&(1<<bit) == 0 {
				zero = true
			} else {
				if zero {
					return netip.Prefix{}, 0, false
				}
				bits++
			}
		}
	}
	return netip.PrefixFrom(a, bits), 2, true
}
func ports(value string) (flow.Interval, bool) {
	parts := strings.Split(value, "-")
	if len(parts) > 2 {
		return flow.Interval{}, false
	}
	a, e := strconv.ParseUint(parts[0], 10, 16)
	if e != nil {
		return flow.Interval{}, false
	}
	b := a
	if len(parts) == 2 {
		b, e = strconv.ParseUint(parts[1], 10, 16)
	}
	return flow.Interval{Low: uint16(a), High: uint16(b)}, e == nil && a <= b
}
func protocol(value string) (uint16, bool) {
	switch value {
	case "tcp":
		return 6, true
	case "udp":
		return 17, true
	case "icmp":
		return 1, true
	}
	n, e := strconv.ParseUint(value, 10, 8)
	return uint16(n), e == nil
}
func (p *parser) commit(s *config.Session, tx *config.Transaction, d fm.Data) error {
	tx.Emit(d)
	if err := s.Commit(tx); err != nil {
		return err
	}
	p.data = s.Data()
	return nil
}

func (p *parser) network(ctx context.Context, s *config.Session) error {
	tx := s.Cursor.Begin()
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
	return p.commit(s, tx, d)
}

func (p *parser) routes(ctx context.Context, s *config.Session) error {
	tx := s.Cursor.Begin()
	defer tx.Rollback()
	var routes catalog[fm.RouteRecord]
	for _, i := range p.data.Interfaces {
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
	return p.commit(s, tx, d)
}

func invalid(id fm.ID, message string) fm.Diagnostic {
	return fm.Diagnostic{Object: id, Code: "unsupported-native", Message: message}
}
func policyID(value string) (fm.ID, bool) {
	n, e := strconv.ParseUint(value, 10, 32)
	return fm.ID(value), e == nil && n > 0 && n < 320000 && strconv.FormatUint(n, 10) == value
}
