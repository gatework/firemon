// Package hillstone implements scoped StoneOS configuration parsing.
package hillstone

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/flow"
)

const ParserVersion = "hillstone-go-2"

type node struct {
	block           *config.Block
	scope, from, to string
}
type statement struct {
	line  config.Statement
	scope string
}
type parser struct {
	session      *config.Session
	document     config.Document
	nodes        []node
	lines        []statement
	zoneVRF      map[fm.ID]string
	addressKinds map[fm.ID]fm.Kind
	serviceKinds map[fm.ID]fm.Kind
	data         fm.Data
	graph        *fm.Firewall
}

type Parser struct{ Limits config.Limits }

func Parse(ctx context.Context, source config.Source, metadata fm.Metadata) (*fm.Firewall, error) {
	return (Parser{}).Parse(ctx, source, metadata)
}

func (native Parser) Parse(ctx context.Context, source config.Source, metadata fm.Metadata) (*fm.Firewall, error) {
	metadata.Vendor = "hillstone"
	metadata.ParserVersion = ParserVersion
	cursor, err := config.NewCursor(ctx, source, native.Limits)
	if err != nil {
		return nil, err
	}
	document, err := config.Blocks(ctx, cursor, classify)
	if err != nil {
		return nil, err
	}
	session, err := config.NewSession(cursor, metadata)
	if err != nil {
		return nil, err
	}
	p := &parser{session: session, document: document, zoneVRF: make(map[fm.ID]string), addressKinds: make(map[fm.ID]fm.Kind), serviceKinds: make(map[fm.ID]fm.Kind)}
	p.collect(document.Roots, "", "", "")
	for _, line := range document.Lines {
		p.lines = append(p.lines, statement{line: line})
	}
	stages := []config.Stage{
		{Name: "structure", Run: p.structure},
		{Name: "zones", Requires: []string{"structure"}, Run: p.zones},
		{Name: "interfaces", Requires: []string{"zones"}, Run: p.interfaces},
		{Name: "objects", Requires: []string{"interfaces"}, Run: p.objects},
		{Name: "routes", Requires: []string{"interfaces"}, Run: p.routes},
		{Name: "rules", Requires: []string{"objects", "routes"}, Run: p.rules},
		{Name: "nat", Requires: []string{"rules"}, Run: p.nat},
	}
	if err = p.session.Run(ctx, stages); err != nil {
		return nil, err
	}
	return fm.Seal(p.session.Data())
}
func classify(s config.Statement, path []string) (config.Boundary, string) {
	w := s.Words
	if len(w) == 0 {
		return config.Member, ""
	}
	if len(w) == 1 && w[0] == "exit" {
		return config.CloseBlock, ""
	}
	owner := ""
	if len(path) > 0 {
		owner = path[len(path)-1]
	}
	if owner == "outside" || owner == "unknown" {
		return config.Member, ""
	}
	if owner != "" && owner != "vrf" && owner != "policy" && owner != "policy-global" {
		if owner == "pbr-policy" && w[0] == "match" {
			return config.OpenBlock, "pbr-match"
		}
		return config.Member, ""
	}
	switch w[0] {
	case "zone", "interface", "address", "service", "servgroup", "schedule", "rule", "natpool", "pbr-policy":
		return config.OpenBlock, w[0]
	case "policy-global":
		return config.OpenBlock, "policy-global"
	case "policy":
		if len(w) > 1 && w[1] == "from" {
			return config.OpenBlock, "policy"
		}
	case "ip":
		if len(w) > 1 && w[1] == "vrouter" {
			return config.OpenBlock, "vrf"
		}
	case "admin", "aaa-server", "role", "track", "interface-group", "webauth", "vswitch":
		return config.OpenBlock, "outside"
	}
	if strings.HasSuffix(w[0], "-profile") {
		return config.OpenBlock, "outside"
	}
	return config.Member, ""
}
func (p *parser) collect(blocks []*config.Block, scope, from, to string) {
	for _, b := range blocks {
		w := b.Header.Words
		switch b.Kind {
		case "vrf":
			if len(w) == 3 {
				p.collect(b.Children, w[2], from, to)
				for _, line := range b.Members {
					p.lines = append(p.lines, statement{line, w[2]})
				}
			} else {
				p.nodes = append(p.nodes, node{b, scope, from, to})
			}
		case "policy":
			if len(w) == 5 && w[1] == "from" && w[3] == "to" {
				p.collect(b.Children, scope, w[2], w[4])
			} else {
				p.nodes = append(p.nodes, node{b, scope, from, to})
			}
		case "policy-global":
			p.collect(b.Children, scope, "any", "any")
		default:
			p.nodes = append(p.nodes, node{b, scope, from, to})
		}
	}
}
func (p *parser) structure(ctx context.Context, s *config.Session) error {
	tx := s.Cursor().Begin()
	tx.Emit(fm.Data{Diagnostics: p.document.Diagnostics})
	var mark func([]*config.Block)
	mark = func(blocks []*config.Block) {
		for _, b := range blocks {
			switch b.Kind {
			case "vrf", "policy", "policy-global":
				tx.Parse(b.Header.Lines()...)
				if b.Complete {
					tx.Parse(b.End.Lines()...)
				}
				mark(b.Children)
			case "outside":
				tx.Ignore("native management block outside firewall domain", b.Header.Lines()...)
				for _, l := range b.Members {
					tx.Ignore("native management block outside firewall domain", l.Lines()...)
				}
				if b.Complete {
					tx.Ignore("native management block boundary", b.End.Lines()...)
				}
			}
		}
	}
	mark(p.document.Roots)
	for _, row := range p.lines {
		w := row.line.Words
		if len(w) == 0 || strings.HasPrefix(w[0], "#") || strings.HasPrefix(w[0], "!") || w[0] == "hostname" {
			tx.Ignore("comment or device display name", row.line.Lines()...)
		}
	}
	return s.Commit(tx)
}
func object(n node) fm.Object {
	w := n.block.Header.Words
	id := ""
	if len(w) > 1 {
		id = w[1]
	}
	if w[0] == "rule" && len(w) > 2 && w[1] == "id" {
		id = w[2]
	}
	return fm.Object{ID: fm.ID(id), Name: id, Scope: n.scope, Spans: []fm.Span{n.block.Header.Span}}
}
func begin(s *config.Session, b *config.Block) *config.Transaction {
	tx := s.Cursor().Begin()
	tx.Parse(b.Header.Lines()...)
	if b.Complete {
		tx.Parse(b.End.Lines()...)
	}
	return tx
}
func consume(tx *config.Transaction, line config.Statement, ok bool, o *fm.Object) {
	if ok {
		tx.Parse(line.Lines()...)
		o.Spans = append(o.Spans, line.Span)
	} else {
		o.Unsupported = append(o.Unsupported, strings.TrimSpace(line.Raw))
	}
}
func ancillary(w []string) bool { return len(w) == 0 || w[0] == "description" }
func (p *parser) zones(_ context.Context, s *config.Session) error {
	for _, n := range p.nodes {
		if n.block.Kind != "zone" {
			continue
		}
		r := fm.ZoneRecord{Object: object(n)}
		tx := begin(s, n.block)
		for _, l := range n.block.Members {
			w := l.Words
			ok := ancillary(w)
			if len(w) == 2 && w[0] == "vrouter" {
				r.Scope = w[1]
				ok = true
			}
			consume(tx, l, ok, &r.Object)
		}
		p.zoneVRF[r.ID] = r.Scope
		tx.Emit(fm.Data{Zones: []fm.ZoneRecord{r}})
		if err := s.Commit(tx); err != nil {
			return err
		}
	}
	return nil
}
func prefix(words []string) (netip.Prefix, error) {
	if len(words) == 0 {
		return netip.Prefix{}, fmt.Errorf("missing prefix")
	}
	if strings.Contains(words[0], "/") {
		return netip.ParsePrefix(words[0])
	}
	a, err := netip.ParseAddr(words[0])
	if err != nil {
		return netip.Prefix{}, err
	}
	bits := a.BitLen()
	if len(words) > 1 {
		mask, err := netip.ParseAddr(words[1])
		if err != nil || !mask.Is4() || !a.Is4() {
			return netip.Prefix{}, fmt.Errorf("invalid netmask")
		}
		b := mask.As4()
		ones, total := net.IPMask(b[:]).Size()
		if total != 32 {
			return netip.Prefix{}, fmt.Errorf("noncontiguous mask")
		}
		bits = ones
	}
	return netip.PrefixFrom(a, bits), nil
}
func (p *parser) interfaces(_ context.Context, s *config.Session) error {
	for _, n := range p.nodes {
		if n.block.Kind != "interface" {
			continue
		}
		r := fm.InterfaceRecord{Object: object(n)}
		tx := begin(s, n.block)
		for _, l := range n.block.Members {
			w := l.Words
			ok := ancillary(w)
			if len(w) == 2 && w[0] == "zone" {
				r.Zone = fm.ID(w[1])
				ok = true
			}
			if len(w) >= 3 && (w[0] == "ip" || w[0] == "ipv6") && w[1] == "address" {
				fields := w[2:]
				if fields[len(fields)-1] == "secondary" {
					fields = fields[:len(fields)-1]
				}
				if len(fields) <= 2 {
					if v, err := prefix(fields); err == nil {
						r.Addresses = append(r.Addresses, v)
						ok = true
					}
				}
			}
			if len(w) == 1 && w[0] == "shutdown" {
				r.Disabled = true
				ok = true
			}
			if slices.Equal(w, []string{"ipv6", "enable"}) {
				ok = true
			}
			consume(tx, l, ok, &r.Object)
		}
		if vrf := p.zoneVRF[r.Zone]; vrf != "" {
			r.Scope = vrf
		}
		delta := fm.Data{Interfaces: []fm.InterfaceRecord{r}}
		for i, prefix := range r.Addresses {
			delta.Routes = append(delta.Routes, fm.RouteRecord{Object: fm.Object{ID: fm.ID(fmt.Sprintf("connected:%s:%d", r.ID, i)), Scope: r.Scope}, Destination: prefix.Masked(), Interface: r.ID, Direct: true})
		}
		tx.Emit(delta)
		if err := s.Commit(tx); err != nil {
			return err
		}
	}
	return nil
}
func literal(value string) (flow.Range, error) {
	if parts := strings.Split(value, "-"); len(parts) == 2 {
		a, e := netip.ParseAddr(parts[0])
		b, e2 := netip.ParseAddr(parts[1])
		r := flow.Range{First: a, Last: b}
		if e != nil || e2 != nil || !r.Valid() {
			return flow.Range{}, flow.ErrRange
		}
		return r, nil
	}
	v, err := prefix([]string{value})
	if err != nil {
		return flow.Range{}, err
	}
	return flow.PrefixRange(v)
}
func number(value string, max int) (uint16, bool) {
	v, err := strconv.Atoi(value)
	return uint16(v), err == nil && v >= 0 && v <= max
}
func port(words []string) (flow.Interval, bool) {
	if len(words) < 1 || len(words) > 2 {
		return flow.Interval{}, false
	}
	a, ok := number(words[0], 65535)
	b := a
	if len(words) == 2 {
		var valid bool
		b, valid = number(words[1], 65535)
		ok = ok && valid
	}
	return flow.Interval{Low: a, High: b}, ok && a <= b
}
func term(w []string) (fm.ServiceTerm, bool) {
	full := flow.Interval{Low: 0, High: 65535}
	octet := flow.Interval{Low: 0, High: 255}
	r := fm.ServiceTerm{SourcePort: full, DestinationPort: full, ICMPType: octet, ICMPCode: octet}
	if len(w) == 2 && w[0] == "protocol" {
		n, ok := number(w[1], 255)
		r.Protocol = flow.Interval{Low: n, High: n}
		return r, ok
	}
	if len(w) == 1 && w[0] == "icmp" {
		r.Protocol = flow.Interval{Low: 1, High: 1}
		return r, true
	}
	if len(w) < 3 || w[1] != "dst-port" {
		return r, false
	}
	protocols := map[string]uint16{"tcp": 6, "udp": 17, "sctp": 132}
	protocol, ok := protocols[w[0]]
	if !ok {
		return r, false
	}
	r.Protocol = flow.Interval{Low: protocol, High: protocol}
	split := slices.Index(w, "src-port")
	end := len(w)
	if split >= 0 {
		end = split
	}
	r.DestinationPort, ok = port(w[2:end])
	if split >= 0 {
		var valid bool
		r.SourcePort, valid = port(w[split+1:])
		ok = ok && valid
	}
	return r, ok
}
func (p *parser) objects(_ context.Context, s *config.Session) error {
	// Inventory names before resolving forward group references.
	for _, n := range p.nodes {
		o := object(n)
		switch n.block.Kind {
		case "address":
			kind := fm.AddressObject
			for _, l := range n.block.Members {
				if len(l.Words) > 0 && l.Words[0] == "member" {
					kind = fm.AddressGroupObject
				}
			}
			p.addressKinds[o.ID] = kind
		case "service":
			p.serviceKinds[o.ID] = fm.ServiceObject
		case "servgroup":
			p.serviceKinds[o.ID] = fm.ServiceGroupObject
		}
	}
	addressDefinitions := make(map[fm.ID]bool)
	emittedEmpty := make(map[fm.ID]bool)
	for _, n := range p.nodes {
		if n.block.Kind == "address" && len(n.block.Members) > 0 {
			addressDefinitions[object(n).ID] = true
		}
	}
	for _, n := range p.nodes {
		b := n.block
		o := object(n)
		var d fm.Data
		if !slices.Contains([]string{"address", "service", "servgroup", "schedule"}, b.Kind) {
			continue
		}
		tx := begin(s, b)
		if b.Kind == "address" && len(b.Members) == 0 {
			if addressDefinitions[o.ID] || emittedEmpty[o.ID] {
				if err := s.Commit(tx); err != nil {
					return err
				}
				continue
			}
			emittedEmpty[o.ID] = true
		}
		switch b.Kind {
		case "address":
			r := fm.AddressRecord{Object: o}
			g := fm.AddressGroupRecord{Object: o}
			for _, l := range b.Members {
				w := l.Words
				ok := ancillary(w)
				if len(w) == 2 && w[0] == "ip" {
					if v, err := literal(w[1]); err == nil {
						r.Ranges = append(r.Ranges, v)
						ok = true
					}
				}
				if len(w) == 3 && w[0] == "range" {
					if v, err := literal(w[1] + "-" + w[2]); err == nil {
						r.Ranges = append(r.Ranges, v)
						ok = true
					}
				}
				if len(w) == 2 && w[0] == "host" {
					r.FQDN = w[1]
					ok = true
				}
				if len(w) == 2 && w[0] == "member" {
					g.Members = append(g.Members, p.addressRef(w[1]))
					ok = true
				}
				consume(tx, l, ok, &r.Object)
			}
			if len(g.Members) > 0 {
				g.Object = r.Object
				if len(r.Ranges) > 0 || r.FQDN != "" {
					leaf := r
					leaf.ID = fm.ID("$members:" + string(o.ID))
					g.Members = append(g.Members, fm.AddressRef{Kind: fm.AddressObject, ID: leaf.ID})
					d.Addresses = append(d.Addresses, leaf)
				}
				d.AddressGroups = append(d.AddressGroups, g)
			} else {
				d.Addresses = append(d.Addresses, r)
			}
		case "service":
			r := fm.ServiceRecord{Object: o}
			for _, l := range b.Members {
				v, ok := term(l.Words)
				if ok {
					r.Terms = append(r.Terms, v)
				}
				consume(tx, l, ok || ancillary(l.Words), &r.Object)
			}
			d.Services = append(d.Services, r)
		case "servgroup":
			r := fm.ServiceGroupRecord{Object: o}
			for _, l := range b.Members {
				w := l.Words
				ok := ancillary(w)
				if len(w) == 2 && w[0] == "service" {
					r.Members = append(r.Members, p.serviceRef(w[1]))
					ok = true
				}
				consume(tx, l, ok, &r.Object)
			}
			d.ServiceGroups = append(d.ServiceGroups, r)
		case "schedule":
			r := fm.ScheduleRecord{Object: o}
			for _, l := range b.Members {
				w := l.Words
				ok := ancillary(w)
				if len(w) == 7 && w[0] == "absolute" && w[1] == "start" && w[4] == "end" {
					start, e := time.Parse("01/02/2006 15:04:05", w[2]+" "+w[3])
					end, e2 := time.Parse("01/02/2006 15:04:05", w[5]+" "+w[6])
					if e == nil && e2 == nil && start.Before(end) {
						r.Windows = append(r.Windows, fm.TimeWindow{Start: start, End: end})
						r.Unsupported = append(r.Unsupported, "device timezone not established")
						ok = true
					}
				}
				consume(tx, l, ok, &r.Object)
			}
			d.Schedules = append(d.Schedules, r)
		}
		tx.Emit(d)
		if err := s.Commit(tx); err != nil {
			return err
		}
	}
	p.data = s.Data()
	return nil
}
func (p *parser) addressRef(name string) fm.AddressRef {
	kind := p.addressKinds[fm.ID(name)]
	if kind == fm.UnknownObject {
		kind = fm.AddressObject
	}
	return fm.AddressRef{Kind: kind, ID: fm.ID(name)}
}
func (p *parser) serviceRef(name string) fm.ServiceRef {
	kind := p.serviceKinds[fm.ID(name)]
	if kind == fm.UnknownObject {
		kind = fm.ServiceObject
	}
	return fm.ServiceRef{Kind: kind, ID: fm.ID(name)}
}
func (p *parser) routes(_ context.Context, s *config.Session) error {
	for _, row := range p.lines {
		w := row.line.Words
		if len(w) < 4 || w[0] != "ip" || w[1] != "route" {
			continue
		}
		dest, err := prefix(w[2:3])
		if err != nil {
			continue
		}
		r := fm.RouteRecord{Object: fm.Object{Scope: row.scope, Spans: []fm.Span{row.line.Span}}, Destination: dest.Masked()}
		rest := w[3:]
		if addr, err := netip.ParseAddr(rest[0]); err == nil {
			r.NextHop = addr
			rest = rest[1:]
		} else {
			r.Interface = fm.ID(rest[0])
			rest = rest[1:]
			if len(rest) > 0 {
				if addr, err := netip.ParseAddr(rest[0]); err == nil {
					r.NextHop = addr
					rest = rest[1:]
				}
			}
		}
		if len(rest) > 0 {
			continue
		}
		tx := s.Cursor().Begin()
		tx.Parse(row.line.Lines()...)
		r.ID = config.RouteID(r)
		tx.Emit(fm.Data{Routes: []fm.RouteRecord{r}})
		if err := s.Commit(tx); err != nil {
			return err
		}
	}
	return nil
}
func (p *parser) rules(_ context.Context, s *config.Session) error {
	position := 0
	records := make(map[fm.ID]fm.RuleRecord)
	var order []fm.ID
	tx := s.Cursor().Begin()
	for _, n := range p.nodes {
		if n.block.Kind != "rule" {
			continue
		}
		o := object(n)
		r, exists := records[o.ID]
		if !exists {
			r = fm.RuleRecord{Object: o, Position: position, Log: fm.Irrelevant, LogStart: fm.Irrelevant, LogEnd: fm.Irrelevant, RuleSet: "security"}
			position++
			order = append(order, o.ID)
		} else {
			r.Spans = append(r.Spans, o.Spans...)
		}
		tx.Parse(n.block.Header.Lines()...)
		if n.block.Complete {
			tx.Parse(n.block.End.Lines()...)
		}
		if n.from == "any" {
			r.Match.AnyFromZone = true
		} else if n.from != "" {
			r.Match.FromZones = []fm.ID{fm.ID(n.from)}
			if r.Scope == "" {
				r.Scope = p.zoneVRF[fm.ID(n.from)]
			}
		}
		if n.to == "any" {
			r.Match.AnyToZone = true
		} else if n.to != "" {
			r.Match.ToZones = []fm.ID{fm.ID(n.to)}
		}
		for _, l := range n.block.Members {
			w := l.Words
			ok := ancillary(w)
			if len(w) == 2 {
				switch w[0] {
				case "src-zone":
					if strings.EqualFold(w[1], "any") {
						r.Match.AnyFromZone = true
					} else {
						r.Match.FromZones = append(r.Match.FromZones, fm.ID(w[1]))
						if r.Scope == "" {
							r.Scope = p.zoneVRF[fm.ID(w[1])]
						}
					}
					ok = true
				case "dst-zone":
					if strings.EqualFold(w[1], "any") {
						r.Match.AnyToZone = true
					} else {
						r.Match.ToZones = append(r.Match.ToZones, fm.ID(w[1]))
					}
					ok = true
				case "src-addr":
					if w[1] == "any" {
						r.Match.AnySource = true
					} else {
						r.Match.Sources = append(r.Match.Sources, p.addressRef(w[1]))
					}
					ok = true
				case "dst-addr":
					if w[1] == "any" {
						r.Match.AnyDestination = true
					} else {
						r.Match.Destinations = append(r.Match.Destinations, p.addressRef(w[1]))
					}
					ok = true
				case "service":
					if w[1] == "any" {
						r.Match.AnyService = true
					} else {
						r.Match.Services = append(r.Match.Services, p.serviceRef(w[1]))
					}
					ok = true
				case "action":
					actions := map[string]fm.Action{"permit": fm.Permit, "deny": fm.Deny, "reject": fm.Reject}
					r.Action = actions[w[1]]
					ok = r.Action != fm.UnknownAction
				case "schedule":
					r.Match.Schedule = fm.ID(w[1])
					ok = true
				case "log":
					if w[1] == "session-start" {
						r.Log, r.LogStart, ok = fm.Known, fm.Known, true
					}
					if w[1] == "session-end" {
						r.Log, r.LogEnd, ok = fm.Known, fm.Known, true
					}
				}
			}
			if slices.Equal(w, []string{"disable"}) {
				r.Disabled = true
				ok = true
			}
			if slices.Equal(w, []string{"log"}) {
				r.Log = fm.Known
				r.LogStart, r.LogEnd = fm.Unknown, fm.Unknown
				ok = true
			}
			consume(tx, l, ok, &r.Object)
			if !ok {
				r.Match.Unsupported = append(r.Match.Unsupported, strings.TrimSpace(l.Raw))
			}
		}
		records[r.ID] = r
	}
	var rules []fm.RuleRecord
	for _, id := range order {
		r := records[id]
		if !r.Match.AnySource && len(r.Match.Sources) == 0 {
			r.Match.Sources = []fm.AddressRef{{ID: "$missing-source", Kind: fm.UnknownObject}}
		}
		if !r.Match.AnyDestination && len(r.Match.Destinations) == 0 {
			r.Match.Destinations = []fm.AddressRef{{ID: "$missing-destination", Kind: fm.UnknownObject}}
		}
		if !r.Match.AnyService && len(r.Match.Services) == 0 {
			r.Match.Services = []fm.ServiceRef{{ID: "$missing-service", Kind: fm.UnknownObject}}
		}
		rules = append(rules, r)
	}
	tx.Emit(fm.Data{Rules: rules})
	return s.Commit(tx)
}
