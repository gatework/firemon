// Package asa parses native ASA blocks, ACL bindings and distinct NAT objects.
package asa

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/flow"
)

type block struct {
	header               config.Statement
	kind, name, protocol string
	members              []config.Statement
}
type parser struct {
	session           *config.Session
	blocks            []block
	lines             []config.Statement
	data              fm.Data
	graph             *fm.Firewall
	literalIDs        map[fm.ID]bool
	literalCommitted  int
	literalDraft      *fm.Data
	literalDraftCount int
	aliases           map[string]fm.ID
	legacy, modern    bool
}

type Parser struct{ Limits config.Limits }

func Parse(ctx context.Context, source config.Source, metadata fm.Metadata) (*fm.Firewall, error) {
	return (Parser{}).Parse(ctx, source, metadata)
}

func (native Parser) Parse(ctx context.Context, source config.Source, metadata fm.Metadata) (*fm.Firewall, error) {
	metadata.Vendor = "asa"
	metadata.ParserVersion = "asa-go-2"
	cursor, err := config.NewCursor(source, native.Limits)
	if err != nil {
		return nil, err
	}
	statements, err := config.Statements(ctx, cursor)
	if err != nil {
		return nil, err
	}
	session, err := config.NewSession(cursor, metadata)
	if err != nil {
		return nil, err
	}
	p := &parser{session: session, aliases: make(map[string]fm.ID)}
	owner := -1
	for _, line := range statements {
		w := line.Words
		if len(w) == 0 || strings.HasPrefix(w[0], "!") {
			p.lines = append(p.lines, line)
			owner = -1
			continue
		}
		if w[0] == "interface" && len(w) == 2 {
			p.blocks = append(p.blocks, block{header: line, kind: "interface", name: w[1]})
			owner = len(p.blocks) - 1
			continue
		}
		if (w[0] == "object" || w[0] == "object-group") && len(w) >= 3 {
			b := block{header: line, kind: w[0] + "/" + w[1], name: w[2]}
			if len(w) > 3 {
				b.protocol = w[3]
			}
			p.blocks = append(p.blocks, b)
			owner = len(p.blocks) - 1
			continue
		}
		top := slices.Contains([]string{"access-list", "access-group", "route", "global", "static", "nat"}, w[0])
		if w[0] == "nat" && owner >= 0 && p.blocks[owner].kind == "object/network" && len(w) > 2 && (w[2] == "static" || w[2] == "dynamic") {
			top = false
		}
		if top {
			owner = -1
			p.lines = append(p.lines, line)
		} else if owner >= 0 {
			p.blocks[owner].members = append(p.blocks[owner].members, line)
		} else {
			p.lines = append(p.lines, line)
		}
	}
	stages := []config.Stage{{Name: "interfaces", Run: p.interfaces}, {Name: "objects", Requires: []string{"interfaces"}, Run: p.objects}, {Name: "routes-bindings", Requires: []string{"objects"}, Run: p.routes}, {Name: "acl", Requires: []string{"routes-bindings"}, Run: p.acls}, {Name: "nat", Requires: []string{"acl"}, Run: p.nat}}
	if err = p.session.Run(ctx, stages); err != nil {
		return nil, err
	}
	d := p.session.Data()
	if p.legacy && p.modern {
		d.Diagnostics = append(d.Diagnostics, fm.Diagnostic{Code: "mixed-nat-generation", Message: "legacy and modern ASA NAT require explicit migration/version evidence"})
	}
	return fm.Seal(d)
}
func object(b block) fm.Object {
	return fm.Object{ID: fm.ID(b.name), Name: b.name, Spans: []fm.Span{b.header.Span}}
}
func prefix(ip, mask string) (netip.Prefix, error) {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return netip.Prefix{}, err
	}
	if mask == "" {
		return netip.PrefixFrom(a, a.BitLen()), nil
	}
	m, err := netip.ParseAddr(mask)
	if err != nil || !a.Is4() || !m.Is4() {
		return netip.Prefix{}, flow.ErrRange
	}
	bytes := m.As4()
	ones, total := net.IPMask(bytes[:]).Size()
	if total != 32 {
		return netip.Prefix{}, flow.ErrRange
	}
	return netip.PrefixFrom(a, ones), nil
}
func iprange(value string) (flow.Range, error) {
	parts := strings.Split(value, "-")
	if len(parts) == 2 {
		a, e := netip.ParseAddr(parts[0])
		b, e2 := netip.ParseAddr(parts[1])
		r := flow.Range{First: a, Last: b}
		if e != nil || e2 != nil || !r.Valid() {
			return flow.Range{}, flow.ErrRange
		}
		return r, nil
	}
	if strings.Contains(value, "/") {
		p, e := netip.ParsePrefix(value)
		if e != nil {
			return flow.Range{}, e
		}
		return flow.PrefixRange(p)
	}
	p, e := prefix(value, "")
	if e != nil {
		return flow.Range{}, e
	}
	return flow.PrefixRange(p)
}
func (p *parser) interfaces(_ context.Context, s *config.Session) error {
	tx := s.Cursor().Begin()
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
	p.data = s.Data()
	return nil
}
func protocol(value string) (uint16, bool) {
	if n, ok := map[string]uint16{"ip": 0, "icmp": 1, "tcp": 6, "udp": 17, "gre": 47, "esp": 50, "ah": 51, "icmp6": 58, "sctp": 132}[value]; ok {
		return n, true
	}
	n, err := strconv.ParseUint(value, 10, 8)
	return uint16(n), err == nil
}
func portNumber(value string) (uint16, bool) {
	if n, ok := map[string]uint16{"http": 80, "www": 80, "https": 443, "ssh": 22, "domain": 53, "smtp": 25, "ftp": 21}[value]; ok {
		return n, true
	}
	n, err := strconv.ParseUint(value, 10, 16)
	return uint16(n), err == nil
}
func portSpec(words []string) ([]flow.Interval, int, bool) {
	if len(words) < 2 {
		return nil, 0, false
	}
	a, ok := portNumber(words[1])
	if !ok {
		return nil, 0, false
	}
	switch words[0] {
	case "eq":
		return []flow.Interval{{Low: a, High: a}}, 2, true
	case "range":
		if len(words) < 3 {
			return nil, 0, false
		}
		b, ok := portNumber(words[2])
		return []flow.Interval{{Low: a, High: b}}, 3, ok && a <= b
	case "lt":
		if a == 0 {
			return nil, 0, false
		}
		return []flow.Interval{{Low: 0, High: a - 1}}, 2, true
	case "gt":
		if a == 65535 {
			return nil, 0, false
		}
		return []flow.Interval{{Low: a + 1, High: 65535}}, 2, true
	case "neq":
		var result []flow.Interval
		if a > 0 {
			result = append(result, flow.Interval{Low: 0, High: a - 1})
		}
		if a < 65535 {
			result = append(result, flow.Interval{Low: a + 1, High: 65535})
		}
		return result, 2, true
	}
	return nil, 0, false
}
func term(proto uint16, source, destination flow.Interval) fm.ServiceTerm {
	return fm.ServiceTerm{Protocol: flow.Interval{Low: proto, High: proto}, SourcePort: source, DestinationPort: destination, ICMPType: flow.Interval{Low: 0, High: 255}, ICMPCode: flow.Interval{Low: 0, High: 255}}
}
func (p *parser) objects(_ context.Context, s *config.Session) error {
	tx := s.Cursor().Begin()
	d := fm.Data{}
	addressGroups := make(map[string]bool)
	serviceGroups := make(map[string]bool)
	for _, b := range p.blocks {
		if b.kind == "object-group/network" {
			addressGroups[b.name] = true
		}
		if b.kind == "object-group/service" || b.kind == "object-group/protocol" {
			serviceGroups[b.name] = true
		}
	}
	full := flow.Interval{Low: 0, High: 65535}
	for _, b := range p.blocks {
		if b.kind == "interface" {
			continue
		}
		o := object(b)
		a := fm.AddressRecord{Object: o}
		ag := fm.AddressGroupRecord{Object: o}
		service := fm.ServiceRecord{Object: o}
		sg := fm.ServiceGroupRecord{Object: o}
		supported := slices.Contains([]string{"object/network", "object-group/network", "object/service", "object-group/service", "object-group/protocol"}, b.kind)
		if !supported {
			continue
		}
		tx.Parse(b.header.Lines()...)
		for _, line := range b.members {
			w := line.Words
			ok := false
			if w[0] == "description" {
				ok = true
			}
			switch b.kind {
			case "object/network":
				if len(w) == 2 && w[0] == "host" {
					if r, err := iprange(w[1]); err == nil {
						a.Ranges = append(a.Ranges, r)
						ok = true
					}
				}
				if len(w) == 3 && w[0] == "subnet" {
					if v, err := prefix(w[1], w[2]); err == nil {
						r, _ := flow.PrefixRange(v)
						a.Ranges = append(a.Ranges, r)
						ok = true
					}
				}
				if len(w) == 3 && w[0] == "range" {
					if r, err := iprange(w[1] + "-" + w[2]); err == nil {
						a.Ranges = append(a.Ranges, r)
						ok = true
					}
				}
				if w[0] == "nat" {
					continue
				}
			case "object-group/network":
				if len(w) == 2 && w[0] == "group-object" {
					ag.Members = append(ag.Members, fm.AddressRef{Kind: fm.AddressGroupObject, ID: fm.ID(w[1])})
					ok = true
				}
				if len(w) == 3 && w[0] == "network-object" {
					if w[1] == "object" {
						kind := fm.AddressObject
						if addressGroups[w[2]] {
							kind = fm.AddressGroupObject
						}
						ag.Members = append(ag.Members, fm.AddressRef{Kind: kind, ID: fm.ID(w[2])})
						ok = true
					} else {
						if ref, n, valid := p.operand(w[1:], &d); valid && n == len(w)-1 {
							ag.Members = append(ag.Members, ref)
							ok = true
						}
					}
				}
			case "object-group/service", "object-group/protocol":
				if len(w) == 2 && w[0] == "group-object" {
					sg.Members = append(sg.Members, fm.ServiceRef{Kind: fm.ServiceGroupObject, ID: fm.ID(w[1])})
					ok = true
				}
				if len(w) == 3 && w[0] == "service-object" && w[1] == "object" {
					kind := fm.ServiceObject
					if serviceGroups[w[2]] {
						kind = fm.ServiceGroupObject
					}
					sg.Members = append(sg.Members, fm.ServiceRef{Kind: kind, ID: fm.ID(w[2])})
					ok = true
				}
				var terms []fm.ServiceTerm
				if len(w) == 2 && w[0] == "protocol-object" {
					terms, ok = serviceDefinition(w[1:])
				}
				if len(w) >= 2 && w[0] == "service-object" && w[1] != "object" {
					terms, ok = serviceDefinition(w[1:])
				}
				if w[0] == "port-object" {
					ranges, n, valid := portSpec(w[1:])
					if valid && n == len(w)-1 {
						protocols := []string{b.protocol}
						if b.protocol == "tcp-udp" {
							protocols = []string{"tcp", "udp"}
						}
						for _, proto := range protocols {
							n, valid := protocol(proto)
							if !valid {
								continue
							}
							for _, r := range ranges {
								terms = append(terms, term(n, full, r))
							}
						}
						ok = len(terms) > 0
					}
				}
				if len(terms) > 0 {
					id := inlineService(&d, p.data, terms)
					sg.Members = append(sg.Members, fm.ServiceRef{Kind: fm.ServiceObject, ID: id})
				}
			case "object/service":
				if len(w) >= 2 && w[0] == "service" {
					terms, valid := serviceDefinition(w[1:])
					if valid {
						service.Terms = append(service.Terms, terms...)
						ok = true
					}
				}
			}
			if ok {
				tx.Parse(line.Lines()...)
			} else {
				a.Unsupported = append(a.Unsupported, "unsupported object member")
				ag.Unsupported = append(ag.Unsupported, "unsupported group member")
				service.Unsupported = append(service.Unsupported, "unsupported service member")
				sg.Unsupported = append(sg.Unsupported, "unsupported service group member")
			}
		}
		switch b.kind {
		case "object/network":
			d.Addresses = append(d.Addresses, a)
		case "object-group/network":
			d.AddressGroups = append(d.AddressGroups, ag)
		case "object/service":
			d.Services = append(d.Services, service)
		default:
			d.ServiceGroups = append(d.ServiceGroups, sg)
		}
	}
	tx.Emit(d)
	if err := s.Commit(tx); err != nil {
		return err
	}
	p.data = s.Data()
	return nil
}
func (p *parser) routes(_ context.Context, s *config.Session) error {
	tx := s.Cursor().Begin()
	d := fm.Data{}
	for _, line := range p.lines {
		w := line.Words
		if len(w) == 6 && w[0] == "access-group" && w[3] == "interface" { // Kept below for native five-word shape too.
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
	p.data = s.Data()
	return nil
}
