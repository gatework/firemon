package huawei

import (
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/flow"
)

type poolDefinition struct {
	record fm.NATPoolRecord
	mode   fm.TranslationMode
}

func (p *parser) nat(ctx context.Context, s *config.Session) error {
	tx := s.Cursor().Begin()
	defer tx.Rollback()
	var d fm.Data
	pools := make(map[fm.ID]poolDefinition)
	for _, direction := range []string{"source", "destination"} {
		groups, err := p.grouped(direction+"-pool", func(w []string) (string, string, error) {
			if (len(w) != 3 && len(w) != 4) || w[2] == "" {
				return "", "", fmt.Errorf("invalid NAT pool")
			}
			if len(w) == 4 {
				if _, ok := number(w[3], 0, 1<<32-1); !ok {
					return "", "", fmt.Errorf("invalid pool ID")
				}
			}
			return w[2], direction, nil
		})
		if err != nil {
			return err
		}
		ids := make(map[string]string)
		for _, g := range groups {
			r := fm.NATPoolRecord{Object: object(direction + ":" + g.name), Ports: flow.Interval{High: 65535}}
			r.Name = g.name
			mode := fm.DynamicIPPort
			if direction == "destination" {
				mode = fm.StaticIP
			}
			var items members[flow.AddressRange]
			var nativeID string
			for _, b := range g.blocks {
				w := b.Header.Words
				if len(w) == 4 {
					if old, ok := ids[w[3]]; ok && old != g.name || nativeID != "" && nativeID != w[3] {
						return fmt.Errorf("%w: conflicting native pool ID", config.ErrSource)
					}
					ids[w[3]] = g.name
					nativeID = w[3]
				}
			}
			err := walk(ctx, tx, &r.Object, g, func(row config.Statement) bool {
				w := row.Words
				if w[0] == "description" && len(w) > 1 {
					return true
				}
				if w[0] == "mode" && direction == "source" {
					switch strings.Join(w[1:], " ") {
					case "pat":
						mode = fm.DynamicIPPort
						return true
					case "no-pat global":
						mode = fm.DynamicIP
						return true
					}
					return false
				}
				if w[0] != "section" {
					return false
				}
				id, rest := member(w[1:])
				if len(rest) < 1 || len(rest) > 2 {
					return false
				}
				last := rest[0]
				if len(rest) == 2 {
					last = rest[1]
				}
				a, ok1 := ipv4(rest[0])
				b, ok2 := ipv4(last)
				rr := flow.AddressRange{First: a, Last: b}
				return ok1 && ok2 && rr.Valid() && items.put(id, rr)
			})
			if err != nil {
				return err
			}
			r.Ranges = items.values
			if len(r.Ranges) == 0 {
				r.Unsupported = append(r.Unsupported, "empty NAT address pool")
			}
			pools[r.ID] = poolDefinition{record: r, mode: mode}
			d.NATPools = append(d.NATPools, r)
		}
	}
	servers := make(map[string]bool)
	for _, row := range p.lines {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !has(row.Words, "nat", "server") {
			continue
		}
		w := row.Words[2:]
		if len(w) == 0 {
			continue
		}
		if servers[w[0]] {
			return fmt.Errorf("%w: duplicate NAT server %s", config.ErrSource, w[0])
		}
		servers[w[0]] = true
		fixed, dynamic, ok := p.server(w, &d)
		if !ok {
			continue
		}
		if fixed != nil {
			fixed.Spans = []fm.Span{row.Span}
			d.StaticNATs = append(d.StaticNATs, *fixed)
		}
		if dynamic != nil {
			dynamic.Spans = []fm.Span{row.Span}
			d.DynamicNATs = append(d.DynamicNATs, *dynamic)
			if len(dynamic.Unsupported) > 0 {
				d.Diagnostics = append(d.Diagnostics, fm.Diagnostic{Code: "unresolved-reverse-server", Message: "protocol-specific reverse server-map conditions are not established", Span: row.Span})
			}
		}
		tx.Parse(row.Lines()...)
	}
	blocks, root, err := p.ruleBlocks("nat-policy")
	if err != nil {
		return err
	}
	for _, row := range root {
		if slices.Equal(row.Words, []string{"nat-policy"}) {
			tx.Parse(row.Lines()...)
		}
	}
	for position, b := range blocks {
		r := fm.DynamicNATRecord{Object: object("policy:" + b.name), Match: anyMatch(), Order: fm.NATOrder{Stage: 2, Position: position, Section: "nat-policy"}, SourceMode: fm.NoTranslation, DestinationMode: fm.NoTranslation}
		r.Name = b.name
		seen := make(map[string]bool)
		actions := make(map[string]bool)
		for _, row := range b.headers {
			claim(tx, &r.Object, row, true)
		}
		for _, row := range b.members {
			if err := ctx.Err(); err != nil {
				return err
			}
			w := row.Words
			ok := false
			if indent(row) == 2 {
				switch {
				case w[0] == "action":
					if len(w) > 1 && !actions[w[1]] {
						actions[w[1]] = true
						ok = p.natAction(&r, w[1:], pools)
					}
				case w[0] == "egress-interface":
					name, valid := interfaceName(w[1:])
					if valid {
						r.Interface = fm.ID(name)
						ok = true
					}
				case len(w) == 1 && w[0] == "disable":
					r.Disabled = true
					ok = true
				case slices.Equal(w, []string{"undo", "disable"}):
					r.Disabled = false
					ok = true
				case w[0] == "description" && len(w) > 1:
					ok = true
				default:
					ok = p.matchLine(&d, &r.Match, w, seen)
				}
			}
			claim(tx, &r.Object, row, ok)
		}
		if len(actions) == 0 || actions["no-nat"] && len(actions) > 1 {
			r.Unsupported = append(r.Unsupported, "missing or conflicting NAT actions")
		}
		if r.SourceMode == fm.InterfaceIP {
			if r.Interface == "" {
				for _, i := range p.data.Interfaces {
					if !r.Match.AnyToZone && slices.Contains(r.Match.ToZones, i.Zone) && !i.Disabled {
						if r.Interface != "" {
							r.Interface = ""
							break
						}
						r.Interface = i.ID
					}
				}
			}
			if r.Interface == "" {
				r.Unsupported = append(r.Unsupported, "Easy-IP requires an unambiguous egress interface")
			}
		}
		if r.DestinationMode != fm.NoTranslation {
			r.Order.Stage = 1
		}
		if len(r.DestinationPorts) > 0 && !p.transportServices(r.Match, d) {
			r.Unsupported = append(r.Unsupported, "destination port translation requires explicit resolved transport services")
		}
		d.DynamicNATs = append(d.DynamicNATs, r)
	}
	return p.commit(s, tx, d)
}

func (p *parser) transportServices(m fm.Match, d fm.Data) bool {
	if m.AnyService || len(m.Services) == 0 {
		return false
	}
	services := make(map[fm.ID]fm.ServiceRecord)
	groups := make(map[fm.ID]fm.ServiceGroupRecord)
	for _, records := range [][]fm.ServiceRecord{p.data.Services, d.Services} {
		for _, s := range records {
			services[s.ID] = s
		}
	}
	for _, g := range p.data.ServiceGroups {
		groups[g.ID] = g
	}
	active := make(map[fm.ID]bool)
	budget := 4096
	var visit func(fm.ServiceRef) bool
	visit = func(ref fm.ServiceRef) bool {
		if budget <= 0 {
			return false
		}
		budget--
		if ref.Kind == fm.ServiceObject {
			s, ok := services[ref.ID]
			if !ok || len(s.Unsupported) > 0 || len(s.Terms) == 0 {
				return false
			}
			for _, t := range s.Terms {
				if t.Protocol.Low != t.Protocol.High || !slices.Contains([]uint16{6, 17, 132}, t.Protocol.Low) {
					return false
				}
			}
			return true
		}
		if ref.Kind != fm.ServiceGroupObject || active[ref.ID] {
			return false
		}
		g, ok := groups[ref.ID]
		if !ok || len(g.Unsupported) > 0 || len(g.Members) == 0 {
			return false
		}
		active[ref.ID] = true
		defer delete(active, ref.ID)
		for _, child := range g.Members {
			if !visit(child) {
				return false
			}
		}
		return true
	}
	for _, ref := range m.Services {
		if !visit(ref) {
			return false
		}
	}
	return true
}
func (p *parser) natAction(r *fm.DynamicNATRecord, w []string, pools map[fm.ID]poolDefinition) bool {
	if len(w) == 1 && w[0] == "no-nat" {
		return true
	}
	if len(w) < 2 || (w[0] != "source-nat" && w[0] != "destination-nat") {
		return false
	}
	if w[0] == "source-nat" {
		if len(w) == 2 && w[1] == "easy-ip" {
			r.SourceMode = fm.InterfaceIP
			return true
		}
		if len(w) != 3 || w[1] != "address-group" {
			return false
		}
		id := fm.ID("source:" + w[2])
		pool, ok := pools[id]
		if !ok {
			return false
		}
		r.SourcePool, r.SourceMode = id, pool.mode
		return true
	}
	if len(w) < 3 || len(w) > 4 {
		return false
	}
	var translated flow.AddressRange
	switch w[1] {
	case "address":
		a, ok := ipv4(w[2])
		if !ok {
			return false
		}
		translated = flow.AddressRange{First: a, Last: a}
	case "address-group":
		id := fm.ID("destination:" + w[2])
		pool, ok := pools[id]
		if !ok {
			return false
		}
		r.DestinationPool = id
		if len(pool.record.Ranges) != 1 || pool.record.Ranges[0].First != pool.record.Ranges[0].Last {
			r.Unsupported = append(r.Unsupported, "destination pool allocation requires native session evidence")
			return false
		}
		translated = pool.record.Ranges[0]
	default:
		return false
	}
	if len(w) == 4 {
		port, ok := number(w[3], 1, 65535)
		if !ok {
			return false
		}
		r.DestinationPorts = []fm.PortMapping{{Original: flow.Interval{High: 65535}, Translated: flow.Interval{Low: uint16(port), High: uint16(port)}, Mode: fm.Constant}}
	}
	all, _ := flow.PrefixRange(netip.MustParsePrefix("0.0.0.0/0"))
	r.DestinationMode = fm.StaticIP
	r.Destination = []fm.Mapping{{Original: all, Translated: translated, Mode: fm.Constant}}
	return true
}

type endpoint struct {
	address flow.AddressRange
	port    uint16
	hasPort bool
}

func serverEndpoint(w []string, proto uint16) (endpoint, bool) {
	var e endpoint
	if len(w) == 0 {
		return e, false
	}
	first, ok := ipv4(w[0])
	if !ok {
		return e, false
	}
	w = w[1:]
	last := first
	if len(w) > 0 {
		if a, ok := ipv4(w[0]); ok {
			last = a
			w = w[1:]
		}
	}
	e.address = flow.AddressRange{First: first, Last: last}
	if !e.address.Valid() || len(w) > 1 {
		return e, false
	}
	if len(w) == 1 {
		if proto != 6 && proto != 17 && proto != 132 {
			return e, false
		}
		n, ok := number(w[0], 1, 65535)
		if !ok {
			return e, false
		}
		e.port, e.hasPort = uint16(n), true
	}
	return e, true
}
func (p *parser) server(w []string, d *fm.Data) (*fm.StaticNATRecord, *fm.DynamicNATRecord, bool) {
	name := w[0]
	w = w[1:]
	if name == "" || slices.Contains([]string{"zone", "protocol", "global", "inside"}, name) {
		return nil, nil, false
	}
	if len(w) > 0 {
		if _, ok := number(w[0], 0, 1<<32-1); ok {
			w = w[1:]
		}
	}
	match := anyMatch()
	var proto uint16
	var hasProto bool
	seen := make(map[string]bool)
	for len(w) > 0 && (w[0] == "zone" || w[0] == "protocol") {
		if len(w) < 2 || seen[w[0]] {
			return nil, nil, false
		}
		seen[w[0]] = true
		if w[0] == "zone" {
			match.AnyFromZone = false
			match.FromZones = []fm.ID{fm.ID(strings.ToLower(w[1]))}
		} else {
			var ok bool
			proto, ok = protocol(w[1])
			if !ok {
				return nil, nil, false
			}
			hasProto = true
		}
		w = w[2:]
	}
	if len(w) < 4 || w[0] != "global" {
		return nil, nil, false
	}
	inside := slices.Index(w, "inside")
	if inside < 2 {
		return nil, nil, false
	}
	public, private := slices.Clone(w[1:inside]), slices.Clone(w[inside+1:])
	noReverse := len(private) > 0 && private[len(private)-1] == "no-reverse"
	if noReverse {
		private = private[:len(private)-1]
	}
	var iface fm.ID
	if len(public) > 0 && public[0] == "interface" {
		public = public[1:]
		if len(public) == 0 {
			return nil, nil, false
		}
		count := 1
		name, ok := interfaceName(public[:1])
		if !ok && len(public) >= 2 {
			name, ok = interfaceName(public[:2])
			count = 2
		}
		if !ok {
			return nil, nil, false
		}
		iface = fm.ID(name)
		found := false
		for _, i := range p.data.Interfaces {
			if i.ID == iface && len(i.Addresses) == 1 && !i.Disabled && len(i.Unsupported) == 0 {
				public = append([]string{i.Addresses[0].Addr().String()}, public[count:]...)
				found = true
				break
			}
		}
		if !found {
			return nil, nil, false
		}
	}
	a, ok1 := serverEndpoint(public, proto)
	b, ok2 := serverEndpoint(private, proto)
	if !ok1 || !ok2 || addressCount(a.address) != addressCount(b.address) || b.hasPort && !a.hasPort {
		return nil, nil, false
	}
	if hasProto && addressCount(a.address) != 1 {
		return nil, nil, false
	}
	if !b.hasPort {
		b.port, b.hasPort = a.port, a.hasPort
	}
	o := object("server:" + name)
	o.Name = name
	mapping := fm.Mapping{Original: a.address, Translated: b.address, Mode: fm.Offset}
	if !hasProto {
		return &fm.StaticNATRecord{Object: o, Match: match, Order: fm.NATOrder{Stage: 0, Section: "nat-server"}, Destination: []fm.Mapping{mapping}, Interface: iface, Bidirectional: !noReverse}, nil, true
	}
	r := fm.DynamicNATRecord{Object: o, Match: match, Order: fm.NATOrder{Stage: 0, Section: "nat-server"}, SourceMode: fm.NoTranslation, DestinationMode: fm.StaticIP, Destination: []fm.Mapping{mapping}, Interface: iface}
	t := term(proto)
	if a.hasPort {
		t.DestinationPort = flow.Interval{Low: a.port, High: a.port}
		r.DestinationPorts = []fm.PortMapping{{Original: t.DestinationPort, Translated: flow.Interval{Low: b.port, High: b.port}, Mode: fm.Offset}}
	}
	r.Match.AnyService = false
	r.Match.Services = []fm.ServiceRef{p.literalService(d, []fm.ServiceTerm{t})}
	if !noReverse {
		r.Unsupported = append(r.Unsupported, "protocol-specific reverse server-map conditions require version evidence")
	}
	return nil, &r, true
}

func addressCount(r flow.AddressRange) uint64 {
	return uint64(binary.BigEndian.Uint32(r.Last.AsSlice())) - uint64(binary.BigEndian.Uint32(r.First.AsSlice())) + 1
}
