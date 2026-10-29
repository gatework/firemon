package asa

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/netip"
	"slices"
	"strings"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/flow"
)

func pair(value string) (string, string, bool) {
	if !strings.HasPrefix(value, "(") || !strings.HasSuffix(value, ")") {
		return "", "", false
	}
	parts := strings.Split(value[1:len(value)-1], ",")
	if len(parts) != 2 {
		return "", "", false
	}
	return parts[0], parts[1], true
}
func (p *parser) ranges(name string) ([]flow.AddressRange, bool) {
	for _, a := range p.data.Addresses {
		if string(a.ID) == name {
			return a.Ranges, len(a.Unsupported) == 0 && a.FQDN == ""
		}
	}
	r, err := iprange(name)
	if err != nil {
		return nil, false
	}
	return []flow.AddressRange{r}, true
}
func nativeMatch(from, to string) fm.Match {
	m := fm.Match{AnySource: true, AnyDestination: true, AnyService: true}
	if from == "any" {
		m.AnyFromZone = true
	} else {
		m.FromZones = []fm.ID{fm.ID(from)}
	}
	if to == "any" {
		m.AnyToZone = true
	} else {
		m.ToZones = []fm.ID{fm.ID(to)}
	}
	return m
}
func staticMappings(original, target []flow.AddressRange) ([]fm.Mapping, bool) {
	if len(original) != 1 || len(target) != 1 {
		return nil, false
	}
	mode := fm.Offset
	if original[0].First.BitLen() != target[0].First.BitLen() || rangeCount(original[0]).Cmp(rangeCount(target[0])) != 0 {
		mode = fm.UnknownMapping
	}
	return []fm.Mapping{{Original: original[0], Translated: target[0], Mode: mode}}, true
}

// A dynamic address pool must be declared as a range (or a host for PAT).
// A subnet's cardinality alone does not prove the native pool syntax is valid.
func (p *parser) dynamicTarget(name string) bool {
	for _, b := range p.blocks {
		if b.kind != "object/network" || b.name != name {
			continue
		}
		count := 0
		for _, line := range b.members {
			if line.Words[0] == "subnet" {
				return false
			}
			if line.Words[0] == "host" || line.Words[0] == "range" {
				count++
			}
		}
		return count == 1
	}
	a, err := netip.ParseAddr(name)
	return err == nil && a.IsValid()
}

func (p *parser) natService(words []string, object bool) (fm.ServiceTerm, fm.ServiceTerm, int, bool) {
	if len(words) == 0 || words[0] != "service" {
		return fm.ServiceTerm{}, fm.ServiceTerm{}, 0, false
	}
	if object {
		if len(words) < 4 || (words[1] != "tcp" && words[1] != "udp") {
			return fm.ServiceTerm{}, fm.ServiceTerm{}, 0, false
		}
		a, ok := portNumber(words[2])
		b, ok2 := portNumber(words[3])
		if !ok || !ok2 {
			return fm.ServiceTerm{}, fm.ServiceTerm{}, 0, false
		}
		proto, _ := protocol(words[1])
		full := flow.Interval{High: 65535}
		return term(proto, flow.Interval{Low: a, High: a}, full), term(proto, flow.Interval{Low: b, High: b}, full), 4, true
	}
	if len(words) < 3 {
		return fm.ServiceTerm{}, fm.ServiceTerm{}, 0, false
	}
	get := func(name string) (fm.ServiceTerm, bool) {
		for _, s := range p.data.Services {
			if string(s.ID) == name && len(s.Unsupported) == 0 && len(s.Terms) == 1 {
				return s.Terms[0], true
			}
		}
		return fm.ServiceTerm{}, false
	}
	a, ok := get(words[1])
	b, ok2 := get(words[2])
	if !ok || !ok2 || a.Protocol != b.Protocol || a.Protocol.Low != a.Protocol.High || (a.Protocol.Low != 6 && a.Protocol.Low != 17) {
		return a, b, 0, false
	}
	return a, b, 3, true
}

func portMapping(a, b flow.Interval) ([]fm.PortMapping, bool) {
	if a == b {
		return nil, true
	}
	if a.High-a.Low != b.High-b.Low {
		return nil, false
	}
	return []fm.PortMapping{{Original: a, Translated: b, Mode: fm.Offset}}, true
}
func (p *parser) nat(_ context.Context, s *config.Session) error {
	tx := s.Cursor().Begin()
	d := fm.Data{}
	for _, line := range p.lines {
		w := line.Words
		if len(w) < 4 || w[0] != "global" {
			continue
		}
		outside := strings.Trim(w[1], "()")
		ranges, known := p.ranges(w[3])
		if !known {
			continue
		}
		id := fm.ID("global:" + outside + ":" + w[2])
		d.NATPools = append(d.NATPools, fm.NATPoolRecord{Object: fm.Object{ID: id, Name: w[2]}, Ranges: ranges, Interface: p.aliases[outside]})
		tx.Parse(line.Lines()...)
		p.legacy = true
	}
	modern := func(line config.Statement, owner string) {
		w := line.Words
		if len(w) < 4 {
			return
		}
		from, to, ok := pair(w[1])
		if !ok {
			return
		}
		rest := w[2:]
		stage := 1
		if owner != "" {
			stage = 2
		}
		if rest[0] == "after-auto" {
			stage = 3
			rest = rest[1:]
		}
		if len(rest) < 2 {
			return
		}
		identity, _ := json.Marshal(struct {
			Owner string
			Words []string
		}{owner, w})
		hash := sha256.Sum256(identity)
		id := fm.ID("nat:" + hex.EncodeToString(hash[:]))
		name := string(id)
		if owner != "" {
			id = fm.ID("auto:" + owner)
			name = owner
		}
		o := fm.Object{ID: id, Name: name, Spans: []fm.Span{line.Span}}
		order := fm.NATOrder{Stage: stage, Position: line.Span.First}
		mode, real, mapped := "", owner, ""
		if owner != "" {
			mode, mapped = rest[0], rest[1]
			rest = rest[2:]
		} else {
			if len(rest) < 4 || rest[0] != "source" {
				return
			}
			mode, real, mapped = rest[1], rest[2], rest[3]
			rest = rest[4:]
		}
		original, known := p.ranges(real)
		target, targetKnown := p.ranges(mapped)
		match := nativeMatch(from, to)
		if real != "" {
			match.AnySource = false
			match.Sources = []fm.AddressRef{{Kind: fm.AddressObject, ID: fm.ID(real)}}
		}
		if mode == "static" {
			if !known || !targetKnown {
				return
			}
			mappings, valid := staticMappings(original, target)
			if !valid {
				return
			}
			r := fm.StaticNATRecord{Object: o, Match: match, Order: order, Source: mappings, Bidirectional: true}
			if len(rest) >= 4 && rest[0] == "destination" && rest[1] == "static" {
				a, ok := p.ranges(rest[2])
				b, ok2 := p.ranges(rest[3])
				if !ok || !ok2 {
					r.Unsupported = append(r.Unsupported, "unresolved twice NAT destination")
				} else {
					r.Destination, _ = staticMappings(a, b)
				}
				rest = rest[4:]
			}
			if len(rest) > 0 && rest[0] == "service" {
				a, b, consumed, valid := p.natService(rest, owner != "")
				if valid {
					src, sourceOK := portMapping(a.SourcePort, b.SourcePort)
					dst, destOK := portMapping(a.DestinationPort, b.DestinationPort)
					if sourceOK && destOK {
						svcID := fm.ID("$nat-service:" + string(id))
						d.Services = append(d.Services, fm.ServiceRecord{Object: fm.Object{ID: svcID}, Terms: []fm.ServiceTerm{a}})
						r.Match.AnyService = false
						r.Match.Services = []fm.ServiceRef{{Kind: fm.ServiceObject, ID: svcID}}
						r.SourcePorts, r.DestinationPorts = src, dst
						rest = rest[consumed:]
					}
				}
			}
			for _, option := range rest {
				switch option {
				case "inactive":
					r.Disabled = true
				case "no-proxy-arp", "route-lookup":
					r.Unsupported = append(r.Unsupported, "native NAT route/proxy option")
				case "unidirectional":
					r.Bidirectional = false
				default:
					r.Unsupported = append(r.Unsupported, "unsupported manual NAT option")
				}
			}
			d.StaticNATs = append(d.StaticNATs, r)
		} else if mode == "dynamic" {
			r := fm.DynamicNATRecord{Object: o, Match: match, Order: order, SourceMode: fm.DynamicIPPort, DestinationMode: fm.NoTranslation}
			if mapped == "interface" {
				r.SourceMode = fm.InterfaceIP
				r.Interface = p.aliases[to]
			} else if targetKnown {
				if !p.dynamicTarget(mapped) {
					r.Unsupported = append(r.Unsupported, "dynamic NAT target must be a host or range")
				}
				if len(target) == 1 && target[0].First != target[0].Last {
					r.SourceMode = fm.DynamicIP
				}
				poolID := fm.ID("$pool:" + string(id))
				r.SourcePool = poolID
				d.NATPools = append(d.NATPools, fm.NATPoolRecord{Object: fm.Object{ID: poolID}, Ranges: target})
			} else {
				r.Unsupported = append(r.Unsupported, "unknown dynamic NAT target")
			}
			if len(rest) > 0 {
				r.Unsupported = append(r.Unsupported, "unsupported dynamic NAT options")
			}
			d.DynamicNATs = append(d.DynamicNATs, r)
		} else {
			return
		}
		p.modern = true
		tx.Parse(line.Lines()...)
	}
	for _, b := range p.blocks {
		if b.kind != "object/network" {
			continue
		}
		for _, line := range b.members {
			if len(line.Words) > 0 && line.Words[0] == "nat" {
				modern(line, b.name)
			}
		}
	}
	for _, line := range p.lines {
		w := line.Words
		if len(w) == 0 {
			continue
		}
		if w[0] == "static" && len(w) == 6 && w[4] == "netmask" {
			from, to, ok := pair(w[1])
			if !ok {
				continue
			}
			a, e := prefix(w[3], w[5])
			b, e2 := prefix(w[2], w[5])
			if e != nil || e2 != nil {
				continue
			}
			real, _ := flow.PrefixRange(a)
			mapped, _ := flow.PrefixRange(b)
			id := fm.ID(fmt.Sprintf("static:%d", line.Span.First))
			d.StaticNATs = append(d.StaticNATs, fm.StaticNATRecord{Object: fm.Object{ID: id, Spans: []fm.Span{line.Span}}, Order: fm.NATOrder{Stage: 0, Position: line.Span.First, Section: "legacy"}, Match: nativeMatch(from, to), Source: []fm.Mapping{{Original: real, Translated: mapped, Mode: fm.Offset}}, Bidirectional: true})
			tx.Parse(line.Lines()...)
			p.legacy = true
		}
		if w[0] == "nat" && len(w) >= 4 {
			if _, _, ok := pair(w[1]); ok {
				modern(line, "")
				continue
			}
			if len(w) == 5 && w[3] == "access-list" {
				inside := strings.Trim(w[1], "()")
				var pools []fm.NATPoolRecord
				for _, pool := range d.NATPools {
					if pool.Name == w[2] {
						pools = append(pools, pool)
					}
				}
				id := fm.ID(fmt.Sprintf("legacy-nat:%d", line.Span.First))
				r := fm.DynamicNATRecord{Object: fm.Object{ID: id, Unsupported: []string{"legacy NAT ACL requires ordered ACL eligibility evaluation"}}, Order: fm.NATOrder{Stage: 0, Position: line.Span.First, Section: "legacy"}, Match: fm.Match{FromZones: []fm.ID{fm.ID(inside)}, AnyToZone: true, AnySource: true, AnyDestination: true, AnyService: true}, SourceMode: fm.DynamicIPPort, DestinationMode: fm.NoTranslation}
				if len(pools) == 1 {
					r.SourcePool = pools[0].ID
				}
				d.DynamicNATs = append(d.DynamicNATs, r)
				tx.Parse(line.Lines()...)
				p.legacy = true
			}
		}
	}
	// Section 2 has native static-before-dynamic ordering, then smaller source objects, address and name.
	type auto struct {
		kind  fm.Kind
		index int
		name  string
		first netip.Addr
		count *big.Int
	}
	var autos []auto
	for i, r := range d.StaticNATs {
		if r.Order.Stage == 2 {
			a := auto{kind: fm.StaticNATObject, index: i, name: r.Name}
			if len(r.Source) > 0 {
				a.first = r.Source[0].Original.First
				a.count = rangeCount(r.Source[0].Original)
			}
			autos = append(autos, a)
		}
	}
	for i, r := range d.DynamicNATs {
		if r.Order.Stage == 2 {
			a := auto{kind: fm.DynamicNATObject, index: i, name: r.Name}
			if len(r.Match.Sources) > 0 {
				if ranges, ok := p.ranges(string(r.Match.Sources[0].ID)); ok && len(ranges) == 1 {
					a.first = ranges[0].First
					a.count = rangeCount(ranges[0])
				}
			}
			autos = append(autos, a)
		}
	}
	slices.SortFunc(autos, func(a, b auto) int {
		if a.kind != b.kind {
			return int(a.kind) - int(b.kind)
		}
		if a.count != nil && b.count != nil {
			if c := a.count.Cmp(b.count); c != 0 {
				return c
			}
		}
		if c := a.first.Compare(b.first); c != 0 {
			return c
		}
		return strings.Compare(a.name, b.name)
	})
	for position, a := range autos {
		if a.kind == fm.StaticNATObject {
			d.StaticNATs[a.index].Order.Position = position
		} else {
			d.DynamicNATs[a.index].Order.Position = position
		}
	}
	tx.Emit(d)
	return s.Commit(tx)
}
func rangeCount(r flow.AddressRange) *big.Int {
	first, last := r.First.As16(), r.Last.As16()
	n := new(big.Int).Sub(new(big.Int).SetBytes(last[:]), new(big.Int).SetBytes(first[:]))
	return n.Add(n, big.NewInt(1))
}
