package paloalto

import (
	"context"
	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/policy"
	"slices"
	"strings"
)

func (p *parser) addressRef(name string, d *fm.Data) fm.AddressRef {
	for _, a := range p.data.Addresses {
		if string(a.ID) == name {
			return fm.AddressRef{Kind: fm.AddressObject, ID: a.ID}
		}
	}
	for _, g := range p.data.AddressGroups {
		if string(g.ID) == name {
			return fm.AddressRef{Kind: fm.AddressGroupObject, ID: g.ID}
		}
	}
	if r, err := address(name); err == nil {
		id := fm.ID("$literal:" + name)
		for _, a := range append(slices.Clone(p.data.Addresses), d.Addresses...) {
			if a.ID == id {
				return fm.AddressRef{Kind: fm.AddressObject, ID: id}
			}
		}
		d.Addresses = append(d.Addresses, fm.AddressRecord{Object: fm.Object{ID: id, Name: name}, Ranges: []flow.Range{r}})
		return fm.AddressRef{Kind: fm.AddressObject, ID: id}
	}
	return fm.AddressRef{Kind: fm.AddressObject, ID: fm.ID(name)}
}
func (p *parser) serviceRef(name string) fm.ServiceRef {
	for _, g := range p.data.ServiceGroups {
		if string(g.ID) == name {
			return fm.ServiceRef{Kind: fm.ServiceGroupObject, ID: g.ID}
		}
	}
	return fm.ServiceRef{Kind: fm.ServiceObject, ID: fm.ID(name)}
}
func (p *parser) matchField(m *fm.Match, field string, rest []string, d *fm.Data) bool {
	switch field {
	case "from", "to":
		for _, name := range rest {
			if field == "from" {
				if name == "any" {
					m.AnyFromZone = true
				} else {
					m.FromZones = append(m.FromZones, fm.ID(name))
				}
			} else {
				if name == "any" {
					m.AnyToZone = true
				} else {
					m.ToZones = append(m.ToZones, fm.ID(name))
				}
			}
		}
		return true
	case "source", "destination":
		for _, name := range rest {
			if field == "source" {
				if name == "any" {
					m.AnySource = true
				} else {
					m.Sources = append(m.Sources, p.addressRef(name, d))
				}
			} else {
				if name == "any" {
					m.AnyDestination = true
				} else {
					m.Destinations = append(m.Destinations, p.addressRef(name, d))
				}
			}
		}
		return true
	case "service":
		for _, name := range rest {
			if name == "any" {
				m.AnyService = true
			} else {
				m.Services = append(m.Services, p.serviceRef(name))
			}
		}
		return true
	}
	return false
}
func ensureSelectors(m *fm.Match) {
	if !m.AnySource && len(m.Sources) == 0 {
		m.Sources = []fm.AddressRef{{ID: "$missing-source", Kind: fm.UnknownObject}}
	}
	if !m.AnyDestination && len(m.Destinations) == 0 {
		m.Destinations = []fm.AddressRef{{ID: "$missing-destination", Kind: fm.UnknownObject}}
	}
	if !m.AnyService && len(m.Services) == 0 {
		m.Services = []fm.ServiceRef{{ID: "$missing-service", Kind: fm.UnknownObject}}
	}
	if !m.AnyFromZone && len(m.FromZones) == 0 {
		m.Unsupported = append(m.Unsupported, "missing source zone")
	}
	if !m.AnyToZone && len(m.ToZones) == 0 {
		m.Unsupported = append(m.Unsupported, "missing destination zone")
	}
}
func (p *parser) rules(_ context.Context, s *config.Session) error {
	tx := s.Cursor.Begin()
	rules := make(map[string]fm.RuleRecord)
	var order []string
	d := fm.Data{}
	for _, row := range p.rows {
		w := row.words
		if len(w) < 6 || w[0] != "rulebase" || (w[1] != "security" && w[1] != "default-security-rules") || w[2] != "rules" {
			continue
		}
		name, field, rest := w[3], w[4], values(w[5:])
		builtin := w[1] == "default-security-rules"
		nativeName := name
		if builtin {
			if name != "intrazone-default" && name != "interzone-default" {
				continue
			}
			name = "$default:" + name
		}
		r, exists := rules[name]
		if !exists {
			r = fm.RuleRecord{Object: object(name, row), Position: len(order), RuleSet: "security"}
			if builtin {
				r = defaultRule(nativeName)
				r.Spans = []fm.Span{row.source.Span}
			}
			order = append(order, name)
		}
		if builtin && !slices.Contains([]string{"action", "log-start", "log-end"}, field) {
			r.Unsupported = append(r.Unsupported, "unsupported native default override "+field)
			rules[name] = r
			continue
		}
		ok := p.matchField(&r.Match, field, rest, &d)
		switch field {
		case "rule-type":
			if len(rest) == 1 {
				switch rest[0] {
				case "universal":
					r.Match.ZoneRelation = fm.AnyZoneRelation
					ok = true
				case "intrazone":
					r.Match.ZoneRelation = fm.SameZone
					ok = true
				case "interzone":
					r.Match.ZoneRelation = fm.DifferentZones
					ok = true
				}
			}
		case "action":
			if len(rest) == 1 {
				r.Action = map[string]fm.Action{"allow": fm.Permit, "deny": fm.Deny, "drop": fm.Drop, "reset-client": fm.ResetClient, "reset-server": fm.ResetServer, "reset-both": fm.ResetBoth}[rest[0]]
				ok = r.Action != fm.UnknownAction
			}
		case "application":
			if slices.Equal(rest, []string{"any"}) {
				ok = true
			} else {
				r.Match.Applications = append(r.Match.Applications, rest...)
				ok = true
			}
		case "source-user":
			if slices.Equal(rest, []string{"any"}) {
				ok = true
			} else {
				r.Match.Users = append(r.Match.Users, rest...)
				ok = true
			}
		case "schedule":
			if len(rest) == 1 {
				r.Match.Schedule = fm.ID(rest[0])
				ok = true
			}
		case "disabled":
			if len(rest) == 1 && (rest[0] == "yes" || rest[0] == "no") {
				r.Disabled = rest[0] == "yes"
				ok = true
			}
		case "log-start", "log-end":
			if len(rest) == 1 && (rest[0] == "yes" || rest[0] == "no") {
				status := fm.Irrelevant
				if rest[0] == "yes" {
					status = fm.Known
				}
				if field == "log-start" {
					r.LogStart = status
				} else {
					r.LogEnd = status
				}
				r.Log = fm.Unknown
				if r.LogStart == fm.Known || r.LogEnd == fm.Known {
					r.Log = fm.Known
				} else if r.LogStart == fm.Irrelevant && r.LogEnd == fm.Irrelevant {
					r.Log = fm.Irrelevant
				}
				ok = true
			}
		case "description":
			r.Description = strings.Join(rest, " ")
			ok = true
		case "tag", "group-tag":
			ok = true
		}
		if ok {
			tx.Parse(row.source.Lines()...)
		} else {
			r.Match.Unsupported = append(r.Match.Unsupported, "unsupported PAN security field "+field)
		}
		rules[name] = r
	}
	for _, name := range order {
		r := rules[name]
		if r.Builtin {
			continue
		}
		r.Position = len(d.Rules)
		ensureSelectors(&r.Match)
		d.Rules = append(d.Rules, r)
	}
	for _, name := range []string{"intrazone-default", "interzone-default"} {
		r, exists := rules["$default:"+name]
		if !exists {
			r = defaultRule(name)
		}
		r.Position = len(d.Rules)
		d.Rules = append(d.Rules, r)
	}
	tx.Emit(d)
	if err := s.Commit(tx); err != nil {
		return err
	}
	p.data = s.Data()
	return nil
}
func (p *parser) ranges(name string, _ map[fm.ID]bool) ([]flow.Range, bool) {
	if r, err := address(name); err == nil {
		return []flow.Range{r}, true
	}
	kind := fm.AddressObject
	if p.graph.AddressGroup(fm.ID(name)) != nil {
		kind = fm.AddressGroupObject
	}
	set, known := policy.Addresses(p.graph, []fm.AddressRef{{Kind: kind, ID: fm.ID(name)}}, false)
	return set.Ranges(), known
}

type natDraft struct {
	object                              fm.Object
	match                               fm.Match
	order                               fm.NATOrder
	sourceMode, destinationMode         fm.TranslationMode
	sourceTarget, destinationTarget     []string
	iface                               fm.ID
	destinationPort                     string
	disabled, bidirectional             bool
	originalSource, originalDestination []string
	hasSource                           bool
}

func (p *parser) nat(_ context.Context, s *config.Session) error {
	var err error
	p.graph, err = fm.Seal(p.data)
	if err != nil {
		return err
	}
	tx := s.Cursor.Begin()
	drafts := make(map[string]natDraft)
	var order []string
	d := fm.Data{}
	for _, row := range p.rows {
		w := row.words
		if len(w) < 6 || !slices.Equal(w[:3], []string{"rulebase", "nat", "rules"}) {
			continue
		}
		name, field, rest := w[3], w[4], values(w[5:])
		r, exists := drafts[name]
		if !exists {
			r = natDraft{object: object(name, row), order: fm.NATOrder{Stage: 1, Position: len(order)}, sourceMode: fm.NoTranslation, destinationMode: fm.NoTranslation}
			order = append(order, name)
		}
		ok := p.matchField(&r.match, field, rest, &d)
		switch field {
		case "source":
			r.originalSource = append(r.originalSource, rest...)
		case "destination":
			r.originalDestination = append(r.originalDestination, rest...)
		case "source-translation":
			r.hasSource = true
			ok = false
			if len(rest) >= 2 {
				switch rest[0] {
				case "static-ip":
					r.sourceMode = fm.StaticIP
					if rest[1] == "translated-address" && len(rest) > 2 {
						r.sourceTarget = rest[2:]
						ok = true
					} else if rest[1] == "bi-directional" && len(rest) == 3 && (rest[2] == "yes" || rest[2] == "no") {
						r.bidirectional = rest[2] == "yes"
						ok = true
					}
				case "dynamic-ip", "dynamic-ip-and-port":
					r.sourceMode = fm.DynamicIP
					if rest[0] == "dynamic-ip-and-port" {
						r.sourceMode = fm.DynamicIPPort
					}
					if rest[1] == "translated-address" && len(rest) > 2 {
						r.sourceTarget = rest[2:]
						ok = true
					} else if len(rest) == 4 && rest[1] == "interface-address" {
						if rest[2] == "interface" {
							r.iface = fm.ID(rest[3])
							r.sourceMode = fm.InterfaceIP
							ok = true
						} else if rest[2] == "ip" {
							r.sourceTarget = []string{rest[3]}
							r.sourceMode = fm.InterfaceIP
							ok = true
						}
					}
				case "none":
					r.sourceMode = fm.NoTranslation
					ok = true
				}
			}
		case "destination-translation":
			if len(rest) == 2 {
				switch rest[0] {
				case "translated-address":
					r.destinationTarget = rest[1:]
					r.destinationMode = fm.StaticIP
					ok = true
				case "translated-port":
					r.destinationPort = rest[1]
					ok = true
				}
			}
		case "disabled":
			if len(rest) == 1 && (rest[0] == "yes" || rest[0] == "no") {
				r.disabled = rest[0] == "yes"
				ok = true
			}
		case "description", "tag", "group-tag":
			ok = true
		}
		if ok {
			tx.Parse(row.source.Lines()...)
		} else {
			r.object.Unsupported = append(r.object.Unsupported, "unsupported PAN NAT field "+field)
		}
		drafts[name] = r
	}
	for _, name := range order {
		r := drafts[name]
		ensureSelectors(&r.match)
		var srcTargets, dstTargets, srcOriginal, dstOriginal []flow.Range
		collect := func(names []string) ([]flow.Range, bool) {
			var result []flow.Range
			for _, name := range names {
				ranges, ok := p.ranges(name, make(map[fm.ID]bool))
				if !ok {
					return nil, false
				}
				result = append(result, ranges...)
			}
			return result, true
		}
		var known bool
		srcTargets, known = collect(r.sourceTarget)
		if !known {
			r.object.Unsupported = append(r.object.Unsupported, "unresolved NAT source target")
		}
		dstTargets, known = collect(r.destinationTarget)
		if !known {
			r.object.Unsupported = append(r.object.Unsupported, "unresolved NAT destination target")
		}
		var destinations []fm.Mapping
		if r.destinationMode == fm.StaticIP {
			dstOriginal, known = collect(r.originalDestination)
			if known && len(dstTargets) == 1 && dstTargets[0].First == dstTargets[0].Last {
				for _, origin := range dstOriginal {
					destinations = append(destinations, fm.Mapping{Original: origin, Translated: dstTargets[0], Mode: fm.Constant})
				}
			} else {
				r.destinationMode = fm.UnknownTranslation
			}
		}
		var portMappings []fm.PortMapping
		if r.destinationPort != "" {
			target, err := ports(r.destinationPort)
			if err != nil || len(target) != 1 || target[0].Low != target[0].High {
				r.object.Unsupported = append(r.object.Unsupported, "unknown destination port relation")
			} else {
				for _, ref := range r.match.Services {
					var terms []fm.ServiceTerm
					for _, service := range p.data.Services {
						if service.ID == ref.ID {
							terms = service.Terms
						}
					}
					if len(terms) == 0 {
						r.object.Unsupported = append(r.object.Unsupported, "unresolved NAT original service")
					}
					for _, term := range terms {
						portMappings = append(portMappings, fm.PortMapping{Original: term.DestinationPort, Translated: target[0], Mode: fm.Constant})
					}
				}
			}
		}
		if r.sourceMode == fm.StaticIP {
			srcOriginal, known = collect(r.originalSource)
			var sources []fm.Mapping
			if known && len(srcOriginal) == 1 && len(srcTargets) == 1 {
				sources = []fm.Mapping{{Original: srcOriginal[0], Translated: srcTargets[0], Mode: fm.Offset}}
			} else {
				r.object.Unsupported = append(r.object.Unsupported, "unknown static NAT source relation")
			}
			d.StaticNATs = append(d.StaticNATs, fm.StaticNATRecord{Object: r.object, Match: r.match, Order: r.order, Source: sources, Destination: destinations, DestinationPorts: portMappings, Bidirectional: r.bidirectional, Disabled: r.disabled})
		} else {
			dynamic := fm.DynamicNATRecord{Object: r.object, Match: r.match, Order: r.order, SourceMode: r.sourceMode, DestinationMode: r.destinationMode, Interface: r.iface, Destination: destinations, DestinationPorts: portMappings, Disabled: r.disabled}
			if len(srcTargets) > 0 {
				poolID := fm.ID("$nat:" + name)
				d.NATPools = append(d.NATPools, fm.NATPoolRecord{Object: fm.Object{ID: poolID}, Ranges: srcTargets})
				dynamic.SourcePool = poolID
			}
			d.DynamicNATs = append(d.DynamicNATs, dynamic)
		}
	}
	tx.Emit(d)
	return s.Commit(tx)
}

// defaultRule represents the native terminal layer; it cannot be an append candidate.
func defaultRule(name string) fm.RuleRecord {
	r := fm.RuleRecord{Object: fm.Object{ID: fm.ID("$default:" + name), Name: name}, RuleSet: "security", Builtin: true,
		Match: fm.Match{AnySource: true, AnyDestination: true, AnyService: true, AnyFromZone: true, AnyToZone: true}}
	if name == "intrazone-default" {
		r.Action = fm.Permit
		r.Match.ZoneRelation = fm.SameZone
	} else {
		r.Action = fm.Deny
		r.Match.ZoneRelation = fm.DifferentZones
	}
	return r
}
