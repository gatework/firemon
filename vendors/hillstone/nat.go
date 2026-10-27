package hillstone

import (
	"context"
	"fmt"
	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/policy"
	"slices"
)

func (p *parser) resolve(name string, _ map[fm.ID]bool) ([]flow.Range, bool) {
	if r, err := literal(name); err == nil {
		return []flow.Range{r}, true
	}
	set, known := policy.Addresses(p.graph, []fm.AddressRef{p.addressRef(name)}, false)
	return set.Ranges(), known
}
func (p *parser) natAddress(name string, d *fm.Data) (fm.AddressRef, bool) {
	if _, ok := p.addressKinds[fm.ID(name)]; ok {
		return p.addressRef(name), true
	}
	r, err := literal(name)
	if err != nil {
		return p.addressRef(name), false
	}
	id := fm.ID("$literal:" + name)
	if _, exists := p.addressKinds[id]; !exists {
		d.Addresses = append(d.Addresses, fm.AddressRecord{Object: fm.Object{ID: id, Name: name}, Ranges: []flow.Range{r}})
		p.addressKinds[id] = fm.AddressObject
	}
	return fm.AddressRef{Kind: fm.AddressObject, ID: id}, true
}
func (p *parser) nat(_ context.Context, s *config.Session) error {
	p.data = s.Data()
	var err error
	p.graph, err = fm.Seal(p.data)
	if err != nil {
		return err
	}
	for _, row := range p.lines {
		w := row.line.Words
		if len(w) < 3 || !slices.Contains([]string{"bnatrule", "snatrule", "dnatrule"}, w[0]) || w[1] != "id" {
			continue
		}
		section := map[string]string{"bnatrule": "bnat", "snatrule": "snat", "dnatrule": "dnat"}[w[0]]
		nativeID := section + ":" + w[2]
		if row.scope != "" {
			nativeID = row.scope + "/" + nativeID
		}
		o := fm.Object{ID: fm.ID(nativeID), Name: w[2], Scope: row.scope, Spans: []fm.Span{row.line.Span}}
		order := fm.NATOrder{Stage: map[string]int{"bnat": 0, "dnat": 1, "snat": 2}[section], Section: section, Position: row.line.Span.First}
		d := fm.Data{}
		if w[0] == "bnatrule" {
			if len(w) < 9 || w[3] != "virtual" || w[6] != "real" || !slices.Contains([]string{"ip", "address-book"}, w[4]) || !slices.Contains([]string{"ip", "address-book"}, w[7]) {
				continue
			}
			valid := true
			for _, flag := range w[9:] {
				if flag != "log" && flag != "disable" {
					valid = false
				}
			}
			if !valid {
				continue
			}
			mapped, ok := p.resolve(w[5], make(map[fm.ID]bool))
			real, ok2 := p.resolve(w[8], make(map[fm.ID]bool))
			if !ok || !ok2 || len(mapped) != 1 || len(real) != 1 {
				continue
			}
			ref, _ := p.natAddress(w[8], &d)
			r := fm.StaticNATRecord{Object: o, Order: order, Source: []fm.Mapping{{Original: real[0], Translated: mapped[0], Mode: fm.Offset}}, Bidirectional: true, Disabled: slices.Contains(w[9:], "disable"), Match: fm.Match{Sources: []fm.AddressRef{ref}, AnyDestination: true, AnyService: true, AnyFromZone: true, AnyToZone: true}}
			d.StaticNATs = append(d.StaticNATs, r)
		} else {
			fields, ok := natFields(w[3:])
			if !ok {
				continue
			}
			match := fm.Match{AnyFromZone: true, AnyToZone: true}
			if fields["from"] == "any" {
				match.AnySource = true
			} else {
				ref, _ := p.natAddress(fields["from"], &d)
				match.Sources = []fm.AddressRef{ref}
			}
			if fields["to"] == "any" {
				match.AnyDestination = true
			} else {
				ref, _ := p.natAddress(fields["to"], &d)
				match.Destinations = []fm.AddressRef{ref}
			}
			if fields["service"] == "any" {
				match.AnyService = true
			} else if fields["service"] != "" {
				match.Services = []fm.ServiceRef{p.serviceRef(fields["service"])}
			} else {
				match.Unsupported = append(match.Unsupported, "NAT service default not established")
			}
			r := fm.DynamicNATRecord{Object: o, Order: order, Match: match, Interface: fm.ID(fields["eif"]), SourceMode: fm.NoTranslation, DestinationMode: fm.NoTranslation, Disabled: fields["disable"] == "true"}
			target := fields["trans-to"]
			ranges, known := p.resolve(target, make(map[fm.ID]bool))
			if w[0] == "snatrule" {
				r.SourceMode = fm.UnknownTranslation
				if fields["mode"] == "dynamicip" {
					r.SourceMode = fm.DynamicIP
				}
				if fields["mode"] == "dynamicport" {
					r.SourceMode = fm.DynamicIPPort
				}
				if target == "eif-ip" {
					r.SourceMode = fm.InterfaceIP
				} else if known {
					poolID := fm.ID("$snat:" + string(o.ID))
					r.SourcePool = poolID
					d.NATPools = append(d.NATPools, fm.NATPoolRecord{Object: fm.Object{ID: poolID, Scope: o.Scope}, Ranges: ranges})
				}
			} else {
				r.DestinationMode = fm.UnknownTranslation
				original, originalKnown := p.resolve(fields["to"], make(map[fm.ID]bool))
				if known && originalKnown && len(ranges) == 1 && ranges[0].First == ranges[0].Last {
					r.DestinationMode = fm.StaticIP
					for _, from := range original {
						r.Destination = append(r.Destination, fm.Mapping{Original: from, Translated: ranges[0], Mode: fm.Constant})
					}
				}
			}
			if fields["port"] != "" {
				target, valid := port([]string{fields["port"]})
				terms, known := p.serviceTerms(fields["service"], make(map[fm.ID]bool))
				if valid && known && len(terms) > 0 {
					for _, term := range terms {
						if term.Protocol.Low != term.Protocol.High || (term.Protocol.Low != 6 && term.Protocol.Low != 17) {
							r.Unsupported = append(r.Unsupported, "port translation requires TCP/UDP service")
							continue
						}
						mapping := fm.PortMapping{Original: term.DestinationPort, Translated: target, Mode: fm.Constant}
						if w[0] == "dnatrule" {
							r.DestinationPorts = append(r.DestinationPorts, mapping)
						} else {
							mapping.Original = term.SourcePort
							r.SourcePorts = append(r.SourcePorts, mapping)
						}
					}
				} else {
					r.Unsupported = append(r.Unsupported, "NAT port relation requires original service partition")
				}
			}
			if fields["sticky"] != "" {
				r.Unsupported = append(r.Unsupported, "sticky allocation semantics")
			}
			if w[0] == "snatrule" && fields["mode"] == "static" {
				fixed := fm.StaticNATRecord{Object: r.Object, Match: r.Match, Order: r.Order, Interface: r.Interface, Disabled: r.Disabled, SourcePorts: r.SourcePorts}
				originals, sourceKnown := p.resolve(fields["from"], nil)
				if known && sourceKnown && len(ranges) == 1 && len(originals) == 1 {
					fixed.Source = []fm.Mapping{{Original: originals[0], Translated: ranges[0], Mode: fm.Offset}}
				} else {
					fixed.Unsupported = append(fixed.Unsupported, "static source relation requires ordered fixed address ranges")
				}
				d.NATPools = nil
				d.StaticNATs = append(d.StaticNATs, fixed)
			} else {
				d.DynamicNATs = append(d.DynamicNATs, r)
			}
		}
		tx := s.Cursor.Begin()
		tx.Parse(row.line.Lines()...)
		tx.Emit(d)
		if err := s.Commit(tx); err != nil {
			return fmt.Errorf("NAT line %d: %w", row.line.Span.First, err)
		}
	}
	return nil
}
func natFields(words []string) (map[string]string, bool) {
	fields := make(map[string]string)
	for i := 0; i < len(words); {
		key := words[i]
		if _, ok := fields[key]; ok {
			return nil, false
		}
		i++
		switch key {
		case "from", "to", "trans-to":
			if i < len(words) && (words[i] == "ip" || words[i] == "address-book" || words[i] == "addressbook") {
				i++
			}
			if i >= len(words) {
				return nil, false
			}
			fields[key] = words[i]
			i++
		case "service", "eif", "mode", "port":
			if i >= len(words) {
				return nil, false
			}
			fields[key] = words[i]
			i++
			if key == "mode" && !slices.Contains([]string{"static", "dynamicip", "dynamicport"}, fields[key]) {
				return nil, false
			}
		case "log", "disable", "sticky":
			fields[key] = "true"
		default:
			return nil, false
		}
	}
	return fields, fields["from"] != "" && fields["to"] != "" && fields["trans-to"] != ""
}

func (p *parser) serviceTerms(name string, _ map[fm.ID]bool) ([]fm.ServiceTerm, bool) {
	return policy.Services(p.graph, []fm.ServiceRef{p.serviceRef(name)}, false)
}
