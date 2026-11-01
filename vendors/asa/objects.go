package asa

import (
	"context"

	"slices"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/flow"
)

func (p *parser) objects(_ context.Context, s *config.Builder) error {
	tx := s.Begin()
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
					id := inlineService(&d, p.builder, terms)
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
	return nil
}
