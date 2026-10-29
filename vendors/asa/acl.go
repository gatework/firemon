package asa

import (
	"context"
	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/policy"
	"slices"
)

func (p *parser) operand(words []string, d *fm.Data) (fm.AddressRef, int, bool) {
	if len(words) == 0 {
		return fm.AddressRef{}, 0, false
	}
	var r flow.Range
	var err error
	consumed := 0
	switch words[0] {
	case "object", "object-group":
		if len(words) < 2 {
			return fm.AddressRef{}, 0, false
		}
		kind := fm.AddressObject
		if words[0] == "object-group" {
			kind = fm.AddressGroupObject
		}
		return fm.AddressRef{Kind: kind, ID: fm.ID(words[1])}, 2, true
	case "any", "any4":
		r, err = iprange("0.0.0.0/0")
		consumed = 1
	case "any6":
		r, err = iprange("::/0")
		consumed = 1
	case "host":
		if len(words) < 2 {
			return fm.AddressRef{}, 0, false
		}
		r, err = iprange(words[1])
		consumed = 2
	default:
		if len(words) < 2 {
			return fm.AddressRef{}, 0, false
		}
		v, e := prefix(words[0], words[1])
		if e != nil {
			return fm.AddressRef{}, 0, false
		}
		r, err = flow.PrefixRange(v)
		consumed = 2
	}
	if err != nil {
		return fm.AddressRef{}, 0, false
	}
	id := fm.ID("$literal:" + r.First.String() + "-" + r.Last.String())
	if p.literalIDs == nil || p.literalDraft != d || len(d.Addresses) < p.literalDraftCount || len(p.data.Addresses) != p.literalCommitted {
		p.literalIDs = make(map[fm.ID]bool, len(p.data.Addresses)+len(d.Addresses))
		for _, a := range p.data.Addresses {
			p.literalIDs[a.ID] = true
		}
		p.literalCommitted = len(p.data.Addresses)
		p.literalDraft = d
		p.literalDraftCount = 0
	}
	for _, a := range d.Addresses[p.literalDraftCount:] {
		p.literalIDs[a.ID] = true
	}
	p.literalDraftCount = len(d.Addresses)
	if !p.literalIDs[id] {
		d.Addresses = append(d.Addresses, fm.AddressRecord{Object: fm.Object{ID: id}, Ranges: []flow.Range{r}})
		p.literalIDs[id] = true
		p.literalDraftCount = len(d.Addresses)
	}
	return fm.AddressRef{Kind: fm.AddressObject, ID: id}, consumed, true
}
func (p *parser) serviceTerms(ctx context.Context, id fm.ID, group bool) ([]fm.ServiceTerm, bool, error) {
	kind := fm.ServiceObject
	if group {
		kind = fm.ServiceGroupObject
	}
	return (policy.Engine{}).ResolveServices(ctx, p.graph, []fm.ServiceRef{{Kind: kind, ID: id}}, false)
}
func (p *parser) acls(ctx context.Context, s *config.Session) error {
	var err error
	p.graph, err = fm.Seal(p.data)
	if err != nil {
		return err
	}
	tx := s.Cursor.Begin()
	d := fm.Data{}
	position := 0
	identities := make(map[fm.ID]bool)
	full := flow.Interval{Low: 0, High: 65535}
	for _, line := range p.lines {
		if err := ctx.Err(); err != nil {
			return err
		}
		w := line.Words
		if len(w) < 3 || w[0] != "access-list" {
			continue
		}
		if w[2] == "remark" {
			tx.Ignore("ACL remark", line.Lines()...)
			continue
		}
		if len(w) < 7 || w[2] != "extended" {
			continue
		}
		id := declarationID("acl:", w)
		for identities[id] {
			id += "-duplicate"
		}
		identities[id] = true
		r := fm.RuleRecord{Object: fm.Object{ID: id, Name: w[1], Spans: []fm.Span{line.Span}}, RuleSet: w[1], Position: position, Log: fm.Irrelevant, LogStart: fm.Irrelevant, LogEnd: fm.Irrelevant}
		r.Action = map[string]fm.Action{"permit": fm.Permit, "deny": fm.Deny}[w[3]]
		if r.Action == fm.UnknownAction {
			continue
		}
		rest := w[4:]
		var baseTerms []fm.ServiceTerm
		var direct *fm.ServiceRef
		if (rest[0] == "object-group" || rest[0] == "object") && len(rest) > 1 {
			terms, ok, err := p.serviceTerms(ctx, fm.ID(rest[1]), rest[0] == "object-group")
			if err != nil {
				return err
			}
			if !ok {
				continue
			}
			baseTerms = terms
			ref := fm.ServiceRef{Kind: fm.ServiceObject, ID: fm.ID(rest[1])}
			if rest[0] == "object-group" {
				ref.Kind = fm.ServiceGroupObject
			}
			direct = &ref
			rest = rest[2:]
		} else {
			terms, ok := serviceDefinition(rest[:1])
			if !ok {
				continue
			}
			baseTerms = terms
			rest = rest[1:]
		}
		source, n, ok := p.operand(rest, &d)
		if !ok {
			continue
		}
		rest = rest[n:]
		srcPorts := []flow.Interval{full}
		if len(rest) > 0 && slices.Contains([]string{"eq", "range", "lt", "gt", "neq"}, rest[0]) {
			direct = nil
			srcPorts, n, ok = portSpec(rest)
			if !ok {
				continue
			}
			rest = rest[n:]
		}
		destination, n, ok := p.operand(rest, &d)
		if !ok {
			continue
		}
		rest = rest[n:]
		var constrained []fm.ServiceTerm
		if len(rest) > 1 && rest[0] == "object-group" {
			direct = nil
			constrained, ok, err = p.serviceTerms(ctx, fm.ID(rest[1]), true)
			if err != nil {
				return err
			}
			if !ok {
				continue
			}
			rest = rest[2:]
		} else if len(rest) > 0 && slices.Contains([]string{"eq", "range", "lt", "gt", "neq"}, rest[0]) {
			direct = nil
			ranges, n, valid := portSpec(rest)
			if !valid {
				continue
			}
			for _, interval := range ranges {
				v := term(0, full, interval)
				v.Protocol = flow.Interval{High: 255}
				constrained = append(constrained, v)
			}
			rest = rest[n:]
		}
		r.Match.Sources = []fm.AddressRef{source}
		r.Match.Destinations = []fm.AddressRef{destination}
		service := fm.ServiceRecord{}
		if len(constrained) == 0 {
			v := term(0, full, full)
			v.Protocol = flow.Interval{High: 255}
			constrained = []fm.ServiceTerm{v}
		}
		visits := 0
		for _, base := range baseTerms {
			for _, src := range srcPorts {
				for _, constraint := range constrained {
					visits++
					if visits > 4096 {
						return policy.ErrBudget
					}
					v, valid := intersectService(base, constraint)
					if !valid {
						continue
					}
					v.SourcePort = flow.Interval{Low: max(v.SourcePort.Low, src.Low), High: min(v.SourcePort.High, src.High)}
					if v.SourcePort.Low <= v.SourcePort.High {
						service.Terms = append(service.Terms, v)
					}
				}
			}
		}
		if direct != nil {
			r.Match.Services = []fm.ServiceRef{*direct}
		} else {
			serviceID := inlineService(&d, p.data, service.Terms)
			r.Match.Services = []fm.ServiceRef{{Kind: fm.ServiceObject, ID: serviceID}}
		}
		for i := 0; i < len(rest); i++ {
			switch rest[i] {
			case "log":
				r.Log = fm.Known
			case "inactive":
				r.Disabled = true
			case "time-range":
				if i+1 < len(rest) {
					i++
					r.Match.Schedule = fm.ID(rest[i])
				} else {
					r.Unsupported = append(r.Unsupported, "missing time range")
				}
			default:
				r.Unsupported = append(r.Unsupported, "unsupported ACL qualifier")
			}
		}
		in, out := false, false
		for _, binding := range p.data.RuleBindings {
			if binding.RuleSet != r.RuleSet {
				continue
			}
			if binding.Direction == "in" {
				r.Match.FromZones = append(r.Match.FromZones, binding.Zone)
				in = true
			} else if binding.Direction == "out" {
				r.Match.ToZones = append(r.Match.ToZones, binding.Zone)
				out = true
			}
		}
		if in && !out {
			r.Match.AnyToZone = true
		} else if out && !in {
			r.Match.AnyFromZone = true
		} else {
			r.Unsupported = append(r.Unsupported, "ACL binding direction is missing or ambiguous")
		}
		d.Rules = append(d.Rules, r)
		position++
		tx.Parse(line.Lines()...)
	}
	tx.Emit(d)
	if err := s.Commit(tx); err != nil {
		return err
	}
	p.data = s.Data()
	return nil
}
