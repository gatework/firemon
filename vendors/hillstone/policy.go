package hillstone

import (
	"context"
	"slices"
	"strings"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
)

func (p *parser) rules(_ context.Context, s *config.Builder) error {
	position := 0
	records := make(map[fm.ID]fm.RuleRecord)
	d := fm.Data{}
	var order []fm.ID
	tx := s.Begin()
	for _, n := range p.doc.nodes {
		if n.block.Kind != "rule" || !ruleHeader(n.block.Header.Words) {
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
		if len(n.block.Children) > 0 {
			r.Match.Unsupported = append(r.Match.Unsupported, "nested rule condition")
		}
		tx.Parse(n.block.Header.Lines()...)
		if n.block.Complete {
			tx.Parse(n.block.End.Lines()...)
		}
		if !exists {
			if strings.EqualFold(n.from, "any") {
				r.Match.AnyFromZone = true
			} else if n.from != "" {
				r.Match.FromZones = []fm.ID{fm.ID(n.from)}
				if r.Scope == "" {
					r.Scope = p.topology.zoneVRF[fm.ID(n.from)]
				}
			}
			if strings.EqualFold(n.to, "any") {
				r.Match.AnyToZone = true
			} else if n.to != "" {
				r.Match.ToZones = []fm.ID{fm.ID(n.to)}
			}
		}
		for _, l := range n.block.Members {
			w := l.Words
			ok := ancillary(w) || p.selector(&r, w, &d)
			if len(w) == 2 {
				switch w[0] {
				case "action":
					actions := map[string]fm.Action{"permit": fm.Permit, "deny": fm.Deny, "reject": fm.Reject}
					r.Action = actions[w[1]]
					ok = r.Action != fm.UnknownAction
				case "name":
					r.Name, ok = w[1], true
				case "application":
					if !strings.EqualFold(w[1], "any") {
						r.Match.Applications = append(r.Match.Applications, w[1])
					}
					ok = true
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
	d.Rules = rules
	tx.Emit(d)
	return s.Commit(tx)
}
