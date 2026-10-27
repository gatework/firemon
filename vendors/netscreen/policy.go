package netscreen

import (
	"context"
	"slices"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
)

type policyNAT struct {
	source                  bool
	pool, destination, port string
}

func (p *parser) policies(ctx context.Context, s *config.Session) error {
	tx := s.Cursor.Begin()
	defer tx.Rollback()
	d := fm.Data{}
	for _, row := range p.rows {
		if err := ctx.Err(); err != nil {
			return err
		}
		if row.scope != "policy" {
			continue
		}
		w := row.Words
		id, ok := policyID(row.owner)
		if !ok {
			continue
		}
		r := p.rules.entries[string(id)]
		valid := false
		if begins(w, "set", "policy", "id") {
			rest := w[4:]
			name := ""
			top := false
			if len(rest) >= 2 && rest[0] == "name" {
				name = rest[1]
				rest = rest[2:]
			}
			if len(rest) > 0 && rest[0] == "top" {
				top = true
				rest = rest[1:]
			}
			if len(rest) >= 8 && rest[0] == "from" && rest[2] == "to" {
				if r != nil {
					d.Diagnostics = append(d.Diagnostics, invalid("", "duplicate native policy ID"))
					continue
				}
				r = p.rules.get(string(id))
				*r = fm.RuleRecord{Object: object(id, name, ""), RuleSet: "security", Log: fm.Irrelevant, LogStart: fm.Irrelevant, LogEnd: fm.Irrelevant, Match: fm.Match{FromZones: []fm.ID{fm.ID(rest[1])}, ToZones: []fm.ID{fm.ID(rest[3])}}}
				if top {
					p.rules.names = append([]string{string(id)}, p.rules.names[:len(p.rules.names)-1]...)
				}
				p.addAddress(r, true, rest[4], &d)
				p.addAddress(r, false, rest[5], &d)
				p.addService(r, rest[6])
				valid = p.policyTail(r, rest[7:])
				if globalZone(r.Match.FromZones) || globalZone(r.Match.ToZones) {
					r.Unsupported = append(r.Unsupported, "Global policy precedence is not modeled")
					valid = false
				}
			} else if r != nil {
				if len(rest) == 0 {
					valid = true
				}
				if len(rest) == 1 && rest[0] == "disable" {
					r.Disabled = true
					valid = true
				}
			}
		} else if r != nil {
			switch {
			case slices.Equal(w, []string{"exit"}):
				valid = true
			case len(w) == 3 && begins(w, "set", "src-address"):
				p.addAddress(r, true, w[2], &d)
				valid = true
			case len(w) == 3 && begins(w, "set", "dst-address"):
				p.addAddress(r, false, w[2], &d)
				valid = true
			case len(w) == 3 && begins(w, "set", "service"):
				p.addService(r, w[2])
				valid = true
			case slices.Equal(w, []string{"set", "log", "session-init"}):
				r.Log, r.LogStart = fm.Known, fm.Known
				valid = true
			case begins(w, "set", "nat"):
				var n policyNAT
				n, valid = natFields(w[1:])
				if valid {
					p.policyNAT[r.ID] = n
				}
			}
		}
		if valid {
			touch(&r.Object, row)
			tx.Parse(row.Lines()...)
		} else if r != nil {
			r.Unsupported = append(r.Unsupported, "unsupported native policy condition")
		}
	}
	for pos, name := range p.rules.names {
		r := p.rules.entries[name]
		r.Position = pos
		d.Rules = append(d.Rules, *r)
	}
	for _, z := range p.data.Zones {
		if p.intraBlocked[z.ID] {
			continue
		}
		d.Rules = append(d.Rules, fm.RuleRecord{Object: object(nativeID("$intrazone", string(z.ID)), "intrazone-bypass", ""), Position: -1, RuleSet: "security", Action: fm.Permit, Builtin: true, Log: fm.Irrelevant, LogStart: fm.Irrelevant, LogEnd: fm.Irrelevant, Match: fm.Match{Sources: []fm.AddressRef{{Kind: fm.AddressObject, ID: "$any-ipv4"}}, Destinations: []fm.AddressRef{{Kind: fm.AddressObject, ID: "$any-ipv4"}}, AnyService: true, FromZones: []fm.ID{z.ID}, ToZones: []fm.ID{z.ID}}})
	}
	d.Rules = append(d.Rules, fm.RuleRecord{Object: object("$default", "default-policy", ""), Position: len(d.Rules), RuleSet: "security", Action: fm.Deny, Builtin: true, Log: fm.Irrelevant, LogStart: fm.Irrelevant, LogEnd: fm.Irrelevant, Match: fm.Match{AnySource: true, AnyDestination: true, AnyService: true, AnyFromZone: true, AnyToZone: true}})
	return p.commit(s, tx, d)
}
func (p *parser) policyTail(r *fm.RuleRecord, rest []string) bool {
	if len(rest) == 0 {
		return false
	}
	if rest[0] == "nat" {
		index := slices.IndexFunc(rest, func(s string) bool { return s == "permit" || s == "deny" || s == "reject" })
		if index < 0 {
			return false
		}
		n, ok := natFields(rest[:index])
		if !ok {
			return false
		}
		p.policyNAT[r.ID] = n
		rest = rest[index:]
	}
	switch rest[0] {
	case "permit":
		r.Action = fm.Permit
	case "deny":
		r.Action = fm.Deny
	case "reject":
		r.Action = fm.Reject
	default:
		return false
	}
	for i := 1; i < len(rest); i++ {
		switch rest[i] {
		case "log":
			r.Log, r.LogEnd = fm.Known, fm.Known
		case "schedule":
			if i+1 == len(rest) {
				return false
			}
			i++
			r.Match.Schedule = fm.ID(rest[i])
		default:
			return false
		}
	}
	return true
}
