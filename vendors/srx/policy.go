package srx

import (
	"context"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/policy"
)

func policyLimit() error { return policy.ErrBudget }

func (p *parser) policies(ctx context.Context, s *config.Session) error {
	tx := s.Cursor().Begin()
	defer tx.Rollback()
	var rules catalog[fm.RuleRecord]
	d := fm.Data{}
	defaultAction := fm.Deny
	hasDefault := false
	for _, row := range p.rows {
		if err := ctx.Err(); err != nil {
			return err
		}
		w := row.Words
		if begins(w, "set", "security", "policies", "default-policy") && len(w) == 5 {
			action := fm.UnknownAction
			switch w[4] {
			case "permit-all":
				action = fm.Permit
			case "deny-all":
				action = fm.Deny
			}
			if action.Valid() {
				if hasDefault && defaultAction != action {
					d.Diagnostics = append(d.Diagnostics, diagnostic("conflicting-default-policy", "conflicting native default actions"))
				}
				defaultAction, hasDefault = action, true
				tx.Parse(row.Lines()...)
			}
			continue
		}
		if len(w) < 9 || (w[0] != "set" && w[0] != "deactivate") || !begins(w[1:], "security", "policies", "from-zone") || w[5] != "to-zone" || w[7] != "policy" {
			continue
		}
		from, to, name := w[4], w[6], w[8]
		id := nativeID("policy", from, to, name)
		r := rules.get(string(id))
		if r.ID == "" {
			*r = fm.RuleRecord{Object: fm.Object{ID: id, Name: name}, Position: len(rules.names) - 1, RuleSet: "security", Match: fm.Match{FromZones: []fm.ID{fm.ID(from)}, ToZones: []fm.ID{fm.ID(to)}}, Log: fm.Irrelevant, LogStart: fm.Irrelevant, LogEnd: fm.Irrelevant}
		}
		rest := w[9:]
		valid := false
		if w[0] == "deactivate" {
			if len(rest) == 0 {
				r.Disabled = true
				valid = true
			}
		} else {
			switch {
			case len(rest) >= 3 && rest[0] == "match":
				if values, ok := list(rest[2:]); ok {
					switch rest[1] {
					case "source-address", "destination-address":
						for _, value := range values {
							if rest[1] == "source-address" {
								if value == "any" && p.lookupAddress(from, value).ID == "" {
									r.Match.AnySource = true
								} else {
									r.Match.Sources = unique(r.Match.Sources, p.addressRef(from, value, &d))
								}
							} else {
								if value == "any" && p.lookupAddress(to, value).ID == "" {
									r.Match.AnyDestination = true
								} else {
									r.Match.Destinations = unique(r.Match.Destinations, p.addressRef(to, value, &d))
								}
							}
						}
						valid = true
					case "application":
						for _, value := range values {
							if value == "any" {
								r.Match.AnyService = true
							} else {
								r.Match.Services = unique(r.Match.Services, p.serviceRef(value))
							}
						}
						valid = true
					}
				}
			case len(rest) == 2 && rest[0] == "then":
				action := fm.UnknownAction
				switch rest[1] {
				case "permit":
					action = fm.Permit
				case "deny":
					action = fm.Deny
				case "reject":
					action = fm.Reject
				}
				if action.Valid() {
					if r.Action.Valid() && r.Action != action {
						r.Unsupported = append(r.Unsupported, "conflicting policy actions")
					}
					r.Action = action
					valid = true
				}
			case len(rest) == 3 && rest[0] == "then" && rest[1] == "log":
				if rest[2] == "session-init" {
					r.LogStart = fm.Known
					valid = true
				}
				if rest[2] == "session-close" {
					r.LogEnd = fm.Known
					valid = true
				}
				if valid {
					r.Log = fm.Known
				}
			case len(rest) == 2 && rest[0] == "description":
				r.Description = rest[1]
				valid = true
			}
		}
		if valid {
			touch(&r.Object, row)
			tx.Parse(row.Lines()...)
		} else {
			r.Unsupported = append(r.Unsupported, "unsupported native policy condition")
		}
	}
	for _, name := range rules.names {
		r := rules.entries[name]
		if !r.Match.AnySource && len(r.Match.Sources) == 0 {
			r.Match.Sources = []fm.AddressRef{{Kind: fm.UnknownObject, ID: "$missing-source"}}
		}
		if !r.Match.AnyDestination && len(r.Match.Destinations) == 0 {
			r.Match.Destinations = []fm.AddressRef{{Kind: fm.UnknownObject, ID: "$missing-destination"}}
		}
		if !r.Match.AnyService && len(r.Match.Services) == 0 {
			r.Match.Services = []fm.ServiceRef{{Kind: fm.UnknownObject, ID: "$missing-application"}}
		}
		d.Rules = append(d.Rules, *r)
	}
	d.Rules = append(d.Rules, fm.RuleRecord{Object: fm.Object{ID: "$default", Name: "default-policy"}, Builtin: true, Position: len(d.Rules), RuleSet: "security", Action: defaultAction, Match: fm.Match{AnySource: true, AnyDestination: true, AnyService: true, AnyFromZone: true, AnyToZone: true}, Log: fm.Irrelevant, LogStart: fm.Irrelevant, LogEnd: fm.Irrelevant})
	tx.Emit(d)
	if err := s.Commit(tx); err != nil {
		return err
	}
	p.data = s.Data()
	return nil
}
