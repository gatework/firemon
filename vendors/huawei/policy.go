package huawei

import (
	"context"
	"fmt"
	"slices"
	"strings"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
)

func anyMatch() fm.Match {
	return fm.Match{AnySource: true, AnyDestination: true, AnyService: true, AnyFromZone: true, AnyToZone: true}
}

type policyBlock struct {
	name             string
	headers, members []config.Statement
}

func (p *parser) ruleBlocks(kind string) ([]policyBlock, []config.Statement, error) {
	var rules []policyBlock
	var root []config.Statement
	index := make(map[string]int)
	for _, b := range p.blocks {
		if b.Kind != kind {
			continue
		}
		if len(b.Header.Words) != 1 {
			return nil, nil, fmt.Errorf("%w: unsupported %s header", config.ErrSource, kind)
		}
		root = append(root, b.Header)
		current := -1
		for _, row := range b.Members {
			if len(row.Words) == 0 {
				continue
			}
			if indent(row) == 1 && has(row.Words, "rule", "name") {
				if len(row.Words) != 3 || row.Words[2] == "" || strings.HasPrefix(row.Words[2], "$") {
					return nil, nil, fmt.Errorf("%w: rule name at line %d", config.ErrSource, row.Span.First)
				}
				name := row.Words[2]
				var ok bool
				current, ok = index[name]
				if !ok {
					current = len(rules)
					index[name] = current
					rules = append(rules, policyBlock{name: name})
				}
				rules[current].headers = append(rules[current].headers, row)
			} else if indent(row) >= 2 && current >= 0 {
				rules[current].members = append(rules[current].members, row)
			} else {
				root = append(root, row)
				current = -1
			}
		}
	}
	return rules, root, nil
}
func (p *parser) matchLine(d *fm.Data, m *fm.Match, w []string, seen map[string]bool) bool {
	if len(w) < 2 {
		return false
	}
	var refs *[]fm.AddressRef
	var any *bool
	switch w[0] {
	case "source-zone", "destination-zone":
		zones, flag := &m.FromZones, &m.AnyFromZone
		if w[0] == "destination-zone" {
			zones, flag = &m.ToZones, &m.AnyToZone
		}
		if !seen[w[0]] {
			*flag = false
			seen[w[0]] = true
		}
		for _, name := range w[1:] {
			if name == "any" {
				*flag = true
			} else {
				*zones = append(*zones, fm.ID(strings.ToLower(name)))
			}
		}
		return true
	case "source-address":
		refs, any = &m.Sources, &m.AnySource
	case "destination-address":
		refs, any = &m.Destinations, &m.AnyDestination
	case "service":
		if !seen[w[0]] {
			m.AnyService = false
			seen[w[0]] = true
		}
		if len(w) == 2 && w[1] == "any" {
			m.AnyService = true
			return true
		}
		if w[1] == "protocol" {
			terms, ok := serviceTerms(w[2:])
			if !ok {
				return false
			}
			m.Services = append(m.Services, p.literalService(d, terms))
			return true
		}
		for _, name := range w[1:] {
			m.Services = append(m.Services, p.serviceRef(name))
		}
		return true
	case "time-range":
		if len(w) == 2 {
			m.Schedule = fm.ID(w[1])
			return true
		}
		return false
	default:
		return false
	}
	if !seen[w[0]] {
		*any = false
		seen[w[0]] = true
	}
	if len(w) == 2 && w[1] == "any" {
		*any = true
		return true
	}
	if len(w) == 3 && w[1] == "address-set" {
		*refs = append(*refs, p.addressRef(w[2]))
		return true
	}
	r, ok := addressRange(w[1:])
	if !ok {
		return false
	}
	*refs = append(*refs, p.literalAddress(d, r))
	return true
}
func (p *parser) policies(ctx context.Context, s *config.Session) error {
	tx := s.Cursor.Begin()
	defer tx.Rollback()
	var d fm.Data
	blocks, root, err := p.ruleBlocks("security-policy")
	if err != nil {
		return err
	}
	defaultAction := fm.Action(0)
	for _, row := range root {
		w := row.Words
		if len(w) == 1 && w[0] == "security-policy" {
			tx.Parse(row.Lines()...)
		}
		if len(w) == 3 && has(w, "default", "action") {
			switch w[2] {
			case "permit":
				defaultAction = fm.Permit
			case "deny":
				defaultAction = fm.Deny
			default:
				continue
			}
			tx.Parse(row.Lines()...)
		}
	}
	for position, b := range blocks {
		r := fm.RuleRecord{Object: object(b.name), Match: anyMatch(), Position: position, RuleSet: "security", Log: fm.Irrelevant, LogStart: fm.Irrelevant, LogEnd: fm.Irrelevant}
		seen := make(map[string]bool)
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
				case len(w) == 2 && w[0] == "action":
					switch w[1] {
					case "permit":
						r.Action = fm.Permit
						ok = true
					case "deny":
						r.Action = fm.Deny
						ok = true
					}
				case len(w) == 1 && w[0] == "disable":
					r.Disabled = true
					ok = true
				case slices.Equal(w, []string{"undo", "disable"}):
					r.Disabled = false
					ok = true
				case w[0] == "description" && len(w) > 1:
					r.Description = strings.Join(w[1:], " ")
					ok = true
				case slices.Equal(w, []string{"policy", "logging"}):
					r.Log, r.LogEnd = fm.Known, fm.Known
					ok = true
				case slices.Equal(w, []string{"undo", "policy", "logging"}):
					r.Log, r.LogEnd = fm.Irrelevant, fm.Irrelevant
					ok = true
				default:
					ok = p.matchLine(&d, &r.Match, w, seen)
				}
			}
			claim(tx, &r.Object, row, ok)
		}
		d.Rules = append(d.Rules, r)
	}
	if defaultAction.Valid() {
		d.Rules = append(d.Rules, fm.RuleRecord{Object: object("$default"), Match: anyMatch(), Action: defaultAction, Position: len(blocks), RuleSet: "security", Builtin: true, Log: fm.Irrelevant, LogStart: fm.Irrelevant, LogEnd: fm.Irrelevant})
	}
	return p.commit(s, tx, d)
}
