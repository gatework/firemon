package report

import (
	"cmp"
	"slices"

	"github.com/gatework/firemon/inventory"
	"github.com/gatework/firemon/query"
)

// ZonePair summarizes what decides the request between two zones of one
// firewall: how many rules permit, deny or may decide it, and whether the
// default action denies part of it. A wide request reads from these rows
// before its details.
type ZonePair struct {
	From    string `json:"from"`
	To      string `json:"to"`
	Permits int    `json:"permits"`
	Denies  int    `json:"denies"`
	Unknown int    `json:"unknown"`
	Default bool   `json:"default,omitempty"`
	// Rules are the deciding rules in rule order, at most maxPairRules.
	Rules []string `json:"rules,omitempty"`
}

// maxPairRules bounds the rules a zone pair names.
const maxPairRules = 5

// zonePairs summarizes a crossing by zone pair, in path order.
func zonePairs(c inventory.Crossing) []ZonePair {
	type acc struct {
		pair  ZonePair
		rules map[string]int // id -> one-based position
		seen  map[string]query.Outcome
	}
	var out []*acc
	for _, p := range c.Paths {
		i := slices.IndexFunc(out, func(a *acc) bool { return a.pair.From == p.From && a.pair.To == p.To })
		if i < 0 {
			out = append(out, &acc{pair: ZonePair{From: p.From, To: p.To}, rules: map[string]int{}, seen: map[string]query.Outcome{}})
			i = len(out) - 1
		}
		a := out[i]
		for _, d := range p.Decisions {
			if d.Rule == nil {
				if d.Outcome == query.OutcomeUnknown {
					a.pair.Unknown++
				} else {
					a.pair.Default = true
				}
				continue
			}
			id := d.Rule.ID()
			if _, ok := a.seen[id]; ok {
				continue
			}
			a.seen[id], a.rules[id] = d.Outcome, d.Rule.Position()+1
			switch d.Outcome {
			case query.OutcomePermit:
				a.pair.Permits++
			case query.OutcomeDeny:
				a.pair.Denies++
			case query.OutcomeUnknown, query.OutcomeUnset, query.OutcomeDefault:
				a.pair.Unknown++
			}
		}
	}
	pairs := make([]ZonePair, len(out))
	for i, a := range out {
		ids := make([]string, 0, len(a.rules))
		for id := range a.rules {
			ids = append(ids, id)
		}
		slices.SortFunc(ids, func(x, y string) int { return cmp.Compare(a.rules[x], a.rules[y]) })
		if len(ids) > maxPairRules {
			ids = ids[:maxPairRules]
		}
		a.pair.Rules = ids
		pairs[i] = a.pair
	}
	return pairs
}
