package design

import (
	"fmt"
	"slices"
	"time"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/traffic"
)

// maxTrials bounds the rule extensions verified per zone pair (ALG-2).
const maxTrials = 8

// open returns the cheapest verified changes that permit n.
func (p *Planner) open(n need, intent Intent, cat *catalog, at time.Time, plan *Plan) ([]Change, error) {
	if n.from == "" || n.to == "" {
		return nil, fmt.Errorf("design: zones of %s are unknown; set the from and to zones", n.region)
	}
	target := n.region.Bounds()
	if changes, err := p.tryExtensions(n, intent, cat, at, plan); err != nil || len(changes) > 0 {
		return changes, err
	}
	mark := cat.mark()
	rule := p.newRule(n, target, intent, cat)
	changes := []Change{rule}
	if p.verify(append(slices.Clone(cat.created), changes...), intent, []need{n}, at) == nil {
		return changes, nil
	}
	cat.rollback(mark)
	// The bounding box would reopen conflicting packets: one rule per space.
	changes = nil
	for _, s := range n.region.Spaces() {
		changes = append(changes, p.newRule(n, s, intent, cat))
	}
	if err := p.verify(append(slices.Clone(cat.created), changes...), intent, []need{n}, at); err != nil {
		cat.rollback(mark)
		return nil, fmt.Errorf("%w for %s -> %s: %w", ErrUnverifiable, n.from, n.to, err)
	}
	return changes, nil
}

// tryExtensions stops at the first proof in cost order. If the trial budget
// cuts off the search, another existing rule may still be the best choice.
func (p *Planner) tryExtensions(n need, intent Intent, cat *catalog, at time.Time, plan *Plan) ([]Change, error) {
	target := n.region.Bounds()
	candidates := p.extensions(n, target, intent, cat)
	if len(candidates) == 0 {
		return nil, nil
	}
	search := CandidateSearch{From: n.from, To: n.to, Traffic: n.region.String(), Total: len(candidates)}
	ranked := candidates[:min(len(candidates), maxTrials)]
	for _, c := range ranked {
		m := c.rule.Match()
		search.Candidates = append(search.Candidates, CandidateTrial{Rule: c.rule.ID(), Field: c.field, Cost: c.cost,
			Src: m.Src.Relation(target.Src), Dst: m.Dst.Relation(target.Dst), Service: m.Service.Relation(target.Service)})
	}
	for i, c := range ranked {
		mark := cat.mark()
		change := c.change(cat)
		err := p.verify(append(slices.Clone(cat.created), change), intent, []need{n}, at)
		if err == nil {
			search.Candidates[i].Selected = true
			plan.Searches = append(plan.Searches, search)
			return []Change{change}, nil
		}
		search.Candidates[i].Error = err.Error()
		cat.rollback(mark)
	}
	search.Exhausted = len(candidates) > len(ranked)
	plan.Searches = append(plan.Searches, search)
	if search.Exhausted {
		return nil, fmt.Errorf("%w: checked %d of %d existing candidates", ErrUnverifiable, len(ranked), len(candidates))
	}
	return nil, nil
}

// extension is a candidate: add the target's field set to one rule.
type extension struct {
	rule  *firemon.Rule
	field Field
	add   traffic.Space // only the field dimension is used
	// whole is the requested set of the field on this zone pair; an
	// existing object equal to it adds the same traffic as add.
	whole traffic.Space
	cost  int
}

// change adds the missing part of the field, or one existing object
// holding the whole target set when there is one: a /24 stays one object
// rather than ranges around what the rule already has.
func (x extension) change(cat *catalog) ExtendRule {
	var names []string
	group := cat.naming.Group(x.rule.ID(), x.field)
	switch x.field {
	case FieldSource:
		names = cat.wholeOr(x.whole.Src, x.add.Src)
		names = cat.groupAddresses(names, x.add.Src, group)
	case FieldDestination:
		names = cat.wholeOr(x.whole.Dst, x.add.Dst)
		names = cat.groupAddresses(names, x.add.Dst, group)
	case FieldService:
		if name, ok := cat.services[x.whole.Service.String()]; ok {
			names = []string{name}
		} else {
			names = cat.serviceNames(x.add.Service)
		}
		names = cat.groupServices(names, x.add.Service, group)
	case FieldUnset:
	}
	return ExtendRule{RuleID: x.rule.ID(), Field: x.field, Names: names}
}

// price uses the same catalog and edit as verification. Each new object,
// group member and reference appended to the rule is one edit.
func (x extension) price(cat *catalog) int {
	mark := cat.mark()
	change := x.change(cat)
	cost := len(change.Names)
	for _, ch := range cat.created[mark:] {
		cost++
		switch c := ch.(type) {
		case AddAddressGroup:
			cost += len(c.Group.Members)
		case AddServiceGroup:
			cost += len(c.Group.Members)
		}
	}
	cat.rollback(mark)
	return cost
}

// extensions lists the rules that can absorb target by growing one
// dimension, cheapest first.
func (p *Planner) extensions(n need, target traffic.Space, intent Intent, cat *catalog) []extension {
	var out []extension
	scope := n.scope.Bounds()
	for _, r := range p.fw.Rules() {
		if n.before != nil && r.Position() >= n.before.Position() {
			break
		}
		if !extendable(r, n.from, n.to, intent) {
			continue
		}
		m := r.Match()
		fits := func(a, b traffic.Space) bool { return a.ContainsSpace(b) }
		if m.Dst.ContainsSet(target.Dst) && m.Service.ContainsSet(target.Service) && fits(scope, traffic.Space{Src: scope.Src, Dst: m.Dst, Service: m.Service}) {
			add := target.Src.Subtract(m.Src)
			if !add.IsEmpty() {
				out = append(out, extension{rule: r, field: FieldSource, add: traffic.Space{Src: add}, whole: scope})
			}
		}
		if m.Src.ContainsSet(target.Src) && m.Service.ContainsSet(target.Service) && fits(scope, traffic.Space{Src: m.Src, Dst: scope.Dst, Service: m.Service}) {
			add := target.Dst.Subtract(m.Dst)
			if !add.IsEmpty() {
				out = append(out, extension{rule: r, field: FieldDestination, add: traffic.Space{Dst: add}, whole: scope})
			}
		}
		if m.Src.ContainsSet(target.Src) && m.Dst.ContainsSet(target.Dst) && fits(scope, traffic.Space{Src: m.Src, Dst: m.Dst, Service: scope.Service}) {
			add := target.Service.Subtract(m.Service)
			if !add.IsEmpty() {
				out = append(out, extension{rule: r, field: FieldService, add: traffic.Space{Service: add}, whole: scope})
			}
		}
	}
	for i := range out {
		out[i].cost = out[i].price(cat)
	}
	slices.SortStableFunc(out, func(a, b extension) int { return CompareCandidates(a.key(), b.key()) })
	return out
}

func (x extension) key() CandidateKey {
	return CandidateKey{BothEnds: x.field == FieldService, Logs: x.rule.Spec().Log.Enabled(), Cost: x.cost, Position: x.rule.Position()}
}
