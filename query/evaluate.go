package query

import (
	"slices"
	"time"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/traffic"
)

// piece is an undecided part of a path and the undecidable rules that
// might already have matched it.
type piece struct {
	space    traffic.Space
	possible []*firemon.Rule
}

// applicability is whether a rule's zones cover a path.
type applicability uint8

const (
	appliesNo applicability = iota
	appliesYes
	appliesMaybe // a zone of the path is unknown
)

// evaluator holds the state of one first-match evaluation.
type evaluator struct {
	path      *Path
	pieces    []piece
	decisions []Decision
	max       int
}

// evaluate runs ordered first-match over p.Policy and fills its decisions
// and verdict.
func (e *Engine) evaluate(p *Path, at time.Time) {
	ev := &evaluator{path: p, pieces: []piece{{space: p.Policy}}, max: e.max}
	for _, r := range e.rules {
		if len(ev.pieces) == 0 {
			break
		}
		if r.InactiveAt(at) {
			continue
		}
		switch applies := zoneApplicability(r, p.From, p.To); {
		case applies == appliesNo:
			continue
		case applies == appliesMaybe || !r.Decidable():
			ev.taint(r)
		default:
			ev.decide(r, outcomeOf(r.Action()))
		}
		if ev.overBudget() {
			p.Incomplete = true
			break
		}
	}
	ev.finish(e.defaultOutcome(p))
	if len(p.NATUncertain) > 0 {
		// Translation may differ from the evaluated packets: nothing is certain.
		for i := range p.Decisions {
			p.Decisions[i].Outcome = OutcomeUnknown
		}
	}
	outcomes := map[Outcome]bool{}
	for _, d := range p.Decisions {
		outcomes[d.Outcome] = true
	}
	p.Verdict = verdictOf(outcomes)
}

// taint marks the parts of every piece an undecidable rule might match.
func (ev *evaluator) taint(r *firemon.Rule) {
	bound := r.Bound()
	var next []piece
	for _, pc := range ev.pieces {
		if !addressesOverlap(pc.space, bound) {
			next = append(next, pc)
			continue
		}
		hit := pc.space.Intersect(bound)
		if hit.IsEmpty() {
			next = append(next, pc)
			continue
		}
		next = append(next, piece{space: hit, possible: append(slices.Clip(pc.possible), r)})
		for _, rest := range pc.space.Subtract(bound) {
			next = append(next, piece{space: rest, possible: pc.possible})
		}
	}
	ev.pieces = next
}

// decide removes the packets r matches from every piece and records them.
func (ev *evaluator) decide(r *firemon.Rule, o Outcome) {
	match := r.Match()
	var next []piece
	for _, pc := range ev.pieces {
		if !addressesOverlap(pc.space, match) {
			next = append(next, pc)
			continue
		}
		hit := pc.space.Intersect(match)
		if hit.IsEmpty() {
			next = append(next, pc)
			continue
		}
		ev.record(r, o, pc.possible, hit)
		for _, rest := range pc.space.Subtract(match) {
			next = append(next, piece{space: rest, possible: pc.possible})
		}
	}
	ev.pieces = next
}

// finish assigns the default outcome to every undecided piece.
func (ev *evaluator) finish(o Outcome) {
	for _, pc := range ev.pieces {
		if ev.path.Incomplete {
			ev.record(nil, OutcomeUnknown, pc.possible, pc.space)
			continue
		}
		ev.record(nil, o, pc.possible, pc.space)
	}
	ev.path.Decisions = ev.decisions
}

// record adds space to the decision of rule r with the same possible set.
func (ev *evaluator) record(r *firemon.Rule, final Outcome, possible []*firemon.Rule, s traffic.Space) {
	o := final
	if !agree(final, possible) {
		o = OutcomeUnknown
	}
	for i := range ev.decisions {
		d := &ev.decisions[i]
		if d.Rule == r && d.Outcome == o && d.Final == final && slices.Equal(d.Possible, possible) {
			d.Space = d.Space.AppendDisjoint(s) // pieces of one partition never overlap
			return
		}
	}
	ev.decisions = append(ev.decisions, Decision{Rule: r, Outcome: o, Final: final, Space: traffic.NewRegion(s), Possible: slices.Clone(possible)})
}

// agree reports whether every possible rule would give the same result as
// the final outcome, so the uncertainty does not change the verdict.
func agree(final Outcome, possible []*firemon.Rule) bool {
	permits := final == OutcomePermit
	if final == OutcomeUnknown {
		return len(possible) == 0
	}
	for _, r := range possible {
		if (r.Action() == firemon.ActionPermit) != permits || r.Action() == firemon.ActionUnset {
			return false
		}
	}
	return true
}

func (ev *evaluator) overBudget() bool { return len(ev.pieces) > ev.max }

// defaultOutcome is the vendor default action for the path's zones.
func (e *Engine) defaultOutcome(p *Path) Outcome {
	if p.From == "" || p.To == "" {
		return OutcomeUnknown
	}
	action := e.fw.Semantics().InterzoneAction
	if p.From == p.To {
		action = e.fw.Semantics().IntrazoneAction
	}
	if action == firemon.ActionPermit {
		return OutcomePermit
	}
	return OutcomeDefault
}

func zoneApplicability(r *firemon.Rule, from, to string) applicability {
	spec := r.Spec()
	if !spec.Scope.Allows(from, to) {
		return appliesNo
	}
	a := zoneApplies(spec.From, spec.To, from, to)
	if a == appliesYes && spec.Scope != firemon.ZoneScopeAny && (from == "" || to == "") {
		return appliesMaybe
	}
	return a
}

// zoneApplies reports whether zone lists certainly cover a zone pair, might
// cover it because a zone is unknown, or do not.
func zoneApplies(fromZones, toZones []string, from, to string) applicability {
	fromOK, fromMaybe := zoneFits(fromZones, from)
	toOK, toMaybe := zoneFits(toZones, to)
	switch {
	case fromOK && toOK:
		return appliesYes
	case (fromOK || fromMaybe) && (toOK || toMaybe):
		return appliesMaybe
	default:
		return appliesNo
	}
}

// zoneFits reports whether a rule's zone list certainly matches zone, or
// might match it because zone is unknown.
func zoneFits(zones []string, zone string) (yes, maybe bool) {
	if len(zones) == 0 {
		return true, false
	}
	if zone == "" {
		return false, true
	}
	return slices.Contains(zones, zone), false
}

func outcomeOf(a firemon.Action) Outcome {
	switch a {
	case firemon.ActionPermit:
		return OutcomePermit
	case firemon.ActionDeny:
		return OutcomeDeny
	case firemon.ActionUnset:
		return OutcomeUnknown
	default:
		return OutcomeUnknown
	}
}

// addressesOverlap is a cheap, allocation-free pre-check: spaces whose
// sources or destinations are disjoint cannot overlap.
func addressesOverlap(a, b traffic.Space) bool {
	return a.Src.Overlaps(b.Src) && a.Dst.Overlaps(b.Dst)
}
