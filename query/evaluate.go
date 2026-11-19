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
	// spaces gathers the pieces of each decision, made a region once in
	// finish: appending to a region one piece at a time copies it each
	// time, quadratic on wide requests split into many pieces.
	spaces [][]traffic.Space
	max    int
}

// evaluate runs ordered first-match over p.Policy and fills its decisions
// and verdict.
func (e *Engine) evaluate(p *Path, at time.Time) {
	ev := &evaluator{path: p, pieces: []piece{{space: p.Policy}}, max: e.max}
	for _, r := range e.rules {
		if len(ev.pieces) == 0 {
			break
		}
		if e.inactive(r, at) {
			continue
		}
		applies := zoneApplicability(r, p.From, p.To)
		if applies == appliesNo {
			continue
		}
		v := e.ruleView(r, p)
		if v.skip {
			continue
		}
		switch {
		case applies == appliesMaybe:
			ev.taint(r, v.bound)
		case !v.decidable:
			// First match: what the rule certainly matches is decided here,
			// the rest of its bound only possibly.
			if !v.certain.IsEmpty() {
				ev.decide(r, v.certain, outcomeOf(r.Action()))
			}
			ev.taint(r, v.bound)
		default:
			ev.decide(r, v.match, outcomeOf(r.Action()))
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
func (ev *evaluator) taint(r *firemon.Rule, bound traffic.Space) {
	ev.split(bound, func(pc piece, hit traffic.Space) []piece {
		return []piece{{space: hit, possible: append(slices.Clip(pc.possible), r)}}
	})
}

// decide removes the packets r matches from every piece and records them.
func (ev *evaluator) decide(r *firemon.Rule, match traffic.Space, o Outcome) {
	ev.split(match, func(pc piece, hit traffic.Space) []piece {
		ev.record(r, o, pc.possible, hit)
		return nil
	})
}

// split cuts every piece overlapping s into its part in s, which onHit
// replaces, and the rest. Pieces s does not touch stay where they are; the
// list is copied only once a piece changes, since most rules touch none.
func (ev *evaluator) split(s traffic.Space, onHit func(pc piece, hit traffic.Space) []piece) {
	var next []piece
	changed := false
	for i, pc := range ev.pieces {
		var hit traffic.Space
		if addressesOverlap(pc.space, s) {
			hit = pc.space.Intersect(s)
		}
		if hit.IsEmpty() {
			if changed {
				next = append(next, pc)
			}
			continue
		}
		if !changed {
			next = append(make([]piece, 0, len(ev.pieces)+4), ev.pieces[:i]...)
			changed = true
		}
		next = append(next, onHit(pc, hit)...)
		for _, rest := range pc.space.Subtract(s) {
			next = append(next, piece{space: rest, possible: pc.possible})
		}
	}
	if changed {
		ev.pieces = next
	}
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
	for i := range ev.decisions {
		ev.decisions[i].Space = traffic.DisjointRegion(ev.spaces[i]...) // pieces of one partition never overlap
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
			ev.spaces[i] = append(ev.spaces[i], s)
			return
		}
	}
	ev.decisions = append(ev.decisions, Decision{Rule: r, Outcome: o, Final: final, Possible: slices.Clone(possible)})
	ev.spaces = append(ev.spaces, []traffic.Space{s})
}

// Deciders returns the possible rules that would change the outcome if
// they matched: permits when the final outcome is not a permit, denies
// when it is. The others agree with the decision and cannot change it.
func (d Decision) Deciders() []*firemon.Rule {
	var out []*firemon.Rule
	for _, r := range d.Possible {
		if !agree(d.Final, []*firemon.Rule{r}) {
			out = append(out, r)
		}
	}
	return out
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

// inactive reports whether r cannot match under the engine's schedule mode.
func (e *Engine) inactive(r *firemon.Rule, at time.Time) bool {
	switch e.schedules {
	case ScheduleAlwaysActive:
		return r.Ignored() || r.ExpiredAt(at)
	case ScheduleNeverActive:
		return r.Ignored() || r.Scheduled()
	case ScheduleAt:
		return r.InactiveAt(at)
	default:
		return r.InactiveAt(at)
	}
}

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
	scope := r.Scope()
	if !scope.Allows(from, to) {
		return appliesNo
	}
	fromZones, toZones := r.Zones()
	a := zoneApplies(fromZones, toZones, from, to)
	if a == appliesYes && scope != firemon.ZoneScopeAny && (from == "" || to == "") {
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
