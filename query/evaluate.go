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
	assumed  []*firemon.Rule // rules taken not to match: premises
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
	// spare is the other piece buffer: split fills it and swaps, so a
	// long rule list does not allocate a new list for every rule.
	spare []piece
	max   int
}

// evaluate runs ordered first-match over p.Policy and fills its decisions
// and verdict.
func (e *Engine) evaluate(p *Path, at time.Time) {
	ev := &evaluator{path: p, pieces: []piece{{space: p.Policy}}, max: e.max}
	for _, r := range e.rules {
		if len(ev.pieces) == 0 {
			break
		}
		e.apply(ev, r, at)
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

// reaches reports whether s overlaps undecided traffic.
func (ev *evaluator) reaches(s traffic.Space) bool {
	for _, pc := range ev.pieces {
		if addressesOverlap(pc.space, s) && pc.space.Overlaps(s) {
			return true
		}
	}
	return false
}

// apply evaluates one rule against the undecided pieces of ev's path:
// it decides what the rule matches, marks what it may match, or records
// the premise it was taken not to match under (ADR 0017).
func (e *Engine) apply(ev *evaluator, r *firemon.Rule, at time.Time) {
	p := ev.path
	applies := zoneApplicability(r, p.From, p.To)
	if p.AppInferred && !p.AppDecisive && applies != appliesNo && len(r.Applications()) > 0 && ev.reaches(r.Bound()) {
		p.AppDecisive = true
	}
	if e.inactive(r, at) {
		if applies != appliesNo && e.offSchedule(r, at) {
			// Inactive now, active at other times: the result holds at the
			// instant evaluated, which is a premise.
			if v := e.ruleView(r, p); !v.skip {
				ev.assume(r, v.bound)
			}
		}
		return
	}
	if applies == appliesNo {
		return
	}
	v := e.ruleView(r, p)
	switch {
	case v.skip:
		if v.assumed {
			ev.assume(r, v.bound)
		}
	case applies == appliesMaybe:
		ev.taint(r, v.bound)
	case !v.decidable:
		// First match: what the rule certainly matches is decided here. The
		// rest of its bound is possible, or, when only the domain names the
		// rule may resolve to are unknown, taken not to be the requested
		// addresses.
		if !v.certain.IsEmpty() {
			ev.decide(r, v.certain, outcomeOf(r.Action()))
		}
		if v.domainPremise {
			ev.assume(r, v.bound)
		} else {
			ev.taint(r, v.bound)
		}
	default:
		ev.decide(r, v.match, outcomeOf(r.Action()))
	}
}

// taint marks the parts of every piece an undecidable rule might match.
func (ev *evaluator) taint(r *firemon.Rule, bound traffic.Space) {
	ev.split(bound, func(pc piece, hit traffic.Space) []piece {
		return []piece{{space: hit, possible: append(slices.Clip(pc.possible), r), assumed: pc.assumed}}
	})
}

// assume marks the parts of every piece a rule was taken not to match.
func (ev *evaluator) assume(r *firemon.Rule, bound traffic.Space) {
	ev.split(bound, func(pc piece, hit traffic.Space) []piece {
		return []piece{{space: hit, possible: pc.possible, assumed: append(slices.Clip(pc.assumed), r)}}
	})
}

// decide removes the packets r matches from every piece and records them.
func (ev *evaluator) decide(r *firemon.Rule, match traffic.Space, o Outcome) {
	ev.split(match, func(pc piece, hit traffic.Space) []piece {
		ev.record(r, o, pc, hit)
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
			next = ev.spare[:0]
			next = append(next, ev.pieces[:i]...)
			changed = true
		}
		next = append(next, onHit(pc, hit)...)
		for _, rest := range pc.space.Subtract(s) {
			next = append(next, piece{space: rest, possible: pc.possible, assumed: pc.assumed})
		}
	}
	if changed {
		// The old list becomes the spare; clear it so the pieces it held
		// can be collected.
		clear(ev.pieces)
		ev.spare, ev.pieces = ev.pieces[:0], next
	}
}

// finish assigns the default outcome to every undecided piece.
func (ev *evaluator) finish(o Outcome) {
	for _, pc := range ev.pieces {
		if ev.path.Incomplete {
			ev.record(nil, OutcomeUnknown, pc, pc.space)
			continue
		}
		ev.record(nil, o, pc, pc.space)
	}
	for i := range ev.decisions {
		ev.decisions[i].Space = traffic.DisjointRegion(ev.spaces[i]...) // pieces of one partition never overlap
	}
	ev.path.Decisions = ev.decisions
}

// record adds space to the decision of rule r with the same possible set.
func (ev *evaluator) record(r *firemon.Rule, final Outcome, pc piece, s traffic.Space) {
	possible := pc.possible
	o := final
	if !agree(final, possible) {
		o = OutcomeUnknown
	}
	for i := range ev.decisions {
		d := &ev.decisions[i]
		if d.Rule == r && d.Outcome == o && d.FallbackOutcome == final && slices.Equal(d.Possible, possible) && slices.Equal(d.Assumed, pc.assumed) {
			ev.spaces[i] = append(ev.spaces[i], s)
			return
		}
	}
	ev.decisions = append(ev.decisions, Decision{Rule: r, Outcome: o, FallbackOutcome: final, Possible: slices.Clone(possible), Assumed: slices.Clone(pc.assumed)})
	ev.spaces = append(ev.spaces, []traffic.Space{s})
}

// Deciders returns the possible rules that would change the outcome if
// they matched: permits when the final outcome is not a permit, denies
// when it is. The others agree with the decision and cannot change it.
func (d Decision) Deciders() []*firemon.Rule {
	var out []*firemon.Rule
	for _, r := range d.Possible {
		if !agree(d.FallbackOutcome, []*firemon.Rule{r}) {
			out = append(out, r)
		}
	}
	return out
}

// Conditional returns the assumed rules that would change the outcome if
// their unknown criterion held: the premises worth stating.
func (d Decision) Conditional() []*firemon.Rule {
	var out []*firemon.Rule
	for _, r := range d.Assumed {
		if !agree(d.FallbackOutcome, []*firemon.Rule{r}) {
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
	case ScheduleWorstCase:
		if r.Ignored() || !r.Scheduled() {
			return r.Ignored()
		}
		activity := ActivityPartial
		if e.activity != nil {
			activity = e.activity(r)
		}
		switch activity {
		case ActivityAlways:
			return false
		case ActivityNever:
			return true
		case ActivityPartial:
		}
		return r.Action() != firemon.ActionDeny
	case ScheduleAt:
		return r.InactiveAt(at)
	default:
		return r.InactiveAt(at)
	}
}

// offSchedule reports a rule a schedule keeps inactive at t that is in
// force at other times.
func (e *Engine) offSchedule(r *firemon.Rule, at time.Time) bool {
	return e.schedules == ScheduleAt && r.Scheduled() && !r.Ignored() && !r.ExpiredAt(at)
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
