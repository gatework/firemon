package plan

import (
	"context"
	"slices"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/policy"
)

type batchState struct {
	planner               Planner
	before, after         *fm.Firewall
	visits                *visitBudget
	baseline              map[string]policy.Result
	changes               []Change
	commands              []string
	cost                  Cost
	attempts, maxAttempts int
}

func (s *batchState) add(ctx context.Context, q policy.Request, targets []policy.Request) (bool, []BatchAttempt, error) {
	p := s.planner
	limit := p.Engine.Limits.WithDefaults().MaxRegions
	if err := s.visits.take(ctx, s.after.RuleCount()); err != nil {
		return false, nil, err
	}
	r, err := p.Engine.Query(ctx, s.after, q)
	if err != nil {
		return false, nil, err
	}
	if !r.Complete || !r.Unknown.Empty() {
		return false, []BatchAttempt{{Stage: PreservationRejection, Reason: "target became unknown"}}, nil
	}
	gap, err := q.Traffic.Difference(r.Allowed, limit)
	if err != nil {
		return false, nil, err
	}
	if gap.Empty() {
		return true, nil, nil
	}
	if p.Renderer == nil {
		return false, nil, ErrInvalid
	}
	if err := s.visits.take(ctx, s.after.RuleCount()); err != nil {
		return false, nil, err
	}
	for _, rule := range s.after.Rules() {
		m := rule.Record().Match
		if m.Schedule != "" || len(m.Applications) > 0 || len(m.Users) > 0 {
			return false, []BatchAttempt{{Stage: PreservationRejection, Reason: "permanent change has unmodeled condition transitions"}}, nil
		}
	}
	all := q
	all.Traffic, err = flow.AllTraffic(limit)
	if err != nil {
		return false, nil, err
	}
	prior, err := p.Engine.Query(ctx, s.after, all)
	if err != nil {
		return false, nil, err
	}
	if !prior.Complete {
		return false, []BatchAttempt{{Stage: PreservationRejection, Reason: "context has unknown policy evidence"}}, nil
	}
	selection := candidateSelection{limit: s.maxAttempts}
	var attempts []BatchAttempt
	record := func(stage RejectionStage, id fm.ID, reason string) {
		if len(attempts) < 16 {
			attempts = append(attempts, BatchAttempt{stage, id, reason})
		}
	}
	for _, rule := range s.after.Rules() {
		if err := s.visits.take(ctx, 1); err != nil {
			return false, attempts, err
		}
		r := rule.Record()
		if r.Disabled || r.Builtin || r.Action != fm.Permit || r.Scope != q.Scope || r.RuleSet != q.RuleSet || r.Log == fm.Unknown || !sameZones(r.Match, q) {
			continue
		}
		next, changes, cost, err := p.appendCandidate(ctx, s.after, r, gap, s.visits)
		if err != nil {
			if err == ErrUnsafe {
				record(DeclarationRejection, r.ID, "append declaration is unknown")
				continue
			}
			return false, attempts, err
		}
		if len(changes) == 0 {
			continue
		}
		possible, err := p.Engine.AppendCanPreserve(ctx, s.after, next, r.ID, q, prior)
		if err != nil {
			return false, attempts, err
		}
		if !possible {
			record(PreservationRejection, r.ID, "append changes traffic outside target")
			continue
		}
		selection.consider(candidate{next, changes, cost})
	}
	try := func(c candidate) (bool, error) {
		if s.attempts >= s.maxAttempts {
			return false, policy.ErrBudget
		}
		s.attempts++
		changes := mergeBatchChanges(s.changes, c.changes, c.after)
		if err := p.preflightReadback(ctx, s.before, c.after); err != nil {
			return false, err
		}
		if _, err := p.proveBatch(ctx, s.before, c.after, targets, s.baseline, s.visits); err != nil {
			if err == ErrUnsafe || err == policy.ErrNotEquivalent {
				record(PreservationRejection, fm.ID(c.cost.ID), "joint target, outside ownership or NAT proof failed")
				return false, nil
			}
			return false, err
		}
		if err := s.visits.takeGraphs(ctx, s.before, c.after); err != nil {
			return false, err
		}
		if err := ValidateChanges(ctx, s.before, c.after, changes); err != nil {
			return false, err
		}
		commands, err := p.renderChanges(ctx, s.before, c.after, changes)
		if err != nil {
			if representationRejected(err) {
				record(RepresentationRejection, fm.ID(c.cost.ID), "native renderer refused candidate")
				return false, nil
			}
			return false, err
		}
		if len(commands) == 0 {
			record(RepresentationRejection, fm.ID(c.cost.ID), "native renderer produced no commands")
			return false, nil
		}
		s.after, s.changes, s.commands = c.after, changes, commands
		s.cost.NewRules += c.cost.NewRules
		s.cost.NewObjects += c.cost.NewObjects
		s.cost.AppendedMembers, s.cost.ModifiedRules = 0, 0
		for _, change := range changes {
			if change.Kind == AppendMembers {
				s.cost.ModifiedRules++
				s.cost.AppendedMembers += len(change.Sources) + len(change.Destinations) + len(change.Services)
			}
		}
		return true, nil
	}
	for _, c := range selection.ordered() {
		ok, err := try(c)
		if err != nil || ok {
			return ok, attempts, err
		}
	}
	if s.attempts >= s.maxAttempts {
		return false, attempts, policy.ErrBudget
	}
	next, changes, cost, err := createCandidate(ctx, s.after, q, gap, s.visits)
	if err != nil {
		return false, attempts, err
	}
	ok, err := try(candidate{next, changes, cost})
	return ok, attempts, err
}

func mergeBatchChanges(prior, added []Change, after *fm.Firewall) []Change {
	result := cloneChanges(prior)
	for _, c := range added {
		i := slices.IndexFunc(result, func(v Change) bool { return v.Rule == c.Rule })
		if i < 0 {
			result = append(result, cloneChanges([]Change{c})[0])
			continue
		}
		old := &result[i]
		if old.Kind == CreateRule {
			m := after.Rule(c.Rule).Record().Match
			old.Sources, old.Destinations, old.Services = m.Sources, m.Destinations, m.Services
		} else {
			old.Sources = append(old.Sources, c.Sources...)
			old.Destinations = append(old.Destinations, c.Destinations...)
			old.Services = append(old.Services, c.Services...)
		}
	}
	return result
}
