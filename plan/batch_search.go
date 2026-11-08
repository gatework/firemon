package plan

import (
	"context"
	"iter"
	"slices"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/policy"
)

type batchState struct {
	planner       Planner
	before, after *fm.Firewall
	visits        *visitBudget
	baseline      map[string]policy.Result
	changes       []Change
	commands      []string
	cost          Cost
	attempts      candidateAttempts
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
	for rule := range s.after.DeclaredRules() {
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
	search := candidateSearch{planner: p, before: s.after, request: q, gap: gap, prior: &prior, visits: s.visits, attempts: &s.attempts}
	adapter := batchSearchAdapter{state: s, targets: targets}
	accepted, err := search.run(ctx, &adapter)
	return accepted, adapter.refusals, err
}

type batchSearchAdapter struct {
	state    *batchState
	targets  []policy.Request
	refusals []BatchAttempt
}

func (a *batchSearchAdapter) rules(ctx context.Context) iter.Seq2[*fm.Rule, error] {
	return func(yield func(*fm.Rule, error) bool) {
		for rule := range a.state.after.DeclaredRules() {
			if err := a.state.visits.take(ctx, 1); err != nil {
				yield(nil, err)
				return
			}
			if !yield(rule, nil) {
				return
			}
		}
	}
}

func (a *batchSearchAdapter) record(stage RejectionStage, id fm.ID, reason string) {
	if len(a.refusals) < 16 {
		a.refusals = append(a.refusals, BatchAttempt{stage, id, reason})
	}
}

func (a *batchSearchAdapter) decline(_ context.Context, stage RejectionStage, id fm.ID, err error) error {
	if stage == DeclarationRejection {
		if err != ErrUnsafe {
			return err
		}
		a.record(stage, id, "append declaration is unknown")
	} else {
		a.record(stage, id, "append changes traffic outside target")
	}
	return nil
}

func (a *batchSearchAdapter) attempt(ctx context.Context, c candidate) (bool, error) {
	s := a.state
	p := s.planner
	changes := mergeBatchChanges(s.changes, c.changes, c.after)
	if err := p.preflightReadback(ctx, s.before, c.after); err != nil {
		return false, err
	}
	if _, err := p.proveBatch(ctx, s.before, c.after, a.targets, s.baseline, s.visits); err != nil {
		if err == ErrUnsafe || err == policy.ErrNotEquivalent {
			a.record(PreservationRejection, fm.ID(c.cost.ID), "joint target, outside ownership or NAT proof failed")
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
			a.record(RepresentationRejection, fm.ID(c.cost.ID), "native renderer refused candidate")
			return false, nil
		}
		return false, err
	}
	if len(commands) == 0 {
		a.record(RepresentationRejection, fm.ID(c.cost.ID), "native renderer produced no commands")
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
