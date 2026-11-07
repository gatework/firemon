package plan

import (
	"context"
	"errors"
	"fmt"
	"iter"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/internal/dependency"
	"github.com/gatework/firemon/policy"
)

type Planner struct {
	Renderer       Renderer
	NativeRenderer NativeRenderer
	// MaxCandidates bounds full proof/render attempts in increasing Cost order.
	// Nonpositive values default to 128. PlanBatch shares this limit across all
	// inputs. Scanning still uses Engine.Limits.
	MaxCandidates int
	Engine        policy.Engine
}

func (p Planner) Plan(ctx context.Context, fw *fm.Firewall, requests []policy.Request) (*Plan, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if fw == nil || len(requests) == 0 || len(requests) > 100 || p.Renderer != nil && dependency.Nil(p.Renderer) {
		return nil, ErrInvalid
	}
	if !fw.Complete() {
		return nil, ErrUnsafe
	}
	limits := p.Engine.Limits.WithDefaults()
	visits := visitBudget(limits.MaxVisits)
	attempts := newCandidateAttempts(p.MaxCandidates)
	q := requests[0]
	if q.RuleSet == "" {
		q.RuleSet = "security"
	}
	for _, r := range requests[1:] {
		if err := visits.take(ctx, 1); err != nil {
			return nil, err
		}
		if !r.SameContext(q) {
			return nil, fmt.Errorf("%w: batch contexts differ", ErrInvalid)
		}
		var err error
		q.Traffic, err = q.Traffic.Union(r.Traffic, limits.MaxRegions)
		if err != nil {
			return nil, err
		}
	}
	evaluation, err := p.Engine.Query(ctx, fw, q)
	if err != nil {
		return nil, err
	}
	if !evaluation.Complete || !evaluation.Unknown.Empty() {
		return nil, ErrUnsafe
	}
	gap, err := q.Traffic.Difference(evaluation.Allowed, limits.MaxRegions)
	if err != nil {
		return nil, err
	}
	if gap.Empty() {
		if err := p.preflightReadback(ctx, fw, fw); err != nil {
			return nil, err
		}
		result := &Plan{before: fw, after: fw, proof: Proof{BaseDigest: fw.SemanticDigest(), ResultDigest: fw.SemanticDigest(), TargetAllowed: true, TargetSatisfied: true, OutsidePreserved: true, NATUnchanged: true}}
		result.intent, result.engine = accessIntent{target: q}, p.Engine
		if err := result.seal(); err != nil {
			return nil, err
		}
		return result, nil
	}
	if p.Renderer == nil {
		return nil, fmt.Errorf("%w: renderer required", ErrInvalid)
	}
	// A permanent change cannot be proven across unmodeled time or condition transitions.
	if err := visits.take(ctx, fw.RuleCount()); err != nil {
		return nil, err
	}
	for _, r := range fw.Rules() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		v := r.Record()
		if v.Match.Schedule != "" || len(v.Match.Applications) > 0 || len(v.Match.Users) > 0 {
			return nil, ErrUnsafe
		}
	}
	all := q
	all.Traffic, err = flow.AllTraffic(limits.MaxRegions)
	if err != nil {
		return nil, err
	}
	prior, err := p.Engine.Query(ctx, fw, all)
	if err != nil {
		return nil, err
	}
	if !prior.Complete {
		return nil, ErrUnsafe
	}
	search := candidateSearch{planner: p, before: fw, request: q, gap: gap, prior: &prior, visits: &visits, attempts: &attempts}
	adapter := accessSearchAdapter{search: &search}
	accepted, err := search.run(ctx, &adapter)
	if err != nil || accepted {
		return adapter.result, err
	}
	return nil, ErrUnsafe
}

type accessSearchAdapter struct {
	search *candidateSearch
	result *Plan
}

func (a *accessSearchAdapter) rules(ctx context.Context) iter.Seq2[*fm.Rule, error] {
	return func(yield func(*fm.Rule, error) bool) {
		s := a.search
		if err := s.visits.take(ctx, s.before.RuleCount()); err != nil {
			yield(nil, err)
			return
		}
		for _, rule := range s.before.Rules() {
			if err := ctx.Err(); err != nil {
				yield(nil, err)
				return
			}
			if !yield(rule, nil) {
				return
			}
		}
	}
}

func (*accessSearchAdapter) decline(ctx context.Context, stage RejectionStage, _ fm.ID, err error) error {
	if stage == DeclarationRejection && (errors.Is(err, policy.ErrBudget) || errors.Is(err, flow.ErrBudget) || ctx.Err() != nil) {
		return err
	}
	return nil
}

func (a *accessSearchAdapter) attempt(ctx context.Context, draft candidate) (bool, error) {
	s := a.search
	result, err := s.planner.tryCandidate(ctx, s.before, draft, s.request, s.prior, s.visits)
	a.result = result
	return result != nil, err
}
