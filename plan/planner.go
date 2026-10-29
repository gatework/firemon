package plan

import (
	"context"
	"errors"
	"fmt"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/internal/dependency"
	"github.com/gatework/firemon/policy"
)

type Planner struct {
	Renderer Renderer
	// MaxCandidates bounds full proof/render attempts in increasing Cost order.
	// Nonpositive values default to 128. Scanning still uses Engine.Limits.
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
	maxCandidates := p.MaxCandidates
	if maxCandidates <= 0 {
		maxCandidates = 128
	}
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
		result.target, result.engine = q, p.Engine
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
	candidates := candidateSelection{limit: maxCandidates}
	if err := visits.take(ctx, fw.RuleCount()); err != nil {
		return nil, err
	}
	for _, rule := range fw.Rules() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		r := rule.Record()
		if r.Disabled || r.Builtin || r.Action != fm.Permit || r.Scope != q.Scope || r.RuleSet != q.RuleSet || r.Log == fm.Unknown || !sameZones(r.Match, q) {
			continue
		}
		next, changes, cost, err := p.appendCandidate(ctx, fw, r, gap, &visits)
		if err != nil {
			if errors.Is(err, policy.ErrBudget) || errors.Is(err, flow.ErrBudget) || ctx.Err() != nil {
				return nil, err
			}
			continue
		}
		if len(changes) == 0 {
			continue
		}
		possible, err := p.Engine.AppendCanPreserve(ctx, fw, next, r.ID, q, prior)
		if err != nil {
			return nil, err
		}
		if !possible {
			continue
		}
		candidates.consider(candidate{after: next, changes: changes, cost: cost})
	}
	attempts := 0
	for _, draft := range candidates.ordered() {
		attempts++
		result, err := p.tryCandidate(ctx, fw, draft, q, &prior, &visits)
		if err != nil || result != nil {
			return result, err
		}
	}
	// Every append has fewer new rules than creation. Construct the fallback
	// only after those attempts fail; an unused fallback must not spend budget.
	if attempts >= maxCandidates {
		return nil, policy.ErrBudget
	}
	next, changes, cost, err := createCandidate(ctx, fw, q, gap, &visits)
	if err != nil {
		return nil, err
	}
	result, err := p.tryCandidate(ctx, fw, candidate{after: next, changes: changes, cost: cost}, q, &prior, &visits)
	if err != nil || result != nil {
		return result, err
	}
	return nil, ErrUnsafe
}
