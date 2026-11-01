package plan

import (
	"context"
	"slices"
	"strings"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/policy"
)

// proveBatch shares only original-baseline evaluations. Candidate and readback
// graphs always undergo fresh target, full-context ownership and NAT proofs.
func (p Planner) proveBatch(ctx context.Context, before, after *fm.Firewall, targets []policy.Request, baseline map[string]policy.Result, visits *visitBudget) (Proof, error) {
	return p.proveBatchPolicy(ctx, before, after, targets, baseline, visits, true)
}

func (p Planner) proveBatchPolicy(ctx context.Context, before, after *fm.Firewall, targets []policy.Request, baseline map[string]policy.Result, visits *visitBudget, preserveNAT bool) (Proof, error) {
	return p.proveBatchPolicyWindows(ctx, before, after, targets, nil, baseline, visits, preserveNAT)
}

func (p Planner) proveBatchPolicyWindows(ctx context.Context, before, after *fm.Firewall, targets []policy.Request, windows []fm.TimeWindow, baseline map[string]policy.Result, visits *visitBudget, preserveNAT bool) (Proof, error) {
	if err := ctx.Err(); err != nil {
		return Proof{}, err
	}
	if before == nil || after == nil || !before.Complete() || !after.Complete() || len(targets) == 0 {
		return Proof{}, ErrUnsafe
	}
	limits := p.Engine.Limits.WithDefaults()
	if baseline == nil {
		baseline = make(map[string]policy.Result)
	}
	from := targets[0].At
	finite := false
	for _, w := range windows {
		if !w.Start.IsZero() {
			finite = true
			from = proofEpoch
			break
		}
	}

	for _, q := range targets {
		if finite && q.At.IsZero() {
			q.At = proofEpoch
		}
		if q.At.Before(from) && !finite {
			from = q.At
		}
		if err := visits.take(ctx, after.RuleCount()); err != nil {
			return Proof{}, err
		}
		r, err := p.Engine.Query(ctx, after, q)
		if err != nil {
			return Proof{}, err
		}
		ok, err := r.Allowed.Contains(q.Traffic, limits.MaxRegions)
		if err != nil {
			return Proof{}, err
		}
		if !ok || !r.Complete || !r.Unknown.Empty() {
			return Proof{}, ErrUnsafe
		}
	}
	if err := visits.takeGraphs(ctx, before, after); err != nil {
		return Proof{}, err
	}
	if preserveNAT {
		if err := p.Engine.PreserveNAT(ctx, before, after, from); err != nil {
			return Proof{}, err
		}
	}
	contexts, err := p.Engine.Contexts(ctx, from, before, after)
	if err != nil {
		return Proof{}, err
	}
	// Include supplied contexts (including wildcard zones and empty native chains)
	// in addition to the complete declared native chain/zone matrix.
	seen := make(map[string]bool)
	for _, q := range contexts {
		seen[batchKey(q)] = true
	}
	all, err := flow.AllTraffic(limits.MaxRegions)
	if err != nil {
		return Proof{}, err
	}
	for _, q := range targets {
		if finite && q.At.IsZero() {
			q.At = proofEpoch
		}
		q.Traffic = all
		key := batchKey(q)
		if !seen[key] {
			if len(contexts) >= limits.MaxCombinations {
				return Proof{}, policy.ErrBudget
			}
			contexts = append(contexts, q)
			seen[key] = true
		}
	}
	slices.SortFunc(contexts, func(a, b policy.Request) int { return strings.Compare(batchKey(a), batchKey(b)) })
	for _, q := range contexts {
		if err := visits.take(ctx, len(targets)); err != nil {
			return Proof{}, err
		}
		var target flow.Traffic
		for index, t := range targets {
			// Legacy targets remain permanent. Finite native targets contribute only
			// during their explicitly proven half-open lifetime.
			if t.Scope != q.Scope || t.RuleSet != q.RuleSet || t.FromZone != "" && t.FromZone != q.FromZone || t.ToZone != "" && t.ToZone != q.ToZone {
				continue
			}
			if len(windows) > 0 {
				w := windows[index]
				if !w.Start.IsZero() && (q.At.Before(w.Start) || !q.At.Before(w.End)) {
					continue
				}
			}
			target, err = target.Union(t.Traffic, limits.MaxRegions)
			if err != nil {
				return Proof{}, err
			}
		}
		key := batchKey(q)
		prior, ok := baseline[key]
		if !ok {
			if err := visits.take(ctx, before.RuleCount()); err != nil {
				return Proof{}, err
			}
			prior, err = p.Engine.Query(ctx, before, q)
			if err != nil {
				return Proof{}, err
			}
			baseline[key] = prior
		}
		if err := visits.take(ctx, after.RuleCount()); err != nil {
			return Proof{}, err
		}
		next, err := p.Engine.Query(ctx, after, q)
		if err != nil {
			return Proof{}, err
		}
		if !prior.Complete || !next.Complete || !prior.Unknown.Empty() || !next.Unknown.Empty() {
			return Proof{}, ErrUnsafe
		}
		if finite {
			ok, err := next.Allowed.Contains(target, limits.MaxRegions)
			if err != nil {
				return Proof{}, err
			}
			if !ok {
				return Proof{}, ErrUnsafe
			}
		}
		if err := preserveOutsideTargetOwnership(ctx, prior, next, target, limits.MaxRegions, visits); err != nil {
			return Proof{}, err
		}
	}
	return Proof{BaseDigest: before.SemanticDigest(), ResultDigest: after.SemanticDigest(), TargetAllowed: true, TargetSatisfied: true, OutsidePreserved: true, NATUnchanged: true}, nil
}
