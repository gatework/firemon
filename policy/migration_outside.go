package policy

import (
	"context"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
)

type migrationNATAxis struct {
	scope, ruleSet                    string
	fromZone, toZone, egressInterface fm.ID
}

func migrationAxis(q Request) migrationNATAxis {
	ruleSet := q.RuleSet
	if ruleSet == "" {
		ruleSet = "security"
	}
	return migrationNATAxis{q.Scope, ruleSet, q.FromZone, q.ToZone, q.EgressInterface}
}

func (a migrationNATAxis) request(at time.Time, traffic flow.Traffic) Request {
	return Request{Scope: a.scope, RuleSet: a.ruleSet, FromZone: a.fromZone, ToZone: a.toZone, EgressInterface: a.egressInterface, At: at, Traffic: traffic}
}

// PreserveNATOutside preserves the target's existing NAT catalog and every
// original-to-translated relation outside authorized domains. Each domain's At
// must be an exact representative of the common future temporal partition of
// timeSources, before and after. It never grants that domain to another time.
// Empty zone/interface fields explicitly cover every corresponding native axis;
// chain and scope remain concrete. A caller must first prove those domains by
// packet effects. Accordingly this method never sets IntentSatisfied.
func (e Engine) PreserveNATOutside(ctx context.Context, before, after *fm.Firewall, from time.Time, domains []Request, timeSources ...*fm.Firewall) (NATProof, error) {
	if err := ctx.Err(); err != nil {
		return NATProof{}, err
	}
	if before == nil || after == nil {
		return NATProof{}, ErrInvalid
	}
	limits := e.Limits.WithDefaults()
	budget := packetProofBudget{limits: limits, remaining: limits.MaxVisits}
	if len(domains) > limits.MaxCombinations {
		return NATProof{}, ErrBudget
	}
	if err := budget.take(ctx, len(domains), len(timeSources)); err != nil {
		return NATProof{}, err
	}
	graphs := make([]*fm.Firewall, 0, len(timeSources)+2)
	seenGraphs := make(map[*fm.Firewall]bool)
	for _, graph := range append([]*fm.Firewall{before, after}, timeSources...) {
		if graph == nil {
			return NATProof{}, ErrInvalid
		}
		if !graph.Complete() {
			return NATProof{}, ErrNotEquivalent
		}
		if seenGraphs[graph] {
			continue
		}
		if err := budget.take(ctx, graph.DeclarationSize()); err != nil {
			return NATProof{}, err
		}
		seenGraphs[graph] = true
		graphs = append(graphs, graph)
	}
	if _, err := natTimeKey(from); err != nil {
		return NATProof{}, err
	}
	for _, domain := range domains {
		if domain.Traffic.Empty() || domain.At.Before(from) {
			return NATProof{}, ErrInvalid
		}
		if domain.Traffic.RegionCount() > limits.MaxRegions {
			return NATProof{}, ErrBudget
		}
		if err := budget.take(ctx, domain.Traffic.RegionCount()); err != nil {
			return NATProof{}, err
		}
		if _, err := natTimeKey(domain.At); err != nil {
			return NATProof{}, err
		}
	}
	if err := existingNATCatalog(before, after); err != nil {
		return NATProof{}, err
	}
	temporal := newSchedulePartition(from, limits.MaxCombinations, func(count int) error { return budget.take(ctx, count) })
	for _, graph := range graphs {
		for _, schedule := range graph.Schedules() {
			if err := temporal.add(schedule); err != nil {
				return NATProof{}, err
			}
		}
	}
	times, err := temporal.times()
	if err != nil {
		return NATProof{}, err
	}
	byTime := make(map[time.Time][]Request, len(times))
	for _, at := range times {
		byTime[at.UTC()] = nil
	}
	for _, domain := range domains {
		at := domain.At.UTC()
		if _, ok := byTime[at]; !ok {
			return NATProof{}, ErrInvalid
		}
		byTime[at] = append(byTime[at], domain)
	}
	// Only the target supplies scope/chain/zone/interface axes. Source graphs
	// contribute temporal boundaries, not unrelated native target identities.
	base, err := e.NATContexts(ctx, from, before, after)
	if err != nil {
		return NATProof{}, err
	}
	if err := budget.take(ctx, len(base)); err != nil {
		return NATProof{}, err
	}
	seenAxes := make(map[migrationNATAxis]bool)
	var axes []migrationNATAxis
	for _, q := range base {
		axis := migrationAxis(q)
		if !seenAxes[axis] {
			seenAxes[axis] = true
			axes = append(axes, axis)
		}
	}
	if len(times) != 0 && len(axes) > limits.MaxCombinations/len(times) {
		return NATProof{}, ErrBudget
	}
	all, err := flow.AllTraffic(limits.MaxRegions)
	if err != nil {
		return NATProof{}, err
	}
	count := 0
	for _, axis := range axes {
		for _, at := range times {
			if err := budget.take(ctx, 1); err != nil {
				return NATProof{}, err
			}
			q := axis.request(at, all)
			var authorized flow.Traffic
			for _, domain := range byTime[at.UTC()] {
				if err := budget.take(ctx, 1); err != nil {
					return NATProof{}, err
				}
				if !natIntentContext(domain, q) {
					continue
				}
				authorized, err = budget.union(ctx, authorized, domain.Traffic)
				if err != nil {
					return NATProof{}, err
				}
			}
			if err := budget.traffic(ctx, all, authorized); err != nil {
				return NATProof{}, err
			}
			q.Traffic, err = all.Difference(authorized, limits.MaxRegions)
			if err != nil {
				return NATProof{}, err
			}
			count++
			if q.Traffic.Empty() {
				continue
			}
			if err := budget.take(ctx, before.DeclarationSize(), after.DeclarationSize()); err != nil {
				return NATProof{}, err
			}
			prior, err := e.QueryNAT(ctx, before, q)
			if err != nil {
				return NATProof{}, err
			}
			next, err := e.QueryNAT(ctx, after, q)
			if err != nil {
				return NATProof{}, err
			}
			if !prior.Complete || !next.Complete || !prior.Unknown.Empty() || !next.Unknown.Empty() {
				return NATProof{}, ErrNotEquivalent
			}
			if same, err := budget.equal(ctx, prior.Unmatched, next.Unmatched); err != nil {
				return NATProof{}, err
			} else if !same {
				return NATProof{}, ErrNotEquivalent
			}
			left, err := migrationOutsidePartitions(ctx, prior.Relations, &budget)
			if err != nil {
				return NATProof{}, err
			}
			right, err := migrationOutsidePartitions(ctx, next.Relations, &budget)
			if err != nil {
				return NATProof{}, err
			}
			if len(left) != len(right) {
				return NATProof{}, ErrNotEquivalent
			}
			for key, traffic := range left {
				if same, err := budget.equal(ctx, traffic, right[key]); err != nil {
					return NATProof{}, err
				} else if !same {
					return NATProof{}, ErrNotEquivalent
				}
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return NATProof{}, err
	}
	return NATProof{BaseDigest: before.SemanticDigest(), ResultDigest: after.SemanticDigest(), OutsidePreserved: true, Contexts: count}, nil
}

func migrationOutsidePartitions(ctx context.Context, relations []NATRelation, budget *packetProofBudget) (map[string]flow.Traffic, error) {
	if len(relations) > budget.limits.MaxCombinations {
		return nil, ErrBudget
	}
	if err := budget.take(ctx, len(relations)); err != nil {
		return nil, err
	}
	var count int
	for _, relation := range relations {
		if err := budget.take(ctx, len(relation.Steps), relation.Original.RegionCount()); err != nil {
			return nil, err
		}
		if count > budget.limits.MaxRegions-relation.Original.RegionCount() {
			return nil, ErrBudget
		}
		count += relation.Original.RegionCount()
	}
	// natPartitions merges regions within each immutable native step identity.
	// Charge the worst possible pairwise union work before those merges.
	if count != 0 && count > budget.remaining/count {
		return nil, ErrBudget
	}
	if err := budget.take(ctx, count*count); err != nil {
		return nil, err
	}
	return natPartitions(relations, budget.limits.MaxRegions)
}
