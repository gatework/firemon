package policy

import (
	"context"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
)

// OriginalTraffic returns the exact original-wire preimage of selected policy
// traffic in a retained packet path. Selection uses path.Policy coordinates,
// which can differ from NativeRequests (for example, Fortinet VIPs). The result
// is restricted to path.Original; constants never invent additional senders or
// destinations. Unknown transformations and selections outside the established
// policy domain fail instead of widening the result.
func (e Engine) OriginalTraffic(ctx context.Context, fw *fm.Firewall, path PacketPath, selected flow.Traffic) (flow.Traffic, error) {
	if err := ctx.Err(); err != nil {
		return flow.Traffic{}, err
	}
	if fw == nil || path.Original.Empty() {
		return flow.Traffic{}, ErrInvalid
	}
	limits := e.Limits.WithDefaults()
	budget := packetProofBudget{limits: limits, remaining: limits.MaxVisits}
	if err := budget.traffic(ctx, path.Original, selected); err != nil {
		return flow.Traffic{}, err
	}
	mapping, err := policyCoordinates(ctx, fw, path, &budget)
	if err != nil {
		return flow.Traffic{}, err
	}
	return mapping.original(ctx, selected, &budget)
}

// Each stage retains its input domain. This makes many-to-one and compound
// translations reversible as relations without assuming a one-to-one session.
type policyNATStage struct {
	transform natTransform
	original  flow.Traffic
}

type policyMapping struct {
	traffic flow.Traffic
	stages  []policyNATStage
}

func policyCoordinates(ctx context.Context, fw *fm.Firewall, path PacketPath, budget *packetProofBudget) (policyMapping, error) {
	if len(path.PolicyNAT) > budget.limits.MaxCombinations || path.Original.RegionCount() > budget.limits.MaxRegions {
		return policyMapping{}, ErrBudget
	}
	if err := budget.take(ctx, len(path.PolicyNAT), path.Original.RegionCount()); err != nil {
		return policyMapping{}, err
	}
	mapping := policyMapping{traffic: path.Original}
	for _, step := range path.PolicyNAT {
		// Record access copies nested declarations; charge before taking them.
		if err := budget.take(ctx, fw.DeclarationSize()); err != nil {
			return policyMapping{}, err
		}
		n, err := transform(fw, step)
		if err != nil {
			return policyMapping{}, err
		}
		if !n.known || n.disabled {
			return policyMapping{}, ErrNAT
		}
		if n.dynamic != nil {
			r := n.dynamic.Record()
			if r.DestinationMode != fm.NoTranslation && (r.DestinationMode != fm.StaticIP || len(n.destination) == 0) {
				return policyMapping{}, ErrNAT
			}
		}
		n = destinationTransform(n)
		mapping.stages = append(mapping.stages, policyNATStage{transform: n, original: mapping.traffic})
		if err := budget.mapping(ctx, mapping.traffic, len(n.destination)); err != nil {
			return policyMapping{}, err
		}
		mapping.traffic, err = mapTraffic(mapping.traffic, n.destination, false, budget.limits.MaxRegions)
		if err != nil {
			return policyMapping{}, err
		}
		if err := budget.mapping(ctx, mapping.traffic, len(n.destinationPorts)); err != nil {
			return policyMapping{}, err
		}
		mapping.traffic, err = mapPorts(mapping.traffic, n.destinationPorts, false, budget.limits.MaxRegions)
		if err != nil {
			return policyMapping{}, err
		}
	}
	return mapping, ctx.Err()
}

func (m policyMapping) original(ctx context.Context, selected flow.Traffic, budget *packetProofBudget) (flow.Traffic, error) {
	if err := budget.traffic(ctx, selected, m.traffic); err != nil {
		return flow.Traffic{}, err
	}
	outside, err := selected.Difference(m.traffic, budget.limits.MaxRegions)
	if err != nil {
		return flow.Traffic{}, err
	}
	if !outside.Empty() {
		return flow.Traffic{}, ErrNAT
	}
	for i := len(m.stages) - 1; i >= 0; i-- {
		stage := m.stages[i]
		// The inverse considers address/port pairs, then unions and intersects
		// them with the retained stage input. Bound that work before expansion.
		count, err := budget.product(ctx, selected.RegionCount(), max(1, len(stage.transform.destination)), max(1, len(stage.transform.destinationPorts)))
		if err != nil {
			return flow.Traffic{}, err
		}
		if _, err := budget.product(ctx, count, count); err != nil {
			return flow.Traffic{}, err
		}
		if _, err := budget.product(ctx, count, stage.original.RegionCount()); err != nil {
			return flow.Traffic{}, err
		}
		selected, err = destinationPreimage(stage.transform, stage.original, selected, budget.limits.MaxRegions)
		if err != nil {
			return flow.Traffic{}, err
		}
	}
	if err := ctx.Err(); err != nil {
		return flow.Traffic{}, err
	}
	return selected, nil
}

func (b *packetProofBudget) mapping(ctx context.Context, traffic flow.Traffic, mappings int) error {
	if traffic.RegionCount() > b.limits.MaxRegions {
		return ErrBudget
	}
	if mappings == 0 {
		return b.take(ctx, traffic.RegionCount())
	}
	count, err := b.product(ctx, traffic.RegionCount(), mappings)
	if err != nil {
		return err
	}
	_, err = b.product(ctx, count, count)
	return err
}

func (b *packetProofBudget) product(ctx context.Context, factors ...int) (int, error) {
	count := 1
	for _, n := range factors {
		if n != 0 && count > b.remaining/n {
			return 0, ErrBudget
		}
		count *= n
	}
	return count, b.take(ctx, count)
}
