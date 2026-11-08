package policy

import (
	"context"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
)

// PacketEquivalence proves one explicit wire request through two native packet
// pipelines. It does not prove other traffic, other times, or live sessions.
type PacketEquivalence struct {
	SourceDigest, TargetDigest string
	At                         time.Time
	SourcePaths, TargetPaths   int
	Partitions                 int
}

type packetPolicyEffect struct {
	Action                fm.Action
	Log, LogStart, LogEnd fm.Status
}

type packetEffectKey struct {
	policy packetPolicyEffect
	nat    string
}

type packetProofBudget struct {
	limits    Limits
	remaining int
}

func (b *packetProofBudget) take(ctx context.Context, counts ...int) error {
	return chargeVisits(ctx, &b.remaining, counts...)
}

func (b *packetProofBudget) traffic(ctx context.Context, a, c flow.Traffic) error {
	x, y := a.RegionCount(), c.RegionCount()
	if x > b.limits.MaxRegions || y > b.limits.MaxRegions {
		return ErrBudget
	}
	if err := b.take(ctx, x, y); err != nil {
		return err
	}
	if x != 0 && y > b.remaining/x {
		return ErrBudget
	}
	return b.take(ctx, x*y)
}

func (b *packetProofBudget) equal(ctx context.Context, a, c flow.Traffic) (bool, error) {
	if err := b.traffic(ctx, a, c); err != nil {
		return false, err
	}
	return a.Equal(c, b.limits.MaxRegions)
}

func (b *packetProofBudget) union(ctx context.Context, a, c flow.Traffic) (flow.Traffic, error) {
	if err := b.traffic(ctx, a, c); err != nil {
		return flow.Traffic{}, err
	}
	return a.Union(c, b.limits.MaxRegions)
}

func (b *packetProofBudget) disjoint(ctx context.Context, a, c flow.Traffic) error {
	if err := b.traffic(ctx, a, c); err != nil {
		return err
	}
	overlap, err := a.Intersection(c, b.limits.MaxRegions)
	if err != nil {
		return err
	}
	if !overlap.Empty() {
		return ErrNotEquivalent
	}
	return nil
}

// EquivalentPacketEffects compares policy effects and the ordered original-to-
// translated relation, allowing native object and zone names to differ. Both
// requests must supply the same wire traffic and instant, explicit ingress and
// post-route destination zones, and complete native evidence. Unmatched policy,
// unknown logging, reverse NAT, and ambiguous policy-coordinate projections are
// rejected. Dynamic allocation modes and pools remain possibilities, never an
// observed session mapping.
func (e Engine) EquivalentPacketEffects(ctx context.Context, source, target *fm.Firewall, sourceRequest, targetRequest PacketRequest) (PacketEquivalence, error) {
	if err := ctx.Err(); err != nil {
		return PacketEquivalence{}, err
	}
	if source == nil || target == nil || sourceRequest.Traffic.Empty() || targetRequest.Traffic.Empty() {
		return PacketEquivalence{}, ErrInvalid
	}
	if !source.Complete() || !target.Complete() || !sourceRequest.At.Equal(targetRequest.At) {
		return PacketEquivalence{}, ErrNotEquivalent
	}
	for _, q := range []PacketRequest{sourceRequest, targetRequest} {
		if q.FromZone == "" || q.ToZone == "" {
			return PacketEquivalence{}, ErrNotEquivalent
		}
	}
	limits := e.Limits.WithDefaults()
	budget := packetProofBudget{limits: limits, remaining: limits.MaxVisits}
	// No catalog export or packet expansion happens before this nested-work
	// preflight. The immutable graph caches its structural size at sealing.
	if err := budget.take(ctx, source.DeclarationSize(), target.DeclarationSize()); err != nil {
		return PacketEquivalence{}, err
	}
	if same, err := budget.equal(ctx, sourceRequest.Traffic, targetRequest.Traffic); err != nil {
		return PacketEquivalence{}, err
	} else if !same {
		return PacketEquivalence{}, ErrNotEquivalent
	}
	left, err := e.QueryPacket(ctx, source, sourceRequest)
	if err != nil {
		return PacketEquivalence{}, err
	}
	if err := ctx.Err(); err != nil {
		return PacketEquivalence{}, err
	}
	right, err := e.QueryPacket(ctx, target, targetRequest)
	if err != nil {
		return PacketEquivalence{}, err
	}
	a, err := packetEffectPartitions(ctx, source, sourceRequest, left, &budget)
	if err != nil {
		return PacketEquivalence{}, err
	}
	b, err := packetEffectPartitions(ctx, target, targetRequest, right, &budget)
	if err != nil {
		return PacketEquivalence{}, err
	}
	if len(a) != len(b) {
		return PacketEquivalence{}, ErrNotEquivalent
	}
	for key, original := range a {
		if same, err := budget.equal(ctx, original, b[key]); err != nil {
			return PacketEquivalence{}, err
		} else if !same {
			return PacketEquivalence{}, ErrNotEquivalent
		}
	}
	if err := ctx.Err(); err != nil {
		return PacketEquivalence{}, err
	}
	return PacketEquivalence{SourceDigest: source.SemanticDigest(), TargetDigest: target.SemanticDigest(), At: sourceRequest.At, SourcePaths: len(left.Paths), TargetPaths: len(right.Paths), Partitions: len(a)}, nil
}

func packetEffectPartitions(ctx context.Context, fw *fm.Firewall, request PacketRequest, result PacketResult, budget *packetProofBudget) (map[packetEffectKey]flow.Traffic, error) {
	if !result.Complete || !result.Unknown.Empty() || len(result.Paths) == 0 {
		return nil, ErrNotEquivalent
	}
	if len(result.Paths) > budget.limits.MaxCombinations {
		return nil, ErrBudget
	}
	if err := budget.take(ctx, len(result.Paths)); err != nil {
		return nil, err
	}
	out := make(map[packetEffectKey]flow.Traffic)
	steps := make(map[NATStep]migrationStepView)
	rules := make(map[fm.ID]packetPolicyEffect)
	var covered flow.Traffic
	for _, path := range result.Paths {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if path.Original.Empty() || path.FromZone != request.FromZone || path.ToZone != request.ToZone || len(path.NativeRequests) != 1 {
			return nil, ErrNotEquivalent
		}
		native := path.NativeRequests[0]
		if native.Scope != request.Scope || native.FromZone != path.FromZone || native.ToZone != path.ToZone || request.EgressInterface != "" && request.EgressInterface != native.EgressInterface {
			return nil, ErrNotEquivalent
		}
		if err := budget.disjoint(ctx, covered, path.Original); err != nil {
			return nil, err
		}
		var err error
		covered, err = budget.union(ctx, covered, path.Original)
		if err != nil {
			return nil, err
		}
		signature, destinationRewrite, err := migrationRelation(ctx, fw, path, steps, budget)
		if err != nil {
			return nil, err
		}
		effects, err := packetPolicyPartitions(ctx, fw, native.Traffic, path.Policy, rules, budget)
		if err != nil {
			return nil, err
		}
		identity, err := budget.equal(ctx, native.Traffic, path.Original)
		if err != nil {
			return nil, err
		}
		// Equal projected sets alone do not prove coordinate identity: DNAT can
		// permute addresses while retaining the same union. Without a strict
		// preimage, only a homogeneous effect can be assigned to the wire domain.
		identity = identity && !destinationRewrite
		if !identity && len(effects) != 1 {
			return nil, ErrNotEquivalent
		}
		for effect, traffic := range effects {
			if !identity {
				traffic = path.Original
			}
			key := packetEffectKey{policy: effect, nat: signature}
			if _, exists := out[key]; !exists && len(out) >= budget.limits.MaxCombinations {
				return nil, ErrBudget
			}
			out[key], err = budget.union(ctx, out[key], traffic)
			if err != nil {
				return nil, err
			}
		}
	}
	if same, err := budget.equal(ctx, covered, request.Traffic); err != nil {
		return nil, err
	} else if !same {
		return nil, ErrNotEquivalent
	}
	return out, nil
}

func packetPolicyPartitions(ctx context.Context, fw *fm.Firewall, native flow.Traffic, result Result, rules map[fm.ID]packetPolicyEffect, budget *packetProofBudget) (map[packetPolicyEffect]flow.Traffic, error) {
	if !result.Complete || !result.Unknown.Empty() || !result.Unmatched.Empty() || native.Empty() {
		return nil, ErrNotEquivalent
	}
	if len(result.Decisions) > budget.limits.MaxCombinations {
		return nil, ErrBudget
	}
	if err := budget.take(ctx, len(result.Decisions)); err != nil {
		return nil, err
	}
	out := make(map[packetPolicyEffect]flow.Traffic)
	var covered, allowed, denied flow.Traffic
	for _, decision := range result.Decisions {
		if !decision.Known || !decision.Action.Valid() || decision.Traffic.Empty() {
			return nil, ErrNotEquivalent
		}
		effect, ok := rules[decision.Rule]
		if !ok {
			if err := budget.take(ctx, fw.DeclarationSize()); err != nil {
				return nil, err
			}
			rule := fw.Rule(decision.Rule)
			if rule == nil {
				return nil, ErrNotEquivalent
			}
			r := rule.Record()
			for _, status := range []fm.Status{r.Log, r.LogStart, r.LogEnd} {
				if status != fm.Known && status != fm.Irrelevant {
					return nil, ErrNotEquivalent
				}
			}
			effect = packetPolicyEffect{Action: r.Action, Log: r.Log, LogStart: r.LogStart, LogEnd: r.LogEnd}
			rules[decision.Rule] = effect
		}
		if effect.Action != decision.Action {
			return nil, ErrNotEquivalent
		}
		if err := budget.disjoint(ctx, covered, decision.Traffic); err != nil {
			return nil, err
		}
		var err error
		covered, err = budget.union(ctx, covered, decision.Traffic)
		if err != nil {
			return nil, err
		}
		if effect.Action == fm.Permit {
			allowed, err = budget.union(ctx, allowed, decision.Traffic)
		} else {
			denied, err = budget.union(ctx, denied, decision.Traffic)
		}
		if err != nil {
			return nil, err
		}
		out[effect], err = budget.union(ctx, out[effect], decision.Traffic)
		if err != nil {
			return nil, err
		}
	}
	for _, pair := range [][2]flow.Traffic{{covered, native}, {allowed, result.Allowed}, {denied, result.Denied}} {
		if same, err := budget.equal(ctx, pair[0], pair[1]); err != nil {
			return nil, err
		} else if !same {
			return nil, ErrNotEquivalent
		}
	}
	return out, nil
}
