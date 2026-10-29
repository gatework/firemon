package plan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/policy"
)

func (p Planner) prove(ctx context.Context, before, after *fm.Firewall, q policy.Request) (Proof, error) {
	visits := visitBudget(p.Engine.Limits.WithDefaults().MaxVisits)
	return p.proveWithBaseline(ctx, before, after, q, nil, &visits)
}

func (p Planner) proveWithBaseline(ctx context.Context, before, after *fm.Firewall, q policy.Request, baselineResult *policy.Result, visits *visitBudget) (Proof, error) {
	if err := ctx.Err(); err != nil {
		return Proof{}, err
	}
	if before == nil || after == nil || !before.Complete() || !after.Complete() {
		return Proof{}, ErrUnsafe
	}
	limit := p.Engine.Limits.WithDefaults().MaxRegions
	if err := visits.take(ctx, after.RuleCount()); err != nil {
		return Proof{}, err
	}
	// NAT ownership and translation preservation are independent of target coverage.
	if err := p.Engine.PreserveNAT(ctx, before, after, q.At); err != nil {
		return Proof{}, err
	}
	// Establish the requested allowed coverage before comparing outside ownership.
	targetResult, err := p.Engine.Query(ctx, after, q)
	if err != nil {
		return Proof{}, err
	}
	covered, err := targetResult.Allowed.Contains(q.Traffic, limit)
	if err != nil {
		return Proof{}, err
	}
	if !covered || !targetResult.Complete || !targetResult.Unknown.Empty() {
		return Proof{}, ErrUnsafe
	}
	contextRequest := q
	contextRequest.Traffic, err = flow.AllTraffic(limit)
	if err != nil {
		return Proof{}, err
	}
	if baselineResult == nil {
		if err := visits.take(ctx, before.RuleCount()); err != nil {
			return Proof{}, err
		}
		result, err := p.Engine.Query(ctx, before, contextRequest)
		if err != nil {
			return Proof{}, err
		}
		baselineResult = &result
	}
	if err := visits.take(ctx, after.RuleCount()); err != nil {
		return Proof{}, err
	}
	candidateResult, err := p.Engine.Query(ctx, after, contextRequest)
	if err != nil {
		return Proof{}, err
	}
	if !baselineResult.Complete || !candidateResult.Complete {
		return Proof{}, ErrUnsafe
	}
	// Preserve effective ownership outside the target, including logging/order.
	if err := preserveOutsideTargetOwnership(ctx, *baselineResult, candidateResult, q.Traffic, limit, visits); err != nil {
		return Proof{}, err
	}
	return Proof{BaseDigest: before.SemanticDigest(), ResultDigest: after.SemanticDigest(), TargetAllowed: true, TargetSatisfied: true, OutsidePreserved: true, NATUnchanged: true}, nil
}

func (p *Plan) seal() error {
	type transfer struct {
		Intent  RuleIntent
		Traffic []flow.TrafficRegion
	}
	targets := make([]transfer, 0, len(p.transfers))
	for _, intent := range p.transfers {
		targets = append(targets, transfer{intent, intent.Request.Traffic.Regions()})
	}
	b, err := json.Marshal(struct {
		Proof        Proof
		Changes      []Change
		Commands     []string
		Target       policy.Request
		Traffic      []flow.TrafficRegion
		Preservation *policy.Equivalence
		Transfers    []transfer
		TransferFrom time.Time
	}{p.proof, p.changes, p.commands, p.target, p.target.Traffic.Regions(), p.preservation, targets, p.transferFrom})
	if err != nil {
		return err
	}
	sum := sha256.Sum256(b)
	p.digest = hex.EncodeToString(sum[:])
	return nil
}
