package plan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/policy"
)

func universe(limit int) (flow.Traffic, error) {
	full := flow.Interval{Low: 0, High: 65535}
	octet := flow.Interval{Low: 0, High: 255}
	var boxes []flow.TrafficRegion
	for _, cidr := range []string{"0.0.0.0/0", "::/0"} {
		r, _ := flow.PrefixRange(netip.MustParsePrefix(cidr))
		boxes = append(boxes, flow.TrafficRegion{Source: r, Destination: r, Protocol: octet, SourcePort: full, DestinationPort: full, ICMPType: octet, ICMPCode: octet})
	}
	return flow.NewTraffic(limit, boxes...)
}

func equal(a, b flow.Traffic, limit int) (bool, error) {
	x, err := a.Difference(b, limit)
	if err != nil || !x.Empty() {
		return false, err
	}
	x, err = b.Difference(a, limit)
	return err == nil && x.Empty(), err
}

func (p Planner) prove(ctx context.Context, before, after *fm.Firewall, q policy.Request) (Proof, error) {
	visits := visitBudget(p.Engine.Limits.WithDefaults().MaxVisits)
	return p.proveWithPrior(ctx, before, after, q, nil, &visits)
}

func (p Planner) proveWithPrior(ctx context.Context, before, after *fm.Firewall, q policy.Request, prior *policy.Result, visits *visitBudget) (Proof, error) {
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
	if err := p.Engine.PreserveNAT(ctx, before, after, q.At); err != nil {
		return Proof{}, err
	}
	target, err := p.Engine.Query(ctx, after, q)
	if err != nil {
		return Proof{}, err
	}
	covered, err := target.Allowed.Contains(q.Traffic, limit)
	if err != nil {
		return Proof{}, err
	}
	if !covered || !target.Complete || !target.Unknown.Empty() {
		return Proof{}, ErrUnsafe
	}
	all := q
	all.Traffic, err = universe(limit)
	if err != nil {
		return Proof{}, err
	}
	if prior == nil {
		if err := visits.take(ctx, before.RuleCount()); err != nil {
			return Proof{}, err
		}
		result, err := p.Engine.Query(ctx, before, all)
		if err != nil {
			return Proof{}, err
		}
		prior = &result
	}
	if err := visits.take(ctx, after.RuleCount()); err != nil {
		return Proof{}, err
	}
	next, err := p.Engine.Query(ctx, after, all)
	if err != nil {
		return Proof{}, err
	}
	if !prior.Complete || !next.Complete {
		return Proof{}, ErrUnsafe
	}
	// Preserve effective ownership outside the target, including logging/order.
	if err := preservedOutside(ctx, *prior, next, q.Traffic, limit, visits); err != nil {
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
