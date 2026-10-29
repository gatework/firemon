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

func universe() flow.Traffic {
	full := flow.Interval{Low: 0, High: 65535}
	octet := flow.Interval{Low: 0, High: 255}
	var boxes []flow.Box
	for _, cidr := range []string{"0.0.0.0/0", "::/0"} {
		r, _ := flow.PrefixRange(netip.MustParsePrefix(cidr))
		boxes = append(boxes, flow.Box{Source: r, Destination: r, Protocol: octet, SourcePort: full, DestinationPort: full, ICMPType: octet, ICMPCode: octet})
	}
	result, _ := flow.NewTraffic(4096, boxes...)
	return result
}

func equal(a, b flow.Traffic) (bool, error) {
	x, err := a.Difference(b, 4096)
	if err != nil || !x.Empty() {
		return false, err
	}
	x, err = b.Difference(a, 4096)
	return err == nil && x.Empty(), err
}

func (p Planner) prove(ctx context.Context, before, after *fm.Firewall, q policy.Request) (Proof, error) {
	return p.proveWithPrior(ctx, before, after, q, nil)
}

func (p Planner) proveWithPrior(ctx context.Context, before, after *fm.Firewall, q policy.Request, prior *policy.Result) (Proof, error) {
	if before == nil || after == nil || !before.Complete() || !after.Complete() {
		return Proof{}, ErrUnsafe
	}
	if err := p.Engine.PreserveNAT(ctx, before, after, q.At); err != nil {
		return Proof{}, err
	}
	target, err := p.Engine.Query(ctx, after, q)
	if err != nil {
		return Proof{}, err
	}
	covered, err := target.Allowed.Contains(q.Traffic, 4096)
	if err != nil {
		return Proof{}, err
	}
	if !covered || !target.Complete || !target.Unknown.Empty() {
		return Proof{}, ErrUnsafe
	}
	all := q
	all.Traffic = universe()
	if prior == nil {
		result, err := p.Engine.Query(ctx, before, all)
		if err != nil {
			return Proof{}, err
		}
		prior = &result
	}
	next, err := p.Engine.Query(ctx, after, all)
	if err != nil {
		return Proof{}, err
	}
	if !prior.Complete || !next.Complete {
		return Proof{}, ErrUnsafe
	}
	// Compare effective rule ownership too: equal permit coverage alone does not preserve logging/order.
	traces := make(map[fm.ID]flow.Traffic)
	for _, trace := range next.Trace {
		traces[trace.Rule] = trace.Traffic
	}
	for _, trace := range prior.Trace {
		old, err := trace.Traffic.Difference(q.Traffic, 4096)
		if err != nil {
			return Proof{}, err
		}
		new, err := traces[trace.Rule].Difference(q.Traffic, 4096)
		if err != nil {
			return Proof{}, err
		}
		same, err := equal(old, new)
		if err != nil {
			return Proof{}, err
		}
		if !same {
			return Proof{}, ErrUnsafe
		}
		delete(traces, trace.Rule)
	}
	for _, trace := range traces {
		outside, err := trace.Difference(q.Traffic, 4096)
		if err != nil {
			return Proof{}, err
		}
		if !outside.Empty() {
			return Proof{}, ErrUnsafe
		}
	}
	old, err := prior.Unmatched.Difference(q.Traffic, 4096)
	if err != nil {
		return Proof{}, err
	}
	new, err := next.Unmatched.Difference(q.Traffic, 4096)
	if err != nil {
		return Proof{}, err
	}
	same, err := equal(old, new)
	if err != nil {
		return Proof{}, err
	}
	if !same {
		return Proof{}, ErrUnsafe
	}
	return Proof{BaseDigest: before.SemanticDigest(), ResultDigest: after.SemanticDigest(), TargetAllowed: true, TargetSatisfied: true, OutsidePreserved: true, NATUnchanged: true}, nil
}

func (p *Plan) seal() error {
	type transfer struct {
		Intent  RuleIntent
		Traffic []flow.Box
	}
	targets := make([]transfer, 0, len(p.transfers))
	for _, intent := range p.transfers {
		targets = append(targets, transfer{intent, intent.Request.Traffic.Boxes()})
	}
	b, err := json.Marshal(struct {
		Proof        Proof
		Changes      []Change
		Commands     []string
		Target       policy.Request
		Traffic      []flow.Box
		Preservation *policy.Equivalence
		Transfers    []transfer
		TransferFrom time.Time
	}{p.proof, p.changes, p.commands, p.target, p.target.Traffic.Boxes(), p.preservation, targets, p.transferFrom})
	if err != nil {
		return err
	}
	sum := sha256.Sum256(b)
	p.digest = hex.EncodeToString(sum[:])
	return nil
}
