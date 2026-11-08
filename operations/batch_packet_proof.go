package operations

import (
	"context"
	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/plan"
)

// A native policy proof alone is insufficient when permitting the packet enables
// post-policy NAT. Re-evaluate wire paths on the complete final device graph.
func (r *targetBatch) recheck(ctx context.Context, fw *fm.Firewall, work []*targetEntry, batch plan.BatchResult) (bool, error) {
	limit := r.engine.Limits.WithDefaults().MaxRegions
	for i, w := range work {
		if w.proof == nil || i >= len(batch.Inputs) || batch.Inputs[i].Disposition == plan.BatchRejected {
			continue
		}
		if err := r.charge(ctx); err != nil {
			return false, err
		}
		proof := w.proof
		packet := proof.packet
		if w.planning.native != nil && w.planning.native.Lifetime != nil {
			// The native planner proves every active interval. This final business
			// view check must sample admission inside the window too, while keeping
			// original input times intact for review and reconstruction.
			packet.At = w.planning.native.Lifetime.Window.Start
		}
		result, err := r.engine.QueryPacket(ctx, fw, packet)
		if err != nil {
			if fatalBatch(err) {
				return false, err
			}
			return false, nil
		}
		if !result.Complete || !result.Unknown.Empty() {
			return false, nil
		}
		var wire, translated flow.Traffic
		for _, p := range result.Paths {
			if !p.Policy.Complete || !p.Policy.Unknown.Empty() || !p.Policy.Denied.Empty() || !p.Policy.Unmatched.Empty() || p.Policy.Allowed.Empty() {
				return false, nil
			}
			wire, err = wire.Union(p.Original, limit)
			if err != nil {
				return false, err
			}
			if proof.expected != nil {
				actual, known := p.View(proof.expected.view)
				if !known {
					return false, nil
				}
				same, err := p.NAT.Original.Equal(p.Original, limit)
				if err != nil {
					return false, err
				}
				if !same {
					return false, nil
				}
				translated, err = translated.Union(actual, limit)
				if err != nil {
					return false, err
				}
			}
		}
		same, err := wire.Equal(proof.packet.Traffic, limit)
		if err != nil {
			return false, err
		}
		if !same {
			return false, nil
		}
		if proof.expected != nil {
			same, err = translated.Equal(proof.expected.traffic, limit)
			if err != nil {
				return false, err
			}
			if !same {
				return false, nil
			}
		}
	}
	return true, ctx.Err()
}
