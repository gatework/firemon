package operations

import (
	"context"
	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/plan"
)

// A native policy proof alone is insufficient when permitting the packet enables
// post-policy NAT. Re-evaluate wire paths on the complete final device graph.
func (r *batchRun) recheck(ctx context.Context, fw *fm.Firewall, work []batchWork, batch plan.BatchResult) (bool, error) {
	limit := r.designer.options.Engine.Limits.WithDefaults().MaxRegions
	for i, w := range work {
		if w.packet == nil || i >= len(batch.Inputs) || batch.Inputs[i].Disposition == plan.BatchRejected {
			continue
		}
		if err := r.charge(ctx); err != nil {
			return false, err
		}
		packet := *w.packet
		if w.native != nil && w.native.Lifetime != nil {
			// The native planner proves every active interval. This final business
			// view check must sample admission inside the window too, while keeping
			// original input times intact for review and reconstruction.
			packet.At = w.native.Lifetime.Window.Start
		}
		result, err := r.designer.options.Engine.QueryPacket(ctx, fw, packet)
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
			if w.viewTraffic != nil {
				actual, known := p.View(w.view)
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
		same, err := wire.Equal(w.packet.Traffic, limit)
		if err != nil {
			return false, err
		}
		if !same {
			return false, nil
		}
		if w.viewTraffic != nil {
			same, err = translated.Equal(*w.viewTraffic, limit)
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
