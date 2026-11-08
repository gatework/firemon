package operations

import (
	"context"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/plan"
)

func (r *targetBatch) evaluate(ctx context.Context, input int, proposal targetProposal) ([]*targetEntry, error) {
	window := r.inputs[input].request.Window
	if window == nil || proposal.window != nil {
		return r.evaluateAt(ctx, input, proposal)
	}
	fw, err := r.load(ctx, input, proposal.traffic, "original", proposal.target, proposal.sources)
	if err != nil || fw == nil {
		return nil, err
	}
	if err := r.chargeGraph(ctx, fw); err != nil {
		return nil, err
	}
	windows, err := r.engine.Windows(ctx, fw, *window)
	if err != nil {
		return nil, err
	}
	var entries []*targetEntry
	for _, w := range windows {
		p := proposal
		p.window = &w
		p.target.Request.At = w.Start
		part, err := r.evaluateAt(ctx, input, p)
		if err != nil {
			return nil, err
		}
		entries = append(entries, part...)
	}
	return entries, ctx.Err()
}

func (r *targetBatch) times(ctx context.Context, fw *fm.Firewall, a AccessRequest) ([]fm.TimeWindow, error) {
	if a.Window == nil {
		return []fm.TimeWindow{{Start: a.At}}, nil
	}
	if err := r.chargeGraph(ctx, fw); err != nil {
		return nil, err
	}
	return r.engine.Windows(ctx, fw, *a.Window)
}

func (r *targetBatch) admit(work []*targetEntry) []*targetEntry {
	admitted := make([]*targetEntry, 0, len(work))
	for _, entry := range work {
		input := r.inputs[entry.origin.input]
		if entry.outcome.Conditional {
			continue
		}
		if input.normalized != nil && !input.normalized.ServiceSpecified {
			r.issue(input.index, entry.outcome.Device, "design", "service_required", entry.outcome.Wire, entry.trafficView, nil, "a query without service does not authorize an unrestricted policy")
			continue
		}
		if input.request.Window != nil && entry.planning.native == nil {
			if entry.outcome.Disposition == plan.BatchCovered {
				continue
			}
			fw := r.graphs[entry.outcome.Revision]
			clock, ok := r.clocks[entry.outcome.Device]
			if !ok || clock.Validate(fw.Metadata()) != nil {
				r.issue(input.index, entry.outcome.Device, "design", "clock_required", entry.outcome.Wire, entry.trafficView, nil, "finite policy needs capture-bound device clock evidence")
				continue
			}
			entry.planning.native = scheduledInput(entry, input, clock)
		}
		admitted = append(admitted, entry)
	}
	return admitted
}
