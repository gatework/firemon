package policy

import (
	"context"

	fm "github.com/gatework/firemon"
)

// AppendCanPreserve is a rejection filter for an expanded existing rule. It
// returns false when traffic outside q changes ownership. A true result still
// requires the caller's complete plan proof and native rendering.
func (e Engine) AppendCanPreserve(ctx context.Context, before, after *fm.Firewall, id fm.ID, q Request, prior Result) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if before == nil || after == nil || before.Rule(id) == nil || after.Rule(id) == nil {
		return false, ErrInvalid
	}
	if !semantics(before.Metadata().Vendor).linearPolicy {
		return true, nil
	}
	all, err := allTraffic(e.Limits.WithDefaults().MaxRegions)
	if err != nil {
		return false, err
	}
	expanded, known, err := e.Match(ctx, after, after.Rule(id).Record().Match, q, all)
	if err != nil || !known {
		return true, err
	}
	outside, err := expanded.Difference(q.Traffic, e.Limits.WithDefaults().MaxRegions)
	if err != nil {
		return false, err
	}
	rule := before.Rule(id).Record()
	for _, trace := range prior.Trace {
		if outside.Empty() {
			return true, nil
		}
		if err := ctx.Err(); err != nil {
			return false, err
		}
		owner := before.Rule(trace.Rule)
		if owner == nil {
			return false, ErrNotEquivalent
		}
		r := owner.Record()
		if r.Position > rule.Position || r.Position == rule.Position && r.ID > rule.ID {
			continue
		}
		outside, err = outside.Difference(trace.Traffic, e.Limits.WithDefaults().MaxRegions)
		if err != nil {
			return false, err
		}
	}
	return outside.Empty(), nil
}
