package plan

import (
	"context"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/policy"
)

// PreflightNativeRequests bounds caller-owned containers before cloning,
// validating ownership, or constructing graphs. It does not validate semantics.
// This ingress allowance is independent of candidate/query/proof allowances.
// Callers adapting business inputs must also charge their own wrapper containers.
func PreflightNativeRequests(ctx context.Context, requests []NativeRequest, limits policy.Limits) error {
	limits = limits.WithDefaults()
	remaining := visitBudget(limits.MaxVisits)
	if err := remaining.take(ctx, len(requests)); err != nil {
		return err
	}
	for _, r := range requests {
		if err := remaining.nativeCounts(ctx, len(r.Sources), len(r.NAT)); err != nil {
			return err
		}
		if err := remaining.nativeTraffic(ctx, r.Request.Traffic, limits.MaxRegions); err != nil {
			return err
		}
		if r.Packet != nil {
			if err := remaining.nativeTraffic(ctx, r.Packet.Traffic, limits.MaxRegions); err != nil {
				return err
			}
		}
		for _, intent := range r.NAT {
			if err := remaining.take(ctx, len(intent.Steps)); err != nil {
				return err
			}
			if err := remaining.nativeTraffic(ctx, intent.Request.Traffic, limits.MaxRegions); err != nil {
				return err
			}
		}
		if err := remaining.nativeAdditions(ctx, r.Additions); err != nil {
			return err
		}
	}
	return ctx.Err()
}

// Subtract each length individually: summing caller-controlled lengths can
// overflow before a budget comparison. Even zero-size charges check cancellation.
func (b *visitBudget) nativeCounts(ctx context.Context, counts ...int) error {
	for _, count := range counts {
		if err := b.take(ctx, count); err != nil {
			return err
		}
	}
	return nil
}
func (b *visitBudget) nativeTraffic(ctx context.Context, t flow.Traffic, maxRegions int) error {
	if err := b.take(ctx, t.RegionCount()); err != nil {
		return err
	}
	if t.RegionCount() > maxRegions {
		return policy.ErrBudget
	}
	return nil
}
func (b *visitBudget) nativeObject(ctx context.Context, o fm.Object) error {
	return b.nativeCounts(ctx, len(o.Spans), len(o.Unsupported))
}
func (b *visitBudget) nativeMatch(ctx context.Context, m fm.Match) error {
	return b.nativeCounts(ctx, len(m.Sources), len(m.Destinations), len(m.Services), len(m.FromZones), len(m.ToZones), len(m.Applications), len(m.Users), len(m.Unsupported))
}
func (b *visitBudget) nativeAdditions(ctx context.Context, a NativeAdditions) error {
	// Pay for every outer container before traversing its records.
	if err := b.nativeCounts(ctx, len(a.Rules), len(a.Addresses), len(a.Services), len(a.StaticNATs), len(a.DynamicNATs), len(a.NATPools), len(a.Schedules)); err != nil {
		return err
	}
	for _, r := range a.Rules {
		if err := b.nativeObject(ctx, r.Object); err != nil {
			return err
		}
		if err := b.nativeMatch(ctx, r.Match); err != nil {
			return err
		}
	}
	for _, r := range a.Addresses {
		if err := b.nativeObject(ctx, r.Object); err != nil {
			return err
		}
		if err := b.take(ctx, len(r.Ranges)); err != nil {
			return err
		}
	}
	for _, r := range a.Services {
		if err := b.nativeObject(ctx, r.Object); err != nil {
			return err
		}
		if err := b.take(ctx, len(r.Terms)); err != nil {
			return err
		}
	}
	for _, r := range a.StaticNATs {
		if err := b.nativeObject(ctx, r.Object); err != nil {
			return err
		}
		if err := b.nativeMatch(ctx, r.Match); err != nil {
			return err
		}
		if err := b.nativeCounts(ctx, len(r.Source), len(r.Destination), len(r.SourcePorts), len(r.DestinationPorts)); err != nil {
			return err
		}
	}
	for _, r := range a.DynamicNATs {
		if err := b.nativeObject(ctx, r.Object); err != nil {
			return err
		}
		if err := b.nativeMatch(ctx, r.Match); err != nil {
			return err
		}
		if err := b.nativeCounts(ctx, len(r.Destination), len(r.SourcePorts), len(r.DestinationPorts)); err != nil {
			return err
		}
	}
	for _, r := range a.Schedules {
		if err := b.nativeObject(ctx, r.Object); err != nil {
			return err
		}
		if err := b.nativeCounts(ctx, len(r.Windows), len(r.Weekly)); err != nil {
			return err
		}
		for _, period := range r.Weekly {
			if err := b.take(ctx, len(period.Windows)); err != nil {
				return err
			}
		}
	}
	for _, r := range a.NATPools {
		if err := b.nativeObject(ctx, r.Object); err != nil {
			return err
		}
		if err := b.take(ctx, len(r.Ranges)); err != nil {
			return err
		}
	}
	return nil
}
