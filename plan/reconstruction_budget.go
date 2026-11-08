package plan

import "context"

// Count every candidate container before Seal clones records or resolves graph
// references. The byte envelope separately bounds strings and JSON decoding.
func preflightPreservation(ctx context.Context, p *reconstructionPreservation, b *visitBudget) error {
	d := p.Candidate
	if err := b.nativeCounts(ctx, len(d.Evidence), len(d.Diagnostics), len(d.Zones), len(d.Interfaces), len(d.Routes), len(d.AddressGroups), len(d.ServiceGroups), len(d.RuleBindings), len(p.Changes)); err != nil {
		return err
	}
	if err := b.nativeAdditions(ctx, NativeAdditions{Addresses: d.Addresses, Services: d.Services, Rules: d.Rules, Schedules: d.Schedules, StaticNATs: d.StaticNATs, DynamicNATs: d.DynamicNATs, NATPools: d.NATPools}); err != nil {
		return err
	}
	for _, r := range d.Zones {
		if err := b.nativeObject(ctx, r.Object); err != nil {
			return err
		}
		if err := b.take(ctx, len(r.Networks)); err != nil {
			return err
		}
	}
	for _, r := range d.Interfaces {
		if err := b.nativeObject(ctx, r.Object); err != nil {
			return err
		}
		if err := b.take(ctx, len(r.Addresses)); err != nil {
			return err
		}
	}
	for _, r := range d.Routes {
		if err := b.nativeObject(ctx, r.Object); err != nil {
			return err
		}
		if err := b.take(ctx, len(r.PolicyMatch)); err != nil {
			return err
		}
	}
	for _, r := range d.AddressGroups {
		if err := b.nativeObject(ctx, r.Object); err != nil {
			return err
		}
		if err := b.take(ctx, len(r.Members)); err != nil {
			return err
		}
	}
	for _, r := range d.ServiceGroups {
		if err := b.nativeObject(ctx, r.Object); err != nil {
			return err
		}
		if err := b.take(ctx, len(r.Members)); err != nil {
			return err
		}
	}
	for _, r := range d.RuleBindings {
		if err := b.nativeObject(ctx, r.Object); err != nil {
			return err
		}
	}
	for _, c := range p.Changes {
		if err := b.nativeCounts(ctx, len(c.Sources), len(c.Destinations), len(c.Services)); err != nil {
			return err
		}
	}
	return ctx.Err()
}
