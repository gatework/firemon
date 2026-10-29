package policy

import (
	"context"
	"encoding/json"
	"maps"
	"slices"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
)

// PreserveNAT proves that a policy edit retains the existing NAT declarations,
// their dependencies and every effective translation partition. Additional
// address/service declarations are permitted, but cannot change an existing
// dependency. Policy-bound NAT is checked across native chains and future
// schedule transitions, including the traffic intentionally changed by a plan.
func (e Engine) PreserveNAT(ctx context.Context, before, after *fm.Firewall, from time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if before == nil || after == nil {
		return ErrInvalid
	}
	if !before.Complete() || !after.Complete() {
		return ErrNotEquivalent
	}
	if before.StaticNATCount() == 0 && before.DynamicNATCount() == 0 && after.StaticNATCount() == 0 && after.DynamicNATCount() == 0 {
		return nil
	}
	limits := e.Limits.WithDefaults()
	remaining := limits.MaxVisits
	if err := chargeVisits(ctx, &remaining, before.RecordCount(), after.RecordCount()); err != nil {
		return err
	}
	a, b := before.Export(), after.Export()
	a.Rules, b.Rules = nil, nil
	if err := chargeVisits(ctx, &remaining, len(a.Addresses), len(a.Services), len(b.Addresses), len(b.Services)); err != nil {
		return err
	}
	addresses := make(map[fm.ID]bool, len(a.Addresses))
	services := make(map[fm.ID]bool, len(a.Services))
	for _, r := range a.Addresses {
		addresses[r.ID] = true
	}
	for _, r := range a.Services {
		services[r.ID] = true
	}
	b.Addresses = slices.DeleteFunc(b.Addresses, func(r fm.AddressRecord) bool { return !addresses[r.ID] })
	b.Services = slices.DeleteFunc(b.Services, func(r fm.ServiceRecord) bool { return !services[r.ID] })
	x, err := fm.Seal(a)
	if err != nil {
		return err
	}
	y, err := fm.Seal(b)
	if err != nil {
		return err
	}
	if x.SemanticDigest() != y.SemanticDigest() {
		return ErrNotEquivalent
	}
	// These native pipelines select translation through policy ownership or
	// activation. Other supported pipelines depend on the unchanged catalogs.
	native := semantics(before.Metadata().Vendor)
	if native.queryNAT == nil {
		return ErrNAT
	}
	if !native.policyBoundNAT {
		return nil
	}
	if err := e.preserveNATActivation(ctx, before, after, &remaining); err != nil {
		return err
	}
	contexts, err := e.Contexts(ctx, from, before, after)
	if err != nil {
		return err
	}
	for _, q := range contexts {
		if err := chargeVisits(ctx, &remaining, before.RuleCount(), after.RuleCount(), before.StaticNATCount(), before.DynamicNATCount(), after.StaticNATCount(), after.DynamicNATCount()); err != nil {
			return err
		}
		prior, err := e.QueryNAT(ctx, before, q)
		if err != nil {
			return err
		}
		next, err := e.QueryNAT(ctx, after, q)
		if err != nil {
			return err
		}
		if !prior.Complete || !next.Complete || !prior.Unknown.Empty() || !next.Unknown.Empty() {
			return ErrNotEquivalent
		}
		if same, err := prior.Unmatched.Equal(next.Unmatched, limits.MaxRegions); err != nil {
			return err
		} else if !same {
			return ErrNotEquivalent
		}
		left, err := natPartitions(prior.Relations, limits.MaxRegions)
		if err != nil {
			return err
		}
		right, err := natPartitions(next.Relations, limits.MaxRegions)
		if err != nil {
			return err
		}
		if err := equivalentPartitions(left, right, limits.MaxRegions); err != nil {
			return err
		}
	}
	return nil
}

func (e Engine) preserveNATActivation(ctx context.Context, before, after *fm.Firewall, remaining *int) error {
	if before.Metadata().Vendor != after.Metadata().Vendor {
		return ErrNotEquivalent
	}
	activation := semantics(before.Metadata().Vendor).activeNAT
	if activation == nil {
		return nil
	}
	a, err := activation(e, ctx, before, remaining)
	if err != nil {
		return err
	}
	b, err := activation(e, ctx, after, remaining)
	if err != nil {
		return err
	}
	if !maps.Equal(a, b) {
		return ErrNotEquivalent
	}
	return nil
}

// With unchanged mapping dependencies, the same ordered steps on the same
// original traffic retain the relation (including input/output correlation).
// Comparing only unions of translated addresses would lose that correlation.
func natPartitions(relations []NATRelation, limit int) (map[string]flow.Traffic, error) {
	out := make(map[string]flow.Traffic)
	for _, r := range relations {
		key, err := json.Marshal(struct {
			Kind                      fm.Kind
			ID                        fm.ID
			Steps                     []NATStep
			Exact, PossibleAllocation bool
		}{r.Kind, r.ID, r.Steps, r.Exact, r.PossibleAllocation})
		if err != nil {
			return nil, err
		}
		out[string(key)], err = out[string(key)].Union(r.Original, limit)
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}
