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
	if len(before.StaticNATs())+len(before.DynamicNATs())+len(after.StaticNATs())+len(after.DynamicNATs()) == 0 {
		return nil
	}
	a, b := before.Export(), after.Export()
	a.Rules, b.Rules = nil, nil
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
	if err := e.preserveNATActivation(ctx, before, after); err != nil {
		return err
	}
	contexts, err := e.Contexts(ctx, from, before, after)
	if err != nil {
		return err
	}
	limits := e.Limits.WithDefaults()
	remaining := limits.MaxVisits
	cost := len(before.Rules()) + len(after.Rules()) + len(before.NATSequence()) + len(after.NATSequence())
	for _, q := range contexts {
		if cost > remaining {
			return ErrBudget
		}
		remaining -= cost
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
		if same, err := equivalentTraffic(prior.Unmatched, next.Unmatched, limits.MaxRegions); err != nil {
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

func (e Engine) preserveNATActivation(ctx context.Context, before, after *fm.Firewall) error {
	if before.Metadata().Vendor != after.Metadata().Vendor {
		return ErrNotEquivalent
	}
	activation := semantics(before.Metadata().Vendor).activeNAT
	if activation == nil {
		return nil
	}
	budget := e.Limits.WithDefaults().MaxVisits
	a, err := activation(e, ctx, before, &budget)
	if err != nil {
		return err
	}
	b, err := activation(e, ctx, after, &budget)
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
