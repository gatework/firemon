// Package render shares native renderer entry validation and change ordering.
package render

import (
	"cmp"
	"context"
	"slices"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/policy"
)

// batch owns validated emission order and newly referenced declarations.
type batch struct {
	changes   []plan.Change
	addresses map[fm.ID]bool
	services  map[fm.ID]bool
}

func (b batch) Changes() []plan.Change        { return slices.Clone(b.changes) }
func (b batch) DeclaresAddress(id fm.ID) bool { return b.addresses[id] }
func (b batch) DeclaresService(id fm.ID) bool { return b.services[id] }

// Prepare returns an owned change order. Most native emitters support creation
// before surviving explicit rules; ASA can select an exact ACL line instead.
func Prepare(ctx context.Context, vendor string, before, after *fm.Firewall, changes []plan.Change) (batch, error) {
	if err := plan.ValidateChanges(ctx, before, after, changes); err != nil {
		return batch{}, err
	}
	if before.Metadata().Vendor != vendor || vendor == "fortinet" && before.Metadata().Context == "" {
		return batch{}, plan.ErrInvalid
	}
	prepared := batch{addresses: make(map[fm.ID]bool), services: make(map[fm.ID]bool)}
	for _, c := range changes {
		if err := ctx.Err(); err != nil {
			return batch{}, err
		}
		for _, refs := range [][]fm.AddressRef{c.Sources, c.Destinations} {
			for _, ref := range refs {
				if ref.Kind == fm.AddressObject && before.Address(ref.ID) == nil {
					prepared.addresses[ref.ID] = true
				}
			}
		}
		for _, ref := range c.Services {
			if ref.Kind == fm.ServiceObject && before.Service(ref.ID) == nil {
				prepared.services[ref.ID] = true
			}
		}
		if c.Kind != plan.CreateRule {
			continue
		}
		r := after.Rule(c.Rule).Record()
		m := r.Match
		for _, dimension := range []struct {
			any   bool
			count int
		}{
			{m.AnySource, len(m.Sources)}, {m.AnyDestination, len(m.Destinations)}, {m.AnyService, len(m.Services)},
			{m.AnyFromZone, len(m.FromZones)}, {m.AnyToZone, len(m.ToZones)},
		} {
			if !dimension.any && dimension.count == 0 || dimension.any && dimension.count != 0 {
				return batch{}, plan.ErrRender
			}
		}
		if r.Description != "" || r.Disabled || (r.Log == fm.Known) != (r.LogStart == fm.Known || r.LogEnd == fm.Known) {
			return batch{}, plan.ErrRender
		}
	}
	if vendor != "asa" {
		seen := make(map[policy.RuleChain]bool)
		for r := range after.OrderedRules() {
			if err := ctx.Err(); err != nil {
				return batch{}, err
			}
			order := policy.NativeRuleOrder(vendor, r.Record())
			if r.Builtin() {
				continue
			}
			if before.Rule(r.ID()) != nil {
				seen[order.Chain] = true
			} else if seen[order.Chain] {
				return batch{}, plan.ErrRender
			}
		}
	}
	result := slices.Clone(changes)
	slices.SortStableFunc(result, func(a, b plan.Change) int {
		if a.Kind == plan.RemoveRule {
			if b.Kind == plan.RemoveRule {
				return 0
			}
			return -1
		}
		if b.Kind == plan.RemoveRule {
			return 1
		}
		if n := cmp.Compare(after.Rule(a.Rule).Position(), after.Rule(b.Rule).Position()); n != 0 {
			return n
		}
		return cmp.Compare(a.Rule, b.Rule)
	})
	prepared.changes = result
	if err := prepared.validateNames(ctx, before, after); err != nil {
		return batch{}, err
	}
	return prepared, ctx.Err()
}
