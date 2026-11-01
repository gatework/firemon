package analysis

import (
	"context"
	"slices"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/policy"
)

func (w *inspectionWalk) walk(ctx context.Context, ref fm.AddressRef, path []fm.AddressRef, emit func(ObjectPath) error) error {
	if err := w.visits.take(ctx, 1); err != nil {
		return err
	}
	if len(path) >= 64 {
		return policy.ErrBudget
	}
	cycle := slices.Contains(path, ref)
	path = append(slices.Clone(path), ref)
	issue := func(code string) error {
		if err := w.row(ctx); err != nil {
			return err
		}
		w.report.Issues = append(w.report.Issues, InspectionIssue{Path: path, Code: code})
		return nil
	}
	if cycle {
		return issue("cycle")
	}
	if ref == w.selector.Object {
		if err := emit(ObjectPath{Path: path, Relation: "identity"}); err != nil {
			return err
		}
	}
	switch ref.Kind {
	case fm.AddressObject:
		a := w.fw.Address(ref.ID)
		if a == nil {
			return issue("missing_address")
		}
		if !w.selector.Addresses.Empty() {
			set := a.Set()
			if err := w.visits.take(ctx, set.RangeCount()+w.selector.Addresses.RangeCount()); err != nil {
				return err
			}
			if !set.Intersection(w.selector.Addresses).Empty() {
				relation := "overlap"
				if set.Contains(w.selector.Addresses) {
					relation = "contains"
				}
				return emit(ObjectPath{Path: path, Relation: relation})
			}
		}
	case fm.AddressGroupObject:
		g := w.fw.AddressGroup(ref.ID)
		if g == nil {
			return issue("missing_group")
		}
		for _, member := range g.Record().Members {
			if err := w.walk(ctx, member, path, emit); err != nil {
				return err
			}
		}
	default:
		return issue("unsupported_reference")
	}
	return nil
}
func (w *inspectionWalk) selectedAddresses(ctx context.Context, ref fm.AddressRef, path []fm.AddressRef) (flow.AddressSet, error) {
	if err := w.visits.take(ctx, 1); err != nil {
		return flow.AddressSet{}, err
	}
	if len(path) >= 64 {
		return flow.AddressSet{}, policy.ErrBudget
	}
	if slices.Contains(path, ref) {
		return flow.AddressSet{}, nil
	}
	path = append(slices.Clone(path), ref)
	if ref.Kind == fm.AddressObject {
		if a := w.fw.Address(ref.ID); a != nil {
			return a.Set(), nil
		}
		return flow.AddressSet{}, nil
	}
	var set flow.AddressSet
	if g := w.fw.AddressGroup(ref.ID); g != nil {
		for _, member := range g.Record().Members {
			part, err := w.selectedAddresses(ctx, member, path)
			if err != nil {
				return flow.AddressSet{}, err
			}
			if err := w.visits.take(ctx, set.RangeCount()+part.RangeCount()); err != nil {
				return flow.AddressSet{}, err
			}
			set = set.Union(part)
		}
	}
	return set, nil
}
func (w *inspectionWalk) pools(ctx context.Context, selected flow.AddressSet, limit int) error {
	if selected.RangeCount() > limit {
		return flow.ErrBudget
	}
	for _, nat := range w.fw.DynamicNATs() {
		if err := w.visits.take(ctx, 1); err != nil {
			return err
		}
		r := nat.Record()
		for _, p := range []struct {
			id   fm.ID
			role Dimension
		}{{r.SourcePool, Source}, {r.DestinationPool, Destination}} {
			if p.id == "" {
				continue
			}
			pool := w.fw.NATPool(p.id)
			if pool == nil {
				continue
			}
			record := pool.Record()
			if len(record.Ranges) > limit {
				return flow.ErrBudget
			}
			if err := w.visits.take(ctx, len(record.Ranges)+selected.RangeCount()); err != nil {
				return err
			}
			set, err := flow.NewAddressSet(record.Ranges...)
			if err != nil {
				return err
			}
			hit := set.Intersection(selected)
			if hit.Empty() {
				continue
			}
			if err := w.row(ctx); err != nil {
				return err
			}
			if err := w.retain(hit.RangeCount()); err != nil {
				return err
			}
			w.report.DynamicPools = append(w.report.DynamicPools, DynamicPoolRelation{NAT: fm.NATRef{Kind: fm.DynamicNATObject, ID: r.ID}, Pool: p.id, Role: p.role, Disabled: r.Disabled, Addresses: hit.Ranges(), PossibleAllocation: true})
		}
	}
	return nil
}
