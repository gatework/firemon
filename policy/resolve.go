package policy

import (
	"context"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
)

type resolutionBudget struct {
	ctx          context.Context
	limit, spent int
	cache        *resolutionCache
}

func (b *resolutionBudget) charge() error { return b.chargeCount(1) }

func (b *resolutionBudget) chargeCount(count int) error {
	if err := b.ctx.Err(); err != nil {
		return err
	}
	if count < 0 || count > b.limit-b.spent {
		return ErrBudget
	}
	b.spent += count
	return nil
}

func expandAddresses(fw *fm.Firewall, refs []fm.AddressRef, any bool, budget *resolutionBudget) (flow.AddressSet, bool, error) {
	if any {
		return allAddresses, true, nil
	}
	known := true
	states := make(map[fm.ID]uint8)
	leaves := make(map[fm.ID]bool)
	var ranges []flow.AddressRange
	var visit func(fm.AddressRef) error
	visit = func(ref fm.AddressRef) error {
		if err := budget.charge(); err != nil {
			return err
		}
		switch ref.Kind {
		case fm.AddressObject:
			if leaves[ref.ID] {
				return nil
			}
			leaves[ref.ID] = true
			a := fw.Address(ref.ID)
			if a == nil {
				known = false
				return nil
			}
			if a.HasUnsupported() || a.FQDN() != "" {
				known = false
			}
			// A FortiOS VIP also selects ports, interfaces and a policy lookup
			// class. Only the native evaluator may reduce it to address coverage.
			if a.VIP() != (fm.NATRef{}) {
				known = false
			}
			set := a.Set()
			// Reserve normalized ranges before retaining their values.
			if err := budget.chargeCount(set.RangeCount()); err != nil {
				return err
			}
			for r := range set.All() {
				ranges = append(ranges, r)
			}
		case fm.AddressGroupObject:
			if states[ref.ID] == 1 {
				known = false
				return nil
			}
			if states[ref.ID] == 2 {
				return nil
			}
			g := fw.AddressGroup(ref.ID)
			if g == nil {
				known = false
				return nil
			}
			states[ref.ID] = 1
			if g.HasUnsupported() {
				known = false
			}
			for member := range g.Members() {
				if err := visit(member); err != nil {
					return err
				}
			}
			states[ref.ID] = 2
		default:
			known = false
		}
		return nil
	}
	for _, ref := range refs {
		if err := visit(ref); err != nil {
			return flow.AddressSet{}, false, err
		}
	}
	if !known {
		return allAddresses, false, nil
	}
	if err := budget.ctx.Err(); err != nil {
		return flow.AddressSet{}, false, err
	}
	set, err := flow.NewAddressSet(ranges...)
	return set, err == nil, err
}
func allServices() []fm.ServiceTerm {
	return []fm.ServiceTerm{{Protocol: flow.Interval{Low: 0, High: 255}, SourcePort: flow.Interval{Low: 0, High: 65535}, DestinationPort: flow.Interval{Low: 0, High: 65535}, ICMPType: flow.Interval{Low: 0, High: 255}, ICMPCode: flow.Interval{Low: 0, High: 255}}}
}

func expandServices(fw *fm.Firewall, refs []fm.ServiceRef, any bool, budget *resolutionBudget) ([]fm.ServiceTerm, bool, error) {
	if any {
		return allServices(), true, nil
	}
	known := true
	states := make(map[fm.ID]uint8)
	leaves := make(map[fm.ID]bool)
	terms := make(map[fm.ServiceTerm]bool)
	var result []fm.ServiceTerm
	var visit func(fm.ServiceRef) error
	visit = func(ref fm.ServiceRef) error {
		if err := budget.charge(); err != nil {
			return err
		}
		switch ref.Kind {
		case fm.ServiceObject:
			if leaves[ref.ID] {
				return nil
			}
			leaves[ref.ID] = true
			s := fw.Service(ref.ID)
			if s == nil {
				known = false
				return nil
			}
			if s.HasUnsupported() {
				known = false
			}
			for term := range s.Terms() {
				if err := budget.charge(); err != nil {
					return err
				}
				if !terms[term] {
					terms[term] = true
					result = append(result, term)
				}
			}
		case fm.ServiceGroupObject:
			if states[ref.ID] == 1 {
				known = false
				return nil
			}
			if states[ref.ID] == 2 {
				return nil
			}
			g := fw.ServiceGroup(ref.ID)
			if g == nil {
				known = false
				return nil
			}
			states[ref.ID] = 1
			if g.HasUnsupported() {
				known = false
			}
			for member := range g.Members() {
				if err := visit(member); err != nil {
					return err
				}
			}
			states[ref.ID] = 2
		default:
			known = false
		}
		return nil
	}
	for _, ref := range refs {
		if err := visit(ref); err != nil {
			return nil, false, err
		}
	}
	if !known {
		return allServices(), false, nil
	}
	return result, true, nil
}

// ResolveAddresses separates unknown declarations from cancellation and resource errors.
// The returned set is conservative when known is false.
func (e Engine) ResolveAddresses(ctx context.Context, fw *fm.Firewall, refs []fm.AddressRef, any bool) (flow.AddressSet, bool, error) {
	if err := ctx.Err(); err != nil {
		return flow.AddressSet{}, false, err
	}
	if fw == nil {
		return flow.AddressSet{}, false, ErrInvalid
	}
	return resolveAddresses(fw, refs, any, &resolutionBudget{ctx: ctx, limit: e.Limits.WithDefaults().MaxCombinations})
}

// ResolveServices resolves service declarations without hiding execution errors.
// Shared children in a group DAG are visited once per resolution.
func (e Engine) ResolveServices(ctx context.Context, fw *fm.Firewall, refs []fm.ServiceRef, any bool) ([]fm.ServiceTerm, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	if fw == nil {
		return nil, false, ErrInvalid
	}
	return resolveServices(fw, refs, any, &resolutionBudget{ctx: ctx, limit: e.Limits.WithDefaults().MaxCombinations})
}
