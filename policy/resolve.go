package policy

import (
	"context"
	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
)

type resolutionBudget struct {
	ctx          context.Context
	limit, spent int
}

func (b *resolutionBudget) charge() error {
	if err := b.ctx.Err(); err != nil {
		return err
	}
	if b.spent >= b.limit {
		return ErrBudget
	}
	b.spent++
	return nil
}

// Addresses returns known=false for unresolved, cyclic or over-budget declarations.
// The query engine additionally reports budget/cancellation errors to its caller.
func Addresses(fw *fm.Firewall, refs []fm.AddressRef, any bool) (flow.Set, bool) {
	result, known, err := resolveAddresses(fw, refs, any, &resolutionBudget{ctx: context.Background(), limit: 4096})
	return result, known && err == nil
}
func resolveAddresses(fw *fm.Firewall, refs []fm.AddressRef, any bool, budget *resolutionBudget) (flow.Set, bool, error) {
	if any {
		return allAddresses(), true, nil
	}
	known := true
	states := make(map[fm.ID]uint8)
	leaves := make(map[fm.ID]bool)
	var ranges []flow.Range
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
			r := a.Record()
			if len(r.Unsupported) > 0 || r.FQDN != "" {
				known = false
			}
			// A FortiOS VIP also selects ports, interfaces and a policy lookup
			// class. Only the native evaluator may reduce it to address coverage.
			if r.VIP != (fm.NATRef{}) {
				known = false
			}
			for _, interval := range a.Set().Ranges() {
				if err := budget.charge(); err != nil {
					return err
				}
				ranges = append(ranges, interval)
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
			r := g.Record()
			if len(r.Unsupported) > 0 {
				known = false
			}
			for _, member := range r.Members {
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
			return flow.Set{}, false, err
		}
	}
	if !known {
		return allAddresses(), false, nil
	}
	set, err := flow.NewSet(ranges...)
	return set, err == nil, err
}
func allServices() []fm.ServiceTerm {
	return []fm.ServiceTerm{{Protocol: flow.Interval{Low: 0, High: 255}, SourcePort: flow.Interval{Low: 0, High: 65535}, DestinationPort: flow.Interval{Low: 0, High: 65535}, ICMPType: flow.Interval{Low: 0, High: 255}, ICMPCode: flow.Interval{Low: 0, High: 255}}}
}

// Services resolves a group DAG as a union; shared children are visited once.
func Services(fw *fm.Firewall, refs []fm.ServiceRef, any bool) ([]fm.ServiceTerm, bool) {
	result, known, err := resolveServices(fw, refs, any, &resolutionBudget{ctx: context.Background(), limit: 4096})
	return result, known && err == nil
}
func resolveServices(fw *fm.Firewall, refs []fm.ServiceRef, any bool, budget *resolutionBudget) ([]fm.ServiceTerm, bool, error) {
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
			r := s.Record()
			if len(r.Unsupported) > 0 {
				known = false
			}
			for _, term := range r.Terms {
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
			r := g.Record()
			if len(r.Unsupported) > 0 {
				known = false
			}
			for _, member := range r.Members {
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
