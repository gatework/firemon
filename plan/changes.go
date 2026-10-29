package plan

import (
	"context"
	"fmt"
	"slices"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/policy"
)

// ValidateChanges establishes that changes describe the entire configuration
// delta. It does not prove traffic safety or authorize device writes. Source
// layout and position renumbering may differ; native relative order may not.
func ValidateChanges(ctx context.Context, before, after *fm.Firewall, changes []Change) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if before == nil || after == nil {
		return ErrInvalid
	}
	a, b := before.Metadata(), after.Metadata()
	if a.Device == "" || a.Device != b.Device || a.Vendor != b.Vendor || a.Context != b.Context || a.Software != b.Software || a.ParserVersion != b.ParserVersion {
		return fmt.Errorf("%w: configuration identity differs", ErrInvalid)
	}
	if !before.Complete() || !after.Complete() {
		return ErrUnsafe
	}
	expected := before.Export()
	selected := make(map[fm.ID]Change, len(changes))
	addresses, services := make(map[fm.ID]bool), make(map[fm.ID]bool)
	for _, c := range changes {
		if err := ctx.Err(); err != nil {
			return err
		}
		if _, exists := selected[c.Rule]; c.Rule == "" || exists {
			return fmt.Errorf("%w: repeated or empty rule", ErrInvalid)
		}
		selected[c.Rule] = c
		old, next := before.Rule(c.Rule), after.Rule(c.Rule)
		switch c.Kind {
		case CreateRule:
			if old != nil || next == nil || next.Builtin() {
				return ErrInvalid
			}
			record := next.Record()
			if !sameMembers(c.Sources, record.Match.Sources) || !sameMembers(c.Destinations, record.Match.Destinations) || !sameMembers(c.Services, record.Match.Services) {
				return fmt.Errorf("%w: creation members differ", ErrInvalid)
			}
			expected.Rules = append(expected.Rules, record)
		case AppendMembers:
			if old == nil || next == nil || old.Builtin() || len(c.Sources)+len(c.Destinations)+len(c.Services) == 0 {
				return ErrInvalid
			}
			m := old.Record().Match
			if !validAppend(m.Sources, c.Sources, m.AnySource) || !validAppend(m.Destinations, c.Destinations, m.AnyDestination) || !validAppend(m.Services, c.Services, m.AnyService) {
				return fmt.Errorf("%w: invalid member addition", ErrInvalid)
			}
		case RemoveRule:
			if old == nil || next != nil || old.Builtin() || len(c.Sources)+len(c.Destinations)+len(c.Services) != 0 {
				return ErrInvalid
			}
		default:
			return ErrInvalid
		}
		for _, refs := range [][]fm.AddressRef{c.Sources, c.Destinations} {
			for _, ref := range refs {
				if err := ctx.Err(); err != nil {
					return err
				}
				if ref.Kind == fm.AddressObject && before.Address(ref.ID) == nil && !addresses[ref.ID] {
					object := after.Address(ref.ID)
					if object == nil {
						return ErrInvalid
					}
					expected.Addresses = append(expected.Addresses, object.Record())
					addresses[ref.ID] = true
				}
			}
		}
		for _, ref := range c.Services {
			if err := ctx.Err(); err != nil {
				return err
			}
			if ref.Kind == fm.ServiceObject && before.Service(ref.ID) == nil && !services[ref.ID] {
				object := after.Service(ref.ID)
				if object == nil {
					return ErrInvalid
				}
				expected.Services = append(expected.Services, object.Record())
				services[ref.ID] = true
			}
		}
	}
	for _, object := range after.Addresses() {
		if err := ctx.Err(); err != nil {
			return err
		}
		if before.Address(object.ID()) == nil && !addresses[object.ID()] && !object.Record().Inline {
			return fmt.Errorf("%w: unrelated address addition", ErrInvalid)
		}
	}
	for _, object := range after.Services() {
		if err := ctx.Err(); err != nil {
			return err
		}
		if before.Service(object.ID()) == nil && !services[object.ID()] && !object.Record().Inline {
			return fmt.Errorf("%w: unrelated service addition", ErrInvalid)
		}
	}
	kept := expected.Rules[:0]
	for _, record := range expected.Rules {
		if err := ctx.Err(); err != nil {
			return err
		}
		c := selected[record.ID]
		if c.Kind == RemoveRule {
			continue
		}
		next := after.Rule(record.ID)
		if next == nil {
			return fmt.Errorf("%w: undeclared rule removal", ErrInvalid)
		}
		if record.Name != next.Name() {
			return fmt.Errorf("%w: undeclared rule rename", ErrInvalid)
		}
		record.Position = next.Position()
		if c.Kind == AppendMembers {
			record.Match.Sources = append(record.Match.Sources, c.Sources...)
			record.Match.Destinations = append(record.Match.Destinations, c.Destinations...)
			record.Match.Services = append(record.Match.Services, c.Services...)
		}
		kept = append(kept, record)
	}
	expected.Rules = kept
	// Compare surviving identities per native chain, not global source offsets.
	chains := make(map[policy.RuleChain][]fm.ID)
	for rule := range before.OrderedRules() {
		if err := ctx.Err(); err != nil {
			return err
		}
		if after.Rule(rule.ID()) == nil {
			continue
		}
		order := policy.NativeRuleOrder(a.Vendor, rule.Record())
		chains[order.Chain] = append(chains[order.Chain], rule.ID())
	}
	for rule := range after.OrderedRules() {
		if err := ctx.Err(); err != nil {
			return err
		}
		if before.Rule(rule.ID()) == nil {
			continue
		}
		order := policy.NativeRuleOrder(b.Vendor, rule.Record())
		ids := chains[order.Chain]
		if len(ids) == 0 || ids[0] != rule.ID() {
			return fmt.Errorf("%w: undeclared rule reordering", ErrInvalid)
		}
		chains[order.Chain] = ids[1:]
	}
	want, err := normalized(expected)
	if err != nil {
		return fmt.Errorf("%w: expected graph: %w", ErrInvalid, err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	got, err := normalized(after.Export())
	if err != nil {
		return fmt.Errorf("%w: result graph: %w", ErrInvalid, err)
	}
	if want.SemanticDigest() != got.SemanticDigest() {
		return fmt.Errorf("%w: undeclared configuration delta", ErrInvalid)
	}
	return ctx.Err()
}

func sameMembers[T comparable](a, b []T) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[T]bool, len(a))
	for _, v := range a {
		if seen[v] {
			return false
		}
		seen[v] = true
	}
	for _, v := range b {
		if !seen[v] {
			return false
		}
		delete(seen, v)
	}
	return true
}

func validAppend[T comparable](before, added []T, any bool) bool {
	if any && len(added) > 0 {
		return false
	}
	seen := make(map[T]bool, len(added))
	for _, v := range added {
		if seen[v] || slices.Contains(before, v) {
			return false
		}
		seen[v] = true
	}
	return true
}
