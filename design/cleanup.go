package design

import (
	"fmt"
	"slices"
	"strings"

	"github.com/gatework/firemon"
)

// PlanKind tells what a plan is for, and so how a deployment of it is
// checked.
type PlanKind uint8

// Plan kinds.
const (
	PlanKindUnset PlanKind = iota
	// PlanKindAccess permits (and translates) an intent; after deployment
	// the intent must need no further change.
	PlanKindAccess
	// PlanKindCleanup removes or merges configuration without changing the
	// effective policy; after deployment the readback must equal the
	// prediction.
	PlanKindCleanup
	// PlanKindMigration builds a configuration for another device; it is
	// rendered, never deployed onto the source.
	PlanKindMigration
)

// String returns the kind name.
func (k PlanKind) String() string {
	switch k {
	case PlanKindUnset:
		return "unset"
	case PlanKindAccess:
		return "access"
	case PlanKindCleanup:
		return "cleanup"
	case PlanKindMigration:
		return "migration"
	default:
		return "invalid"
	}
}

// MarshalText implements encoding.TextMarshaler.
func (k PlanKind) MarshalText() ([]byte, error) { return []byte(k.String()), nil }

// DeleteRule removes a security rule. Rule is the removed rule and Next
// the ID of the rule that followed it (empty: it was last), so that a
// rollback restores it in place.
type DeleteRule struct {
	Rule firemon.SecurityRule `json:"rule"`
	Next string               `json:"next,omitempty"`
}

// DeleteAddress removes an address object.
type DeleteAddress struct {
	Address firemon.Address `json:"address"`
}

// DeleteAddressGroup removes an address group.
type DeleteAddressGroup struct {
	Group firemon.AddressGroup `json:"group"`
}

// DeleteService removes a service object.
type DeleteService struct {
	Service firemon.Service `json:"service"`
}

// DeleteServiceGroup removes a service group.
type DeleteServiceGroup struct {
	Group firemon.ServiceGroup `json:"group"`
}

// DeleteSchedule removes a schedule.
type DeleteSchedule struct {
	Schedule firemon.Schedule `json:"schedule"`
}

// ReduceRule removes object names from one field of a rule, the inverse of
// ExtendRule. It never empties a field, which would mean any.
type ReduceRule struct {
	RuleID string   `json:"rule_id"`
	Field  Field    `json:"field"`
	Names  []string `json:"names"`
}

// AddSchedule creates a schedule.
type AddSchedule struct {
	Schedule firemon.Schedule `json:"schedule"`
}

// String describes the change.
func (c DeleteRule) String() string { return "delete rule " + c.Rule.ID }

// String describes the change.
func (c DeleteAddress) String() string { return "delete address " + c.Address.Name }

// String describes the change.
func (c DeleteAddressGroup) String() string { return "delete address group " + c.Group.Name }

// String describes the change.
func (c DeleteService) String() string { return "delete service " + c.Service.Name }

// String describes the change.
func (c DeleteServiceGroup) String() string { return "delete service group " + c.Group.Name }

// String describes the change.
func (c DeleteSchedule) String() string { return "delete schedule " + c.Schedule.Name }

// String describes the change.
func (c ReduceRule) String() string {
	return "reduce rule " + c.RuleID + " " + c.Field.String() + " -= " + strings.Join(c.Names, ",")
}

// String describes the change.
func (c AddSchedule) String() string { return "add schedule " + c.Schedule.Name }

func (DeleteRule) change()         {}
func (DeleteAddress) change()      {}
func (DeleteAddressGroup) change() {}
func (DeleteService) change()      {}
func (DeleteServiceGroup) change() {}
func (DeleteSchedule) change()     {}
func (ReduceRule) change()         {}
func (AddSchedule) change()        {}

// ErrInUse reports a deletion of an object something still refers to, or
// a reduction that would empty a field.
var ErrInUse = fmt.Errorf("design: still in use")

// applyCleanup applies the cleanup changes; ok is false for other kinds.
func applyCleanup(cfg *firemon.Config, ch Change) (ok bool, err error) {
	switch c := ch.(type) {
	case DeleteRule:
		i := slices.IndexFunc(cfg.Rules, func(r firemon.SecurityRule) bool { return r.ID == c.Rule.ID })
		if i < 0 {
			return true, fmt.Errorf("%w %q", ErrUnknownRule, c.Rule.ID)
		}
		cfg.Rules = slices.Delete(cfg.Rules, i, i+1)
	case DeleteAddress:
		return true, remove(&cfg.Addresses, c.Address.Name, func(a firemon.Address) string { return a.Name })
	case DeleteAddressGroup:
		return true, remove(&cfg.AddressGroups, c.Group.Name, func(g firemon.AddressGroup) string { return g.Name })
	case DeleteService:
		return true, remove(&cfg.Services, c.Service.Name, func(s firemon.Service) string { return s.Name })
	case DeleteServiceGroup:
		return true, remove(&cfg.ServiceGroups, c.Group.Name, func(g firemon.ServiceGroup) string { return g.Name })
	case DeleteSchedule:
		return true, remove(&cfg.Schedules, c.Schedule.Name, func(s firemon.Schedule) string { return s.Name })
	case ReduceRule:
		return true, reduce(cfg, c)
	case AddSchedule:
		cfg.Schedules = append(cfg.Schedules, c.Schedule)
	default:
		return false, nil
	}
	return true, nil
}

func remove[T any](list *[]T, name string, key func(T) string) error {
	i := slices.IndexFunc(*list, func(v T) bool { return key(v) == name })
	if i < 0 {
		return fmt.Errorf("design: delete unknown object %q", name)
	}
	*list = slices.Delete(*list, i, i+1)
	return nil
}

func reduce(cfg *firemon.Config, c ReduceRule) error {
	i := slices.IndexFunc(cfg.Rules, func(r firemon.SecurityRule) bool { return r.ID == c.RuleID })
	if i < 0 {
		return fmt.Errorf("%w %q", ErrUnknownRule, c.RuleID)
	}
	r := &cfg.Rules[i]
	drop := func(ref firemon.AddressRef) bool { return !ref.IsInline() && slices.Contains(c.Names, ref.Name) }
	switch c.Field {
	case FieldSource:
		r.Source = slices.DeleteFunc(r.Source, drop)
		if len(r.Source) == 0 {
			return fmt.Errorf("%w: rule %s would match any source", ErrInUse, c.RuleID)
		}
	case FieldDestination:
		r.Destination = slices.DeleteFunc(r.Destination, drop)
		if len(r.Destination) == 0 {
			return fmt.Errorf("%w: rule %s would match any destination", ErrInUse, c.RuleID)
		}
	case FieldService:
		r.Services = slices.DeleteFunc(r.Services, func(s string) bool { return slices.Contains(c.Names, s) })
		if len(r.Services) == 0 && len(r.ServiceEntries) == 0 {
			return fmt.Errorf("%w: rule %s would match any service", ErrInUse, c.RuleID)
		}
	case FieldUnset:
		return fmt.Errorf("design: reduce rule %q: field unset", c.RuleID)
	}
	return nil
}
