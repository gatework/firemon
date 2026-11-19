package design

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/traffic"
)

// Status summarizes a plan.
type Status uint8

// Plan statuses.
const (
	StatusUnset Status = iota
	// StatusNoChange means the intent is already permitted.
	StatusNoChange
	// StatusChange means the plan's changes permit the need.
	StatusChange
	// StatusConflict means specific deny rules block part of the intent and
	// the intent did not ask to override them; any other need is planned.
	StatusConflict
	// StatusIndeterminate means part of the intent depends on undecidable
	// rules or unknown zones and could not be planned.
	StatusIndeterminate
)

// String returns the status name.
func (s Status) String() string {
	switch s {
	case StatusUnset:
		return "unset"
	case StatusNoChange:
		return "no-change"
	case StatusChange:
		return "change"
	case StatusConflict:
		return "conflict"
	case StatusIndeterminate:
		return "indeterminate"
	default:
		return "invalid"
	}
}

// MarshalText implements encoding.TextMarshaler.
func (s Status) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// Field names the rule dimension an extension adds members to.
type Field uint8

// Rule fields.
const (
	FieldUnset Field = iota
	FieldSource
	FieldDestination
	FieldService
)

// String returns the field name.
func (f Field) String() string {
	switch f {
	case FieldUnset:
		return "unset"
	case FieldSource:
		return "source"
	case FieldDestination:
		return "destination"
	case FieldService:
		return "service"
	default:
		return "invalid"
	}
}

// MarshalText implements encoding.TextMarshaler.
func (f Field) MarshalText() ([]byte, error) { return []byte(f.String()), nil }

// Change is one vendor-neutral configuration change. The set of changes is
// closed: AddAddress, AddService, AddAddressGroup, AddServiceGroup,
// ExtendRule, AddRule, AddNAT, AddStaticNAT, AddSchedule, ReduceRule and
// the Delete changes.
type Change interface {
	fmt.Stringer
	change()
}

// AddAddress creates an address object.
type AddAddress struct {
	Address firemon.Address `json:"address"`
}

// AddService creates a service object.
type AddService struct {
	Service firemon.Service `json:"service"`
}

// AddAddressGroup creates an address group of existing or new objects.
type AddAddressGroup struct {
	Group firemon.AddressGroup `json:"group"`
}

// AddServiceGroup creates a service group of existing or new services.
type AddServiceGroup struct {
	Group firemon.ServiceGroup `json:"group"`
}

// ExtendRule adds members to one dimension of an existing rule.
type ExtendRule struct {
	RuleID string   `json:"rule_id"`
	Field  Field    `json:"field"`
	Names  []string `json:"names"`
}

// AddRule inserts a security rule before the rule with ID Before, or at the
// end of the rulebase when Before is empty.
type AddRule struct {
	Rule   firemon.SecurityRule `json:"rule"`
	Before string               `json:"before,omitempty"`
}

// AddNAT inserts a dynamic NAT rule. NAT is first match like security
// rules, so the rule goes before the rule with ID Before in the same NAT
// list (the source or destination list of separate-order vendors, the one
// list of single-order vendors), or at the end of that list. Bidirectional
// adds the reverse half of a static source translation (PAN-OS static-ip
// bi-directional).
type AddNAT struct {
	Rule          firemon.DynamicNAT `json:"rule"`
	Before        string             `json:"before,omitempty"`
	Bidirectional bool               `json:"bidirectional,omitempty"`
}

// AddStaticNAT adds a one-to-one mapping (StoneOS bnatrule).
type AddStaticNAT struct {
	Mapping firemon.StaticNAT `json:"mapping"`
}

// String describes the change.
func (c AddNAT) String() string {
	where := "at end"
	if c.Before != "" {
		where = "before " + c.Before
	}
	return "add nat " + c.Rule.ID + " " + where
}

// String describes the change.
func (c AddStaticNAT) String() string {
	return "add static nat " + c.Mapping.ID + " " + c.Mapping.Mapped.String() + " <-> " + c.Mapping.Real.String()
}

// String describes the change.
func (c AddAddress) String() string {
	entries := make([]string, len(c.Address.Entries))
	for i, e := range c.Address.Entries {
		entries[i] = e.String()
	}
	return "add address " + c.Address.Name + " " + strings.Join(entries, ",")
}

// String describes the change.
func (c AddService) String() string {
	var set traffic.ServiceSet
	for _, e := range c.Service.Entries {
		set = set.Union(e.Set())
	}
	return "add service " + c.Service.Name + " " + set.String()
}

// String describes the change.
func (c AddAddressGroup) String() string {
	return "add address group " + c.Group.Name + " " + strings.Join(c.Group.Members, ",")
}

// String describes the change.
func (c AddServiceGroup) String() string {
	return "add service group " + c.Group.Name + " " + strings.Join(c.Group.Members, ",")
}

// String describes the change.
func (c ExtendRule) String() string {
	return "extend rule " + c.RuleID + " " + c.Field.String() + " += " + strings.Join(c.Names, ",")
}

// String describes the change.
func (c AddRule) String() string {
	where := "at end"
	if c.Before != "" {
		where = "before " + c.Before
	}
	return "add rule " + c.Rule.ID + " " + where
}

func (AddAddress) change()      {}
func (AddService) change()      {}
func (AddAddressGroup) change() {}
func (AddServiceGroup) change() {}
func (ExtendRule) change()      {}
func (AddRule) change()         {}
func (AddNAT) change()          {}
func (AddStaticNAT) change()    {}

// Conflict is part of the intent a specific deny rule blocks.
type Conflict struct {
	RuleID string         `json:"rule_id"`
	From   string         `json:"from"`
	To     string         `json:"to"`
	Space  traffic.Region `json:"-"`
	Text   string         `json:"space"`
}

// Plan is a designed change set: for an intent (access), a cleanup or a
// migration.
type Plan struct {
	Kind      PlanKind   `json:"kind"`
	Intent    Intent     `json:"-"`
	Baseline  string     `json:"baseline"`
	Status    Status     `json:"status"`
	Changes   []Change   `json:"-"`
	Conflicts []Conflict `json:"conflicts,omitempty"`
	// Unknown lists the intent parts that depend on undecidable rules or
	// unknown zones.
	Unknown []string `json:"unknown,omitempty"`
	// Warnings note planned parts that undecidable permit rules may already
	// allow.
	Warnings []string `json:"warnings,omitempty"`
	// Verified reports that applying Changes permits the planned need and
	// nothing outside the intent.
	Verified bool `json:"verified"`
	// VerifyError is why verification failed, when it did.
	VerifyError string `json:"verify_error,omitempty"`
	// NAT is the outcome of the NAT part, when the intent asks for one.
	NAT *NATOutcome `json:"nat,omitempty"`
	// Bypassed are the deny rules the new rules are placed before, in rule
	// order: the change overrides them for the traffic it permits.
	Bypassed []string `json:"bypassed,omitempty"`
}

// Merge combines the plans of the parts of one request on one firewall,
// each designed on the configuration the plans before it leave, into one
// plan for that firewall: its changes in order, its findings together,
// verified only when every part is, and based on the first plan's
// baseline, the firewall as it is now.
func Merge(plans ...*Plan) *Plan {
	if len(plans) == 0 {
		return nil
	}
	out := *plans[0]
	out.Changes = slices.Clone(out.Changes)
	out.Bypassed = slices.Clone(out.Bypassed)
	for _, p := range plans[1:] {
		out.Changes = append(out.Changes, p.Changes...)
		out.Conflicts = append(out.Conflicts, p.Conflicts...)
		out.Unknown = append(out.Unknown, p.Unknown...)
		out.Warnings = append(out.Warnings, p.Warnings...)
		for _, id := range p.Bypassed {
			if !slices.Contains(out.Bypassed, id) {
				out.Bypassed = append(out.Bypassed, id)
			}
		}
		out.Status = max(out.Status, p.Status)
		out.Verified = out.Verified && p.Verified
		out.VerifyError = cmp.Or(out.VerifyError, p.VerifyError)
		if out.NAT == nil {
			out.NAT = p.NAT
		}
	}
	return &out
}

// bypassed records the deny rules the changes opening n are placed before,
// in rule order.
func (p *Plan) bypassed(n need, changes []Change) {
	if len(changes) == 0 {
		return
	}
	rules := slices.Clone(n.bypass)
	slices.SortFunc(rules, func(a, b *firemon.Rule) int { return a.Position() - b.Position() })
	for _, r := range rules {
		if !slices.Contains(p.Bypassed, r.ID()) {
			p.Bypassed = append(p.Bypassed, r.ID())
		}
	}
}
