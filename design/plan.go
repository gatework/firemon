package design

import (
	"fmt"
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
// ExtendRule and AddRule.
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

// Conflict is part of the intent a specific deny rule blocks.
type Conflict struct {
	RuleID string         `json:"rule_id"`
	From   string         `json:"from"`
	To     string         `json:"to"`
	Space  traffic.Region `json:"-"`
	Text   string         `json:"space"`
}

// Plan is the designed change set for one intent.
type Plan struct {
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
}
