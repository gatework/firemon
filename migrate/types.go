package migrate

import (
	"github.com/gatework/firemon"
	"github.com/gatework/firemon/design"
)

// Fidelity is how faithfully an item was translated.
type Fidelity uint8

// Fidelities, from best to worst.
const (
	FidelityUnset Fidelity = iota
	// FidelityExact: the target matches exactly what the source matched.
	FidelityExact
	// FidelityApproximate: the target differs in a stated, bounded way.
	FidelityApproximate
	// FidelityUntranslatable: the target cannot express the item; a rule
	// is carried over disabled.
	FidelityUntranslatable
)

// String returns the fidelity name.
func (f Fidelity) String() string {
	switch f {
	case FidelityUnset:
		return "unset"
	case FidelityExact:
		return "exact"
	case FidelityApproximate:
		return "approximate"
	case FidelityUntranslatable:
		return "untranslatable"
	default:
		return "invalid"
	}
}

// MarshalText implements encoding.TextMarshaler.
func (f Fidelity) MarshalText() ([]byte, error) { return []byte(f.String()), nil }

// ItemKind classifies a translated item.
type ItemKind uint8

// Item kinds.
const (
	ItemKindUnset ItemKind = iota
	ItemKindVirtualRouter
	ItemKindZone
	ItemKindInterface
	ItemKindRoute
	ItemKindSchedule
	ItemKindAddress
	ItemKindAddressGroup
	ItemKindService
	ItemKindServiceGroup
	ItemKindRule
	ItemKindNAT
	// ItemKindDefault is a default action made explicit.
	ItemKindDefault
	ItemKindPolicyRoute
	ItemKindPolicyBinding
)

// String returns the kind name.
func (k ItemKind) String() string {
	switch k {
	case ItemKindUnset:
		return "unset"
	case ItemKindVirtualRouter:
		return "virtual-router"
	case ItemKindZone:
		return "zone"
	case ItemKindInterface:
		return "interface"
	case ItemKindRoute:
		return "route"
	case ItemKindSchedule:
		return "schedule"
	case ItemKindAddress:
		return "address"
	case ItemKindAddressGroup:
		return "address-group"
	case ItemKindService:
		return "service"
	case ItemKindServiceGroup:
		return "service-group"
	case ItemKindRule:
		return "rule"
	case ItemKindNAT:
		return "nat"
	case ItemKindPolicyRoute:
		return "policy-route"
	case ItemKindPolicyBinding:
		return "policy-binding"
	case ItemKindDefault:
		return "default"
	default:
		return "invalid"
	}
}

// MarshalText implements encoding.TextMarshaler.
func (k ItemKind) MarshalText() ([]byte, error) { return []byte(k.String()), nil }

// Item is the translation of one source item.
type Item struct {
	Kind     ItemKind `json:"kind"`
	Source   string   `json:"source"`
	Target   []string `json:"target,omitempty"`
	Fidelity Fidelity `json:"fidelity"`
	Reason   string   `json:"reason,omitempty"`
}

// Mapping names source items on the target. Names missing from a map are
// kept as they are (sanitized for the target); interfaces kept that way
// are reported, since port names rarely match between devices.
type Mapping struct {
	Zones          map[string]string `json:"zones,omitempty" yaml:"zones,omitempty"`
	Interfaces     map[string]string `json:"interfaces,omitempty" yaml:"interfaces,omitempty"`
	VirtualRouters map[string]string `json:"virtual_routers,omitempty" yaml:"virtual_routers,omitempty"`
	// Services maps predefined source service names to target ones, for
	// example HTTP to service-http.
	Services map[string]string `json:"services,omitempty" yaml:"services,omitempty"`
	// Applications maps source application names to target ones; a rule
	// with an unmapped application is carried over disabled.
	Applications map[string]string `json:"applications,omitempty" yaml:"applications,omitempty"`
}

// Target describes the destination platform.
type Target struct {
	Vendor       firemon.Vendor
	Semantics    firemon.Semantics
	Capabilities firemon.Capabilities
	// Sanitize adapts names to the target's rules; nil keeps them.
	Sanitize func(string) string
	// Services are the target's predefined services.
	Services firemon.ServiceBook
	// Render writes a plan in the target's syntax and Parse reads a target
	// configuration, so that a translation can be checked by parsing what
	// it renders; nil when the caller does not provide them.
	Render func(plan *design.Plan) (design.Script, error)
	Parse  func(text string) (*firemon.Config, error)
}

// Result is a translation.
type Result struct {
	// Config is the target configuration the plan builds.
	Config *firemon.Config `json:"-"`
	// Plan creates Config on an empty target device; it is rendered, not
	// deployed.
	Plan  *design.Plan `json:"plan"`
	Items []Item       `json:"items"`
	// DisabledDenies are the source deny rules carried over disabled: the
	// traffic they blocked is not blocked by them on the target, and the
	// migration is not safe to apply until they are fixed.
	DisabledDenies []string `json:"disabled_denies,omitempty"`
}

// Count returns the number of items of a fidelity.
func (r Result) Count(f Fidelity) int {
	n := 0
	for _, it := range r.Items {
		if it.Fidelity == f {
			n++
		}
	}
	return n
}
