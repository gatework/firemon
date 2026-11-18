package audit

import "slices"

// Kind classifies a finding.
type Kind uint8

// Finding kinds.
const (
	KindUnset Kind = iota
	// KindRedundant is a rule fully covered by earlier rules with the same action.
	KindRedundant
	// KindShadowed is a rule fully covered by earlier rules, at least one of
	// which has the opposite action.
	KindShadowed
	// KindDisabled is a disabled rule.
	KindDisabled
	// KindExpired is a rule whose validity window or schedule has ended.
	KindExpired
	// KindUndecidable is a rule whose match cannot be evaluated offline.
	KindUndecidable
	// KindPermitAny is a permit rule matching any source, destination and service.
	KindPermitAny
	// KindUnusedAddress is an address object or group nothing references.
	KindUnusedAddress
	// KindUnusedService is a service object or group nothing references.
	KindUnusedService
	// KindIncomplete is a rule missing its action, an address or its
	// service; the device ignores it.
	KindIncomplete
)

// String returns the kind name.
func (k Kind) String() string {
	switch k {
	case KindUnset:
		return "unset"
	case KindRedundant:
		return "redundant"
	case KindShadowed:
		return "shadowed"
	case KindDisabled:
		return "disabled"
	case KindExpired:
		return "expired"
	case KindUndecidable:
		return "undecidable"
	case KindPermitAny:
		return "permit-any"
	case KindUnusedAddress:
		return "unused-address"
	case KindUnusedService:
		return "unused-service"
	case KindIncomplete:
		return "incomplete"
	default:
		return "invalid"
	}
}

// MarshalText implements encoding.TextMarshaler.
func (k Kind) MarshalText() ([]byte, error) { return []byte(k.String()), nil }

// Finding is one audit result about a rule or an object.
type Finding struct {
	Kind Kind `json:"kind"`
	// Rule is the rule ID, or empty for object findings.
	Rule string `json:"rule,omitempty"`
	// Object is the object name for unused-object findings.
	Object string `json:"object,omitempty"`
	// By lists the earlier rules that cover a shadowed or redundant rule.
	By     []string `json:"by,omitempty"`
	Detail string   `json:"detail,omitempty"`
}

// Report is the result of an audit, ordered by rule position and then by
// object name.
type Report struct {
	Findings []Finding `json:"findings"`
	// Incomplete names rules whose shadowing analysis hit the budget.
	Incomplete []string `json:"incomplete,omitempty"`
}

// Count returns the number of findings of kind k.
func (r Report) Count(k Kind) int {
	n := 0
	for _, f := range r.Findings {
		if f.Kind == k {
			n++
		}
	}
	return n
}

// Of returns the findings of kind k.
func (r Report) Of(k Kind) []Finding {
	return slices.DeleteFunc(slices.Clone(r.Findings), func(f Finding) bool { return f.Kind != k })
}
