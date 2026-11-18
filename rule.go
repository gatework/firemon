package firemon

import "time"

// Action is what a security rule does with matching traffic.
type Action uint8

// Rule actions.
const (
	ActionUnset Action = iota
	// ActionPermit allows the traffic.
	ActionPermit
	// ActionDeny drops or rejects the traffic.
	ActionDeny
)

// String returns "permit", "deny" or "unset".
func (a Action) String() string {
	switch a {
	case ActionUnset:
		return "unset"
	case ActionPermit:
		return "permit"
	case ActionDeny:
		return "deny"
	default:
		return "invalid"
	}
}

// MarshalText implements encoding.TextMarshaler.
func (a Action) MarshalText() ([]byte, error) { return []byte(a.String()), nil }

// SecurityRule is one entry of the ordered security rulebase. Empty zone,
// address, service and application lists mean "any".
type SecurityRule struct {
	// ID is the device identifier: the Hillstone rule id, or the PAN-OS rule
	// name.
	ID          string `json:"id"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`

	From        []string     `json:"from,omitempty"`
	To          []string     `json:"to,omitempty"`
	Source      []AddressRef `json:"source,omitempty"`
	Destination []AddressRef `json:"destination,omitempty"`
	// NegateSource and NegateDestination invert the address match.
	NegateSource      bool     `json:"negate_source,omitempty"`
	NegateDestination bool     `json:"negate_destination,omitempty"`
	Services          []string `json:"services,omitempty"`
	// ApplicationDefault restricts services to each application's default
	// ports (PAN-OS "application-default").
	ApplicationDefault bool     `json:"application_default,omitempty"`
	Applications       []string `json:"applications,omitempty"`

	Action   Action `json:"action"`
	Disabled bool   `json:"disabled,omitempty"`
	Log      bool   `json:"log,omitempty"`
	// Schedule names a Schedule; Window is an inline validity period
	// (Hillstone start-time/expire-time).
	Schedule string     `json:"schedule,omitempty"`
	Window   TimeWindow `json:"window,omitzero"`
	// Group is the rule-group (Hillstone aggregate) this rule belongs to.
	Group string `json:"group,omitempty"`
	// Unsupported lists match criteria the parser recognized but cannot
	// evaluate, such as users, URL categories or HIP profiles.
	Unsupported []string `json:"unsupported,omitempty"`
}

// ActiveAt reports whether the rule's inline window allows t.
func (r SecurityRule) ActiveAt(t time.Time) bool { return r.Window.Contains(t) }
