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

// ZoneScope restricts which zone pairs of its From and To lists a rule
// applies to (PAN-OS rule-type).
type ZoneScope uint8

// Zone scopes.
const (
	// ZoneScopeAny applies to every pair of a From and a To zone.
	ZoneScopeAny ZoneScope = iota
	// ZoneScopeIntra applies only when source and destination zone are equal.
	ZoneScopeIntra
	// ZoneScopeInter applies only when they differ.
	ZoneScopeInter
)

// String returns "any", "intrazone" or "interzone".
func (z ZoneScope) String() string {
	switch z {
	case ZoneScopeAny:
		return "any"
	case ZoneScopeIntra:
		return "intrazone"
	case ZoneScopeInter:
		return "interzone"
	default:
		return "invalid"
	}
}

// MarshalText implements encoding.TextMarshaler.
func (z ZoneScope) MarshalText() ([]byte, error) { return []byte(z.String()), nil }

// UnmarshalText implements encoding.TextUnmarshaler.
func (z *ZoneScope) UnmarshalText(text []byte) error {
	return unmarshalEnum(z, text, "zone scope", ZoneScopeAny, ZoneScopeIntra, ZoneScopeInter)
}

// Allows reports whether the scope admits the zone pair. Unknown zones
// (empty) are admitted; callers treat them as possible matches.
func (z ZoneScope) Allows(from, to string) bool {
	if from == "" || to == "" {
		return true
	}
	switch z {
	case ZoneScopeIntra:
		return from == to
	case ZoneScopeInter:
		return from != to
	case ZoneScopeAny:
		return true
	default:
		return true
	}
}

// Covers reports whether every pair z admits, o admits too: o is at least
// as broad as z.
func (z ZoneScope) Covers(o ZoneScope) bool { return o == ZoneScopeAny || z == o }

// SecurityRule is one entry of the ordered security rulebase. Empty zone,
// address, service and application lists mean "any".
type SecurityRule struct {
	// ID is the device identifier: the Hillstone rule id, or the PAN-OS rule
	// name.
	ID          string `json:"id"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`

	From []string `json:"from,omitempty"`
	To   []string `json:"to,omitempty"`
	// Scope restricts the zone pairs further (PAN-OS rule-type).
	Scope       ZoneScope    `json:"scope,omitzero"`
	Source      []AddressRef `json:"source,omitempty"`
	Destination []AddressRef `json:"destination,omitempty"`
	// NegateSource and NegateDestination invert the address match.
	NegateSource      bool     `json:"negate_source,omitempty"`
	NegateDestination bool     `json:"negate_destination,omitempty"`
	Services          []string `json:"services,omitempty"`
	// ServiceEntries are inline services, matched in addition to Services.
	ServiceEntries []ServiceEntry `json:"service_entries,omitempty"`
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

// RuleGroup is a named folder of security rules (Hillstone aggregate
// policy). Its ID shares the rule ID space but it matches no traffic.
type RuleGroup struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}
