package firemon

import (
	"fmt"
	"slices"
	"time"
)

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

// Logging is what a rule logs.
type Logging struct {
	// Start and End log the session at its start and end.
	Start bool `json:"start,omitempty"`
	End   bool `json:"end,omitempty"`
	// Deny logs packets the rule denies (StoneOS policy-deny).
	Deny bool `json:"deny,omitempty"`
	// Forward names the configuration that sends the logs elsewhere.
	Forward string `json:"forward,omitempty"`
}

// Enabled reports whether the rule logs anything.
func (l Logging) Enabled() bool { return l.Start || l.End || l.Deny }

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
	// DefaultPorts makes the services the standard ports of the rule's
	// applications.
	DefaultPorts bool `json:"default_ports,omitempty"`
	// Conditions are what the rule matches on beyond zones, addresses and
	// services; all of them must hold.
	Conditions []Condition `json:"conditions,omitempty"`

	Action   Action  `json:"action"`
	Disabled bool    `json:"disabled,omitempty"`
	Log      Logging `json:"logging,omitzero"`
	// Schedule names a Schedule; Window is an inline validity period
	// (Hillstone start-time/expire-time).
	Schedule string     `json:"schedule,omitempty"`
	Window   TimeWindow `json:"window,omitzero"`
	// Group is the rule group this rule belongs to (see Config.RuleGroups
	// for its name, where the vendor names groups apart).
	Group string `json:"group,omitempty"`
	// Inspection lists the security inspection the rule applies to the
	// traffic it permits, in the vendor's terms ("ips NAME"). It does not
	// change what the rule matches.
	Inspection []string `json:"inspection,omitempty"`
	// Incomplete is why the device ignores the rule, when a required part
	// such as the action, an address or the service is missing. An
	// incomplete rule never matches.
	Incomplete string `json:"incomplete,omitempty"`
}

// Applications returns the applications the rule matches on; none means
// any application.
func (r SecurityRule) Applications() []string {
	return ConditionValues(r.Conditions, ConditionApplication)
}

// ActiveAt reports whether the rule's inline window allows t.
func (r SecurityRule) ActiveAt(t time.Time) bool { return r.Window.Contains(t) }

// RuleGroup is a named folder of security rules (Hillstone aggregate
// policy). Its ID shares the rule ID space but it matches no traffic.
type RuleGroup struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// ConditionKind is what a condition matches on. The set is closed: each
// kind is a question operators ask on its own; anything else is other.
type ConditionKind uint8

// Condition kinds.
const (
	ConditionUnset ConditionKind = iota
	// ConditionApplication matches traffic identified as one of the
	// applications in Values.
	ConditionApplication
	// ConditionDomain matches by domain name, beyond the addresses.
	ConditionDomain
	// ConditionUser matches by user, user group or role.
	ConditionUser
	// ConditionURLCategory matches by URL category.
	ConditionURLCategory
	// ConditionOther is any other criterion, kept as the vendor wrote it.
	ConditionOther
)

// String returns the kind name used in JSON output.
func (k ConditionKind) String() string {
	switch k {
	case ConditionUnset:
		return "unset"
	case ConditionApplication:
		return "application"
	case ConditionDomain:
		return "domain"
	case ConditionUser:
		return "user"
	case ConditionURLCategory:
		return "url-category"
	case ConditionOther:
		return "other"
	default:
		return "invalid"
	}
}

// MarshalText implements encoding.TextMarshaler.
func (k ConditionKind) MarshalText() ([]byte, error) { return []byte(k.String()), nil }

// UnmarshalText implements encoding.TextUnmarshaler.
func (k *ConditionKind) UnmarshalText(text []byte) error {
	for c := ConditionUnset; c <= ConditionOther; c++ {
		if c.String() == string(text) {
			*k = c
			return nil
		}
	}
	return fmt.Errorf("firemon: unknown condition kind %q", text)
}

// Condition is one criterion a rule matches on besides the five-tuple.
type Condition struct {
	Kind ConditionKind `json:"kind"`
	// Values are what the condition names: applications, domains, users,
	// categories. Any one of them satisfies the condition.
	Values []string `json:"values,omitempty"`
	// Raw is the vendor text of a condition other than an application
	// list, for display and rendering.
	Raw string `json:"raw,omitempty"`
}

// ApplicationCondition returns the condition matching any of apps.
func ApplicationCondition(apps ...string) Condition {
	return Condition{Kind: ConditionApplication, Values: apps}
}

// Criterion returns a condition the vendor wrote as raw, naming values.
func Criterion(kind ConditionKind, raw string, values ...string) Condition {
	return Condition{Kind: kind, Values: values, Raw: raw}
}

// AddApplications returns conds with apps added to the application
// condition, which it creates first when there is none.
func AddApplications(conds []Condition, apps ...string) []Condition {
	return WithApplications(conds, append(ConditionValues(conds, ConditionApplication), apps...))
}

// ConditionValues returns the values of the conditions of one kind, in
// order.
func ConditionValues(conds []Condition, kind ConditionKind) []string {
	var out []string
	for _, c := range conds {
		if c.Kind == kind {
			out = append(out, c.Values...)
		}
	}
	return out
}

// WithApplications returns conds with the application condition replaced
// by apps; none removes it.
func WithApplications(conds []Condition, apps []string) []Condition {
	out := slices.DeleteFunc(slices.Clone(conds), func(c Condition) bool { return c.Kind == ConditionApplication })
	if len(apps) > 0 {
		out = append([]Condition{ApplicationCondition(apps...)}, out...)
	}
	return out
}

// Criteria returns the vendor text of the conditions other than
// applications: the criteria the model holds but cannot evaluate offline.
func Criteria(conds []Condition) []string {
	var out []string
	for _, c := range conds {
		if c.Kind != ConditionApplication {
			out = append(out, c.Raw)
		}
	}
	return out
}
