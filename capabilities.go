package firemon

import "github.com/gatework/firemon/traffic"

// Capabilities describe what a vendor's configuration can express, so that
// a translation from another vendor knows what to rewrite and what it
// cannot carry over.
type Capabilities struct {
	// ExcludeEntries: address objects can exclude addresses (StoneOS).
	ExcludeEntries bool
	// MixedAddressObjects: one address object holds several entries of any
	// kind (StoneOS); otherwise one entry per object (PAN-OS).
	MixedAddressObjects bool
	// GroupEntries: address groups hold inline entries besides members.
	GroupEntries bool
	// WildcardFQDN: address objects match wildcard domain names.
	WildcardFQDN bool
	// MultiProtocolServices: one service object holds several protocols or
	// non-port protocols such as ICMP.
	MultiProtocolServices bool
	// NegateAddresses: rules can negate their source or destination.
	NegateAddresses bool
	// RuleTypes: rules can be intrazone or interzone only.
	RuleTypes bool
	// ApplicationDefault: services can be the applications' default ports.
	ApplicationDefault bool
	// RuleWindows: rules carry an inline validity window.
	RuleWindows bool
	// LogDeny: rules log the packets they deny on their own (StoneOS
	// policy-deny); elsewhere a deny rule logs at session end.
	LogDeny bool
	// InlineServices: rules carry inline service entries.
	InlineServices bool
	// InlineFQDN: rules carry inline domain names.
	InlineFQDN bool
	// DynamicAddressGroups supports a group whose members follow a filter.
	DynamicAddressGroups bool
	// DiscardRoutes supports rendering a static discard route.
	DiscardRoutes bool
	// MinuteSchedules supports one period type per schedule with minute precision.
	MinuteSchedules bool
	// MonthlySchedules supports days of the month in recurring schedules.
	MonthlySchedules bool
	// PerRulePolicyRouteID is the normalized entry ID when each forwarding
	// rule owns its bindings. An empty ID denotes ordered, numeric entries
	// in one routing policy per ingress zone or interface.
	PerRulePolicyRouteID string
	// ApplicationAlias maps a source application to a target signature.
	ApplicationAlias func(Vendor, string) (string, bool)
	// ServiceApplication maps a portless service to a target application.
	ServiceApplication func(traffic.ServiceSet) (string, bool)
	// MaxNameLength bounds object and rule names; zero means no limit.
	MaxNameLength int
}
