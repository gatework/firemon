package firemon

import (
	"slices"
	"time"

	"github.com/gatework/firemon/traffic"
)

// Rule is a compiled security rule: its match space resolved to exact sets
// and every reason the match is not exact recorded in Issues. A rule with
// issues is undecidable: evaluation must treat it as a possible match and
// never as a definite one.
//
// Rule values are immutable; Spec shares memory with the Firewall and must
// not be modified.
type Rule struct {
	position int
	spec     SecurityRule
	match    traffic.Space
	bound    traffic.Space
	issues   []string
	schedule *Schedule
	loc      *time.Location
}

// Position returns the zero-based evaluation order of the rule.
func (r *Rule) Position() int { return r.position }

// ID returns the device identifier of the rule.
func (r *Rule) ID() string { return r.spec.ID }

// Spec returns the declarative rule. Its slices are shared and read-only.
func (r *Rule) Spec() SecurityRule { return r.spec }

// Action returns the rule action.
func (r *Rule) Action() Action { return r.spec.Action }

// Match returns the exact match space. When Issues is non-empty it is the
// part of the match that could be resolved.
func (r *Rule) Match() traffic.Space { return r.match }

// Bound returns a space that certainly contains every packet the rule can
// match. For a decidable rule it equals Match; a dimension that could not
// be resolved exactly (unknown objects, domain names, dynamic groups) is
// widened to any, while criteria that only narrow the match (applications,
// users, URL categories) leave it unchanged.
func (r *Rule) Bound() traffic.Space { return r.bound }

// Issues returns why the match space is not exact.
func (r *Rule) Issues() []string { return slices.Clone(r.issues) }

// Decidable reports whether the match space is exact.
func (r *Rule) Decidable() bool { return len(r.issues) == 0 }

// Scheduled reports whether a schedule or validity window restricts the rule.
func (r *Rule) Scheduled() bool { return r.schedule != nil || r.spec.Window != (TimeWindow{}) }

// Applies reports whether the rule is written for traffic from zone from to
// zone to. Empty zone lists match every zone.
func (r *Rule) Applies(from, to string) bool {
	return zoneMatches(r.spec.From, from) && zoneMatches(r.spec.To, to)
}

// ActiveAt reports whether the rule is enabled and its schedule and window
// allow instant t.
func (r *Rule) ActiveAt(t time.Time) bool {
	if r.spec.Disabled {
		return false
	}
	local := t.In(r.loc)
	if !r.spec.ActiveAt(local) {
		return false
	}
	return r.schedule == nil || r.schedule.ActiveAt(local)
}

// InactiveAt reports whether the rule certainly cannot match at instant t:
// it is disabled, outside its validity window, or outside a schedule the
// compiler could model. Unlike !ActiveAt it is safe for undecidable rules.
func (r *Rule) InactiveAt(t time.Time) bool {
	if r.spec.Disabled {
		return true
	}
	local := t.In(r.loc)
	if !r.spec.ActiveAt(local) {
		return true
	}
	return r.schedule != nil && r.schedule.Unsupported == "" && !r.schedule.ActiveAt(local)
}

// ExpiredAt reports whether the rule can never become active again after
// instant t: its validity window has ended, or its schedule has only
// absolute windows that all ended.
func (r *Rule) ExpiredAt(t time.Time) bool {
	local := t.In(r.loc)
	if end := r.spec.Window.End; !end.IsZero() && !local.Before(end) {
		return true
	}
	return r.schedule != nil && r.schedule.Unsupported == "" && r.schedule.ExpiredAt(local)
}

// NATRule is a compiled dynamic NAT rule.
type NATRule struct {
	position   int
	spec       DynamicNAT
	match      traffic.Space
	translated traffic.AddressSet
	issues     []string
}

// Position returns the zero-based evaluation order among rules of its kind.
func (n *NATRule) Position() int { return n.position }

// Spec returns the declarative rule. Its slices are shared and read-only.
func (n *NATRule) Spec() DynamicNAT { return n.spec }

// Kind returns whether the rule rewrites the source or the destination.
func (n *NATRule) Kind() NATKind { return n.spec.Kind }

// Match returns the original packets the rule applies to.
func (n *NATRule) Match() traffic.Space { return n.match }

// Translated returns the addresses the rewritten side is translated to. It
// is empty for TranslationModeNone and for interface-address translation
// without a named interface, where the egress interface of each packet
// supplies the address.
func (n *NATRule) Translated() traffic.AddressSet { return n.translated }

// Issues returns why the match or translation is not exact.
func (n *NATRule) Issues() []string { return slices.Clone(n.issues) }

// Decidable reports whether match and translation are exact.
func (n *NATRule) Decidable() bool { return len(n.issues) == 0 }

// Applies reports whether the rule is written for traffic from zone from to
// zone to.
func (n *NATRule) Applies(from, to string) bool {
	return !n.spec.Disabled && zoneMatches(n.spec.From, from) && zoneMatches(n.spec.To, to)
}

// StaticMapping is a compiled one-to-one static NAT.
type StaticMapping struct {
	spec   StaticNAT
	real   traffic.AddressSet
	mapped traffic.AddressSet
	issues []string
}

// Spec returns the declarative mapping.
func (m *StaticMapping) Spec() StaticNAT { return m.spec }

// Real returns the internal addresses.
func (m *StaticMapping) Real() traffic.AddressSet { return m.real }

// Mapped returns the public addresses.
func (m *StaticMapping) Mapped() traffic.AddressSet { return m.mapped }

// Issues returns why the mapping cannot be applied exactly.
func (m *StaticMapping) Issues() []string { return slices.Clone(m.issues) }

// Decidable reports whether the mapping is exact.
func (m *StaticMapping) Decidable() bool { return len(m.issues) == 0 }

// Enabled reports whether the mapping is in effect.
func (m *StaticMapping) Enabled() bool { return !m.spec.Disabled && len(m.issues) == 0 }

// ToMapped translates the real addresses in s to their mapped counterparts.
// Addresses of s outside Real are dropped.
func (m *StaticMapping) ToMapped(s traffic.AddressSet) traffic.AddressSet {
	return shiftSet(s.Intersect(m.real), m.real, m.mapped)
}

// ToReal translates the mapped addresses in s to their real counterparts.
// Addresses of s outside Mapped are dropped.
func (m *StaticMapping) ToReal(s traffic.AddressSet) traffic.AddressSet {
	return shiftSet(s.Intersect(m.mapped), m.mapped, m.real)
}

func zoneMatches(zones []string, zone string) bool {
	return len(zones) == 0 || slices.Contains(zones, zone)
}
