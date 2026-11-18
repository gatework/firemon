package firemon

import (
	"slices"
	"strings"
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
	position   int
	spec       SecurityRule
	match      traffic.Space
	bound      traffic.Space
	issues     []string // every reason, for reporting
	dstDomains traffic.DomainSet
	apps       []string // normalized application names
	// domainOnly and appOnly count issues that only destination domains or
	// only application matching cause; a target that carries a domain or an
	// application decides those dimensions itself.
	domainIssues, appIssues int
	schedule                *Schedule
	loc                     *time.Location
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

// DecidableFor reports whether the rule is exact for a target that names
// its destination domain (domains) or its application (apps): those
// dimensions are then matched by name instead of being unknown.
func (r *Rule) DecidableFor(domains, apps bool) bool {
	rest := len(r.issues)
	if domains {
		rest -= r.domainIssues
	}
	if apps {
		rest -= r.appIssues
	}
	return rest == 0
}

// DstDomains returns the destination domain patterns of the rule.
func (r *Rule) DstDomains() traffic.DomainSet { return r.dstDomains }

// Applications returns the lowercase application names the rule matches;
// empty means any application.
func (r *Rule) Applications() []string { return slices.Clone(r.apps) }

// MatchesApplication reports whether the rule admits application app.
func (r *Rule) MatchesApplication(app string) bool {
	return len(r.apps) == 0 || slices.Contains(r.apps, strings.ToLower(app))
}

// Scheduled reports whether a schedule or validity window restricts the rule.
func (r *Rule) Scheduled() bool { return r.schedule != nil || r.spec.Window != (TimeWindow{}) }

// Applies reports whether the rule is written for traffic from zone from to
// zone to. Empty zone lists match every zone.
func (r *Rule) Applies(from, to string) bool {
	return zoneMatches(r.spec.From, from) && zoneMatches(r.spec.To, to) && r.spec.Scope.Allows(from, to)
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
	position int
	spec     DynamicNAT
	match    traffic.Space
	bound    traffic.Space
	src, dst traffic.AddressSet // translated addresses per side
	issues   []string
}

// Position returns the zero-based position in the NAT rule list.
func (n *NATRule) Position() int { return n.position }

// Spec returns the declarative rule. Its slices are shared and read-only.
func (n *NATRule) Spec() DynamicNAT { return n.spec }

// Match returns the original packets the rule applies to.
func (n *NATRule) Match() traffic.Space { return n.match }

// Bound returns a space certainly containing every packet the rule can
// match, widening unresolvable dimensions to any.
func (n *NATRule) Bound() traffic.Space { return n.bound }

// Translates reports whether the rule rewrites the given side; an
// exemption (TranslationModeNone) counts as a decision on that side.
func (n *NATRule) Translates(side NATKind) bool {
	return n.translation(side).Mode != TranslationModeUnset
}

// Exempts reports whether the rule matches without translating anything.
func (n *NATRule) Exempts() bool {
	src, dst := n.spec.TranslatedSource.Mode, n.spec.TranslatedDestination.Mode
	return (src == TranslationModeNone || src == TranslationModeUnset) && (dst == TranslationModeNone || dst == TranslationModeUnset)
}

// Translation returns the declarative translation of one side.
func (n *NATRule) Translation(side NATKind) Translation { return n.translation(side) }

// Translated returns the addresses one side is translated to. It is empty
// for TranslationModeNone, and for interface-address translation without a
// named interface, where the egress interface supplies the address.
func (n *NATRule) Translated(side NATKind) traffic.AddressSet {
	if side == NATKindSource {
		return n.src
	}
	return n.dst
}

// Issues returns why the match or translation is not exact.
func (n *NATRule) Issues() []string { return slices.Clone(n.issues) }

// Decidable reports whether match and translation are exact.
func (n *NATRule) Decidable() bool { return len(n.issues) == 0 }

// InVirtualRouter reports whether the rule applies in routing context vr.
func (n *NATRule) InVirtualRouter(vr string) bool {
	return n.spec.VirtualRouter == "" || vr == "" || n.spec.VirtualRouter == vr
}

// AppliesFrom reports whether the rule is enabled for traffic entering
// from zone from.
func (n *NATRule) AppliesFrom(from string) bool {
	return !n.spec.Disabled && zoneMatches(n.spec.From, from)
}

// Applies reports whether the rule is written for traffic from zone from to
// zone to.
func (n *NATRule) Applies(from, to string) bool {
	return n.AppliesFrom(from) && zoneMatches(n.spec.To, to)
}

func (n *NATRule) translation(side NATKind) Translation {
	if side == NATKindSource {
		return n.spec.TranslatedSource
	}
	return n.spec.TranslatedDestination
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

// InVirtualRouter reports whether the mapping applies in routing context vr.
func (m *StaticMapping) InVirtualRouter(vr string) bool {
	return m.spec.VirtualRouter == "" || vr == "" || m.spec.VirtualRouter == vr
}

// AppliesInbound reports whether traffic entering from zone from to the
// mapped addresses is translated.
func (m *StaticMapping) AppliesInbound(from string) bool {
	return m.Enabled() && zoneMatches(m.spec.Zones, from)
}

// AppliesOutbound reports whether traffic from the real addresses entering
// from zone from and leaving to zone to is translated.
func (m *StaticMapping) AppliesOutbound(from, to string) bool {
	return m.Enabled() && zoneMatches(m.spec.From, from) && zoneMatches(m.spec.Zones, to)
}

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
