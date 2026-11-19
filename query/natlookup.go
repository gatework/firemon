package query

import (
	"cmp"
	"slices"
	"strings"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/traffic"
)

// NATRole is how an address takes part in a NAT rule.
type NATRole uint8

// NAT roles.
const (
	NATRoleUnset NATRole = iota
	// NATRoleOutbound: the address is a source the rule translates when it
	// goes out.
	NATRoleOutbound
	// NATRolePublished: the address is an internal server the rule
	// publishes at a public address.
	NATRolePublished
	// NATRoleInbound: the address is public; the rule translates it to an
	// internal one.
	NATRoleInbound
	// NATRolePool: the address is one sources are translated to.
	NATRolePool
	// NATRoleExempt: the rule matches the address and translates nothing.
	NATRoleExempt
)

// String returns the role name used in JSON output.
func (r NATRole) String() string {
	switch r {
	case NATRoleUnset:
		return "unset"
	case NATRoleOutbound:
		return "outbound"
	case NATRolePublished:
		return "published"
	case NATRoleInbound:
		return "inbound"
	case NATRolePool:
		return "pool"
	case NATRoleExempt:
		return "exempt"
	default:
		return "invalid"
	}
}

// MarshalText implements encoding.TextMarshaler.
func (r NATRole) MarshalText() ([]byte, error) { return []byte(r.String()), nil }

// NATState says whether a NAT entry takes effect.
type NATState uint8

// NAT states.
const (
	NATStateUnset NATState = iota
	// NATStateActive: nothing before the entry takes all of its traffic.
	NATStateActive
	// NATStateShadowed: an earlier rule of the same list matches all of
	// the entry's traffic first.
	NATStateShadowed
	// NATStateDisabled: the entry is disabled.
	NATStateDisabled
	// NATStatePossible: the entry cannot be evaluated exactly offline.
	NATStatePossible
)

// String returns the state name used in JSON output.
func (s NATState) String() string {
	switch s {
	case NATStateUnset:
		return "unset"
	case NATStateActive:
		return "active"
	case NATStateShadowed:
		return "shadowed"
	case NATStateDisabled:
		return "disabled"
	case NATStatePossible:
		return "possible"
	default:
		return "invalid"
	}
}

// MarshalText implements encoding.TextMarshaler.
func (s NATState) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// NATUse is one NAT entry an address takes part in.
type NATUse struct {
	Rule   *firemon.NATRule       `json:"-"`
	Static *firemon.StaticMapping `json:"-"`
	ID     string                 `json:"id"`
	Role   NATRole                `json:"role"`
	Side   firemon.NATKind        `json:"side"`
	// Match is what the entry matches before translation: the public
	// address and port of a destination translation, the sources of a
	// source translation.
	Match traffic.Space `json:"match"`
	// Translated is what the translated side becomes; Interface names the
	// egress interface whose address source NAT uses when there is no
	// fixed address.
	Translated traffic.AddressSet `json:"translated"`
	Interface  string             `json:"interface,omitempty"`
	// Service is the destination service after translation (the internal
	// port of a published server).
	Service traffic.ServiceSet `json:"service"`
	// Position is the one-based place of the rule in its NAT list; zero
	// for static mappings.
	Position   int      `json:"position,omitempty"`
	State      NATState `json:"state"`
	ShadowedBy string   `json:"shadowed_by,omitempty"`
}

// NATLookup finds the NAT entries an address takes part in, both ways: as
// an internal address (translated when it goes out, published at a public
// address) and as a public one (translated to internal servers, used as
// a source pool). svc narrows the lookup to a service; empty is any.
// Entries come in list order with whether they take effect: a rule an
// earlier rule of its list fully covers never applies.
func (e *Engine) NATLookup(addr traffic.AddressSet, svc traffic.ServiceSet) []NATUse {
	if svc.IsEmpty() {
		svc = traffic.AnyService()
	}
	zones := e.addressZones(addr)
	var out []NATUse
	for _, list := range e.natLists() {
		for i, r := range list {
			for _, u := range ruleUses(r, i, list, addr, svc) {
				if relevant(u, zones) {
					out = append(out, e.natEffect(u, addr))
				}
			}
		}
	}
	for _, m := range e.fw.StaticNATs() {
		out = append(out, staticUses(m, addr)...)
	}
	return slices.DeleteFunc(out, func(u NATUse) bool { return poolAsSource(u, out) })
}

// poolAsSource reports an outbound entry that matches the address only
// because the rule takes any source, when the same rule translates to the
// address: the address is the rule's pool, not one of its sources.
func poolAsSource(u NATUse, all []NATUse) bool {
	if u.Role != NATRoleOutbound || u.Rule == nil || (!u.Match.Src.Equal(traffic.AnyAddress()) && !u.Match.Src.Equal(traffic.AnyIPv4())) {
		return false
	}
	return slices.ContainsFunc(all, func(o NATUse) bool { return o.Rule == u.Rule && o.Role == NATRolePool })
}

// natLists returns the NAT rule lists in the order they apply: one list by
// precedence on single-order vendors, the destination list then the source
// list on the others.
func (e *Engine) natLists() [][]*firemon.NATRule {
	if e.fw.Semantics().NATOrder == firemon.NATOrderSingle {
		all := e.fw.NATRules()
		slices.SortStableFunc(all, func(a, b *firemon.NATRule) int { return cmp.Compare(a.Spec().Precedence, b.Spec().Precedence) })
		return [][]*firemon.NATRule{all}
	}
	dst := e.fw.NATRulesFor(firemon.NATKindDestination)
	var src []*firemon.NATRule
	for _, r := range e.fw.NATRulesFor(firemon.NATKindSource) {
		if !slices.Contains(dst, r) {
			src = append(src, r)
		}
	}
	return [][]*firemon.NATRule{dst, src}
}

func ruleUses(r *firemon.NATRule, i int, list []*firemon.NATRule, addr traffic.AddressSet, svc traffic.ServiceSet) []NATUse {
	m := r.Match()
	internal := m.Service // the destination service after translation
	if port := r.Spec().TranslatedDestination.Port; port != 0 {
		internal = withPort(m.Service, port)
	}
	if !m.Service.Overlaps(svc) && !internal.Overlaps(svc) {
		return nil
	}
	base := NATUse{Rule: r, ID: r.Spec().ID, Match: m, Position: i + 1}
	base.State, base.ShadowedBy = ruleState(r, list[:i])
	var out []NATUse
	add := func(role NATRole, side firemon.NATKind) {
		u := base
		u.Role, u.Side = role, side
		u.Translated = r.Translated(side)
		if side == firemon.NATKindSource && u.Translated.IsEmpty() {
			u.Interface = cmp.Or(r.Translation(side).Interface, r.Spec().Egress)
		}
		u.Service = m.Service
		if side == firemon.NATKindDestination {
			u.Service = internal
		}
		out = append(out, u)
	}
	switch {
	case r.Exempts():
		if m.Src.Overlaps(addr) || m.Dst.Overlaps(addr) {
			add(NATRoleExempt, firemon.NATKindSource)
		}
		return out
	case r.Translates(firemon.NATKindDestination):
		if m.Dst.Overlaps(addr) {
			add(NATRoleInbound, firemon.NATKindDestination)
		}
		if r.Translated(firemon.NATKindDestination).Overlaps(addr) {
			add(NATRolePublished, firemon.NATKindDestination)
		}
	}
	if r.Translates(firemon.NATKindSource) && r.Translation(firemon.NATKindSource).Mode != firemon.TranslationModeNone {
		if m.Src.Overlaps(addr) {
			add(NATRoleOutbound, firemon.NATKindSource)
		}
		if r.Translated(firemon.NATKindSource).Overlaps(addr) {
			add(NATRolePool, firemon.NATKindSource)
		}
	}
	return out
}

// ruleState says whether a rule takes effect after the rules before it in
// its list: an enabled, exact earlier rule for the same zones that matches
// all of its traffic takes it first.
func ruleState(r *firemon.NATRule, before []*firemon.NATRule) (NATState, string) {
	switch {
	case r.Spec().Disabled:
		return NATStateDisabled, ""
	case !r.Decidable():
		return NATStatePossible, ""
	}
	for _, e := range before {
		s := e.Spec()
		if s.Disabled || !e.Decidable() {
			continue
		}
		if zonesCover(s.From, r.Spec().From) && zonesCover(s.To, r.Spec().To) && (s.Egress == "" || s.Egress == r.Spec().Egress) &&
			e.Match().ContainsSpace(r.Match()) {
			return NATStateShadowed, s.ID
		}
	}
	return NATStateActive, ""
}

// zonesCover reports whether zone list a admits every zone b does; empty
// means any.
func zonesCover(a, b []string) bool {
	if len(a) == 0 {
		return true
	}
	if len(b) == 0 {
		return false
	}
	for _, z := range b {
		if !slices.Contains(a, z) {
			return false
		}
	}
	return true
}

func staticUses(m *firemon.StaticMapping, addr traffic.AddressSet) []NATUse {
	state := NATStateActive
	switch {
	case m.Spec().Disabled:
		state = NATStateDisabled
	case !m.Decidable():
		state = NATStatePossible
	}
	base := NATUse{Static: m, ID: m.Spec().ID, State: state, Service: traffic.AnyService()}
	var out []NATUse
	if inside := m.Real().Intersect(addr); !inside.IsEmpty() {
		u := base
		u.Role, u.Side = NATRolePublished, firemon.NATKindDestination
		u.Match = traffic.Space{Src: traffic.AnyAddress(), Dst: m.ToMapped(inside), Service: traffic.AnyService()}
		u.Translated = inside
		out = append(out, u)
	}
	if mapped := m.Mapped().Intersect(addr); !mapped.IsEmpty() {
		u := base
		u.Role, u.Side = NATRoleInbound, firemon.NATKindDestination
		u.Match = traffic.Space{Src: traffic.AnyAddress(), Dst: mapped, Service: traffic.AnyService()}
		u.Translated = m.ToReal(mapped)
		out = append(out, u)
	}
	return out
}

// addressZones returns the zones the firewall routes addr to, in its
// default routing context; empty when it routes it nowhere.
func (e *Engine) addressZones(addr traffic.AddressSet) []string {
	table, ok := e.fw.RoutingTable(e.fw.Semantics().DefaultVirtualRouter)
	if !ok {
		return nil
	}
	egress, _ := table.Lookup(addr)
	var out []string
	for _, x := range egress {
		if x.Zone != "" && !slices.Contains(out, x.Zone) {
			out = append(out, x.Zone)
		}
	}
	return out
}

// relevant drops a rule that matches the address only because it matches
// any address on that side, when the address is in none of the rule's
// source zones: a source translation for traffic from the inside says
// nothing about a public address.
func relevant(u NATUse, zones []string) bool {
	var side traffic.AddressSet
	switch u.Role {
	case NATRoleOutbound, NATRoleExempt:
		side = u.Match.Src
	case NATRoleInbound, NATRolePublished, NATRolePool, NATRoleUnset:
		return true
	}
	if !side.Equal(traffic.AnyAddress()) && !side.Equal(traffic.AnyIPv4()) {
		return true
	}
	from := u.Rule.Spec().From
	if len(from) == 0 || len(zones) == 0 {
		return true
	}
	return slices.ContainsFunc(zones, func(z string) bool { return slices.Contains(from, z) })
}

// natEffect checks by evaluating the rule's own traffic whether the rule
// is the one that translates it: an earlier rule of the list that takes
// the traffic first makes it shadowed, whatever the static comparison
// said. Entries the evaluation cannot settle keep their state.
func (e *Engine) natEffect(u NATUse, addr traffic.AddressSet) NATUse {
	if u.State != NATStateActive && u.State != NATStateShadowed {
		return u
	}
	req := Request{Src: u.Match.Src, Dst: u.Match.Dst, Service: u.Match.Service}
	switch u.Role {
	case NATRoleOutbound:
		req.Src = u.Match.Src.Intersect(addr)
	case NATRoleInbound:
		req.Dst = u.Match.Dst.Intersect(addr)
	case NATRolePublished, NATRolePool, NATRoleExempt, NATRoleUnset:
	}
	res, err := e.Query(req)
	if err != nil || res.Incomplete {
		return u
	}
	var others []string
	for _, p := range res.Paths {
		if len(p.NATUncertain) > 0 {
			return u
		}
		for _, h := range pathHits(p, u.Side) {
			if h.Rule == u.Rule {
				u.State, u.ShadowedBy = NATStateActive, ""
				return u
			}
			if h.Rule != nil && !slices.Contains(others, h.Rule.Spec().ID) {
				others = append(others, h.Rule.Spec().ID)
			}
			if h.Static != nil && !slices.Contains(others, h.Static.Spec().ID) {
				others = append(others, h.Static.Spec().ID)
			}
		}
	}
	if len(others) > 0 {
		u.State, u.ShadowedBy = NATStateShadowed, strings.Join(others, ",")
	}
	return u
}

// pathHits are the translations of one side on a path.
func pathHits(p Path, side firemon.NATKind) []NATHit {
	var out []NATHit
	if p.DestinationNAT != nil && p.DestinationNAT.Side == side {
		out = append(out, *p.DestinationNAT)
	}
	for _, h := range p.SourceNAT {
		if h.Side == side {
			out = append(out, h)
		}
	}
	return out
}
