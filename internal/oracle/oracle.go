// Package oracle decides single packets the way a firewall does, by
// reading the security rules from the top and stopping at the first that
// matches. It shares no code with the query engine, which evaluates whole
// regions of traffic by splitting them: tests compare the two on boundary
// packets of every rule to prove the engine's first-match decisions.
//
// The oracle answers the policy question only: the packet is given as the
// security rules see it (after any translation) together with its zones.
package oracle

import (
	"net/netip"
	"slices"
	"time"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/traffic"
)

// Packet is one packet as the security policy sees it.
type Packet struct {
	Src, Dst netip.Addr
	Protocol traffic.Protocol
	SrcPort  uint16
	DstPort  uint16
	From, To string
}

// Service returns the packet's service as a one-point set.
func (p Packet) Service() traffic.ServiceSet {
	return traffic.NewService(p.Protocol, traffic.PortRange{Low: p.SrcPort, High: p.SrcPort}, traffic.PortRange{Low: p.DstPort, High: p.DstPort})
}

// Verdict is the decision on one packet.
type Verdict struct {
	// Rule is the first rule that certainly matches; nil when the default
	// action decides.
	Rule *firemon.Rule
	// Possible are the rules above Rule that might match: rules the model
	// cannot evaluate exactly, or whose schedule it cannot read.
	Possible []*firemon.Rule
	// Default is the default action when no rule matches.
	Default firemon.Action
}

// Action is what the deciding rule, or the default, does.
func (v Verdict) Action() firemon.Action {
	if v.Rule != nil {
		return v.Rule.Action()
	}
	return v.Default
}

// Settled reports whether the possible rules cannot change the result:
// each of them would permit exactly when the decision permits.
func (v Verdict) Settled() bool {
	a := v.Action()
	for _, r := range v.Possible {
		if a == firemon.ActionUnset || r.Action() == firemon.ActionUnset || (r.Action() == firemon.ActionPermit) != (a == firemon.ActionPermit) {
			return false
		}
	}
	return true
}

// Decide returns the first-match decision on p at instant at.
func Decide(fw *firemon.Firewall, p Packet, at time.Time) Verdict {
	svc := p.Service()
	var v Verdict
	for _, r := range fw.Rules() {
		if r.Ignored() || !applies(r, p.From, p.To) || r.InactiveAt(at) {
			continue
		}
		scheduleKnown := r.ActiveAt(at) // InactiveAt is false: active, or unreadable
		certain, exact := r.Certain()
		switch {
		case exact && scheduleKnown && contains(certain, p, svc):
			v.Rule = r
			return v
		case contains(r.Bound(), p, svc):
			v.Possible = append(v.Possible, r)
		}
	}
	v.Default = fw.Semantics().InterzoneAction
	if p.From == p.To {
		v.Default = fw.Semantics().IntrazoneAction
	}
	return v
}

// applies reports whether a rule is written for the zone pair: an empty
// list is any zone, and the scope restricts to or excludes one zone.
func applies(r *firemon.Rule, from, to string) bool {
	in := func(zones []string, z string) bool { return len(zones) == 0 || slices.Contains(zones, z) }
	fromZones, toZones := r.Zones()
	if !in(fromZones, from) || !in(toZones, to) {
		return false
	}
	switch r.Scope() {
	case firemon.ZoneScopeIntra:
		return from == to
	case firemon.ZoneScopeInter:
		return from != to
	case firemon.ZoneScopeAny:
		return true
	default:
		return true
	}
}

func contains(s traffic.Space, p Packet, svc traffic.ServiceSet) bool {
	return s.Src.Contains(p.Src) && s.Dst.Contains(p.Dst) && s.Service.ContainsSet(svc)
}
