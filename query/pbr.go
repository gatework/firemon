package query

import (
	"slices"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/traffic"
)

// routed is part of a piece with the egress policy-based routing chose
// for it (nil: the routing table decides) and the conditions under which
// that holds.
type routed struct {
	piece      natPiece
	out        *hop
	policy     string // policy route that chose out
	conditions []string
}

// policyRoute applies the policy routes bound to the ingress zone or
// interface, first match per packet, to a translated piece. An entry that
// cannot be decided offline (user groups, unresolved domains) splits the
// traffic into a branch that takes it, conditioned on the entry matching,
// and a branch that does not.
func (e *Engine) policyRoute(pc natPiece, in hop, domain string) []routed {
	rules := e.fw.PolicyRoutesFor(in.zone, in.iface)
	work := []routed{{piece: pc}}
	if len(rules) == 0 {
		return work
	}
	var done []routed
	for _, r := range rules {
		if vr := r.Spec().VirtualRouter; vr != "" && in.vr != "" && vr != in.vr {
			continue
		}
		var next []routed
		for _, w := range work {
			taken, rest := e.applyPolicyRoute(r, w, domain)
			done = append(done, taken...)
			next = append(next, rest...)
		}
		work = next
	}
	return append(done, work...)
}

// applyPolicyRoute splits one undecided part by one entry.
func (e *Engine) applyPolicyRoute(r *firemon.PBRRule, w routed, domain string) (taken, rest []routed) {
	s := w.piece.translated
	match, bound := r.Match(), r.Bound()
	decidable := r.DecidableFor(domain != "")
	if domain != "" && r.DstDomains().Match(domain) {
		match.Dst, bound.Dst = traffic.AnyAddress(), traffic.AnyAddress()
	} else if domain != "" && !match.Dst.ContainsSet(traffic.AnyIPv4()) {
		decidable = false // an unresolved name may or may not be one of the addresses
		bound.Dst = traffic.AnyAddress()
	}
	id := r.Spec().Policy + "/" + r.Spec().ID
	iface, zone := r.Egress()
	out := &hop{vr: r.Spec().VirtualRouter, zone: zone, iface: iface, prefixLen: -1}
	if !decidable {
		maybe := s.Intersect(bound)
		if maybe.IsEmpty() {
			return nil, []routed{w}
		}
		yes := w.restrict(maybe)
		yes.out, yes.policy, yes.conditions = out, id, append(clip(w.conditions), "policy route "+id+" matches")
		no := w.restrict(maybe)
		no.conditions = append(clip(w.conditions), "policy route "+id+" does not match")
		return []routed{yes}, append([]routed{no}, w.restrictAll(s.Subtract(bound))...)
	}
	hit := s.Intersect(match)
	if hit.IsEmpty() {
		return nil, []routed{w}
	}
	t := w.restrict(hit)
	t.out, t.policy = out, id
	return []routed{t}, w.restrictAll(s.Subtract(match))
}

func clip(s []string) []string { return slices.Clip(s) }

// restrict narrows a routed part to space s of its translated traffic.
func (w routed) restrict(s traffic.Space) routed {
	out := w
	out.piece.translated = s
	out.piece.original.Src = s.Src
	if out.piece.dstHit == nil {
		out.piece.original = s
	}
	return out
}

func (w routed) restrictAll(spaces []traffic.Space) []routed {
	out := make([]routed, 0, len(spaces))
	for _, s := range spaces {
		out = append(out, w.restrict(s))
	}
	return out
}
