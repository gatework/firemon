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
	conditions []Condition
}

// policyRoute applies the policy routes bound to the ingress zone or
// interface, first match per packet, to a translated piece. An entry that
// cannot be decided offline (user groups, unresolved domains) splits the
// traffic into a branch that takes it, conditioned on the entry matching,
// and a branch that does not.
func (e *search) policyRoute(pc natPiece, in hop) []routed {
	rules := e.fw.PolicyRoutesFor(in.zone, in.iface)
	work := []routed{{piece: pc}}
	if len(rules) == 0 {
		return work
	}
	var done []routed
	for _, r := range rules {
		if e.tooMany(len(work)) {
			break
		}
		if vr := r.Spec().VirtualRouter; vr != "" && in.vr != "" && vr != in.vr {
			continue
		}
		var next []routed
		for _, w := range work {
			taken, rest := e.applyPolicyRoute(r, w, e.domain, e.resolved)
			done = append(done, taken...)
			next = append(next, rest...)
		}
		work = next
	}
	return fold(append(done, work...))
}

// fold removes conditions that do not matter: where both branches of an
// undecidable entry reach the same egress, the traffic takes it whether or
// not the entry matches.
func fold(parts []routed) []routed {
	for i := range parts {
		a := parts[i]
		n := len(a.conditions)
		if a.out == nil || n == 0 || !a.conditions[n-1].Matches {
			continue
		}
		for j := range parts {
			b := parts[j]
			if j == i || b.out == nil || b.out.iface != a.out.iface || b.out.zone != a.out.zone || len(b.conditions) != n ||
				!slices.Equal(b.conditions[:n-1], a.conditions[:n-1]) || b.conditions[n-1] != (Condition{PolicyRoute: a.conditions[n-1].PolicyRoute}) {
				continue
			}
			both := a.piece.translated.Intersect(b.piece.translated)
			if both.IsEmpty() {
				continue
			}
			merged := b.restrict(both)
			merged.conditions = slices.Clip(a.conditions[:n-1])
			var rest []routed
			rest = append(rest, a.restrictAll(a.piece.translated.Subtract(both))...)
			rest = append(rest, b.restrictAll(b.piece.translated.Subtract(both))...)
			out := slices.Concat(parts[:min(i, j)], parts[min(i, j)+1:max(i, j)], parts[max(i, j)+1:], []routed{merged}, rest)
			return fold(out)
		}
	}
	return parts
}

// applyPolicyRoute splits one undecided part by one entry.
func (e *Engine) applyPolicyRoute(r *firemon.PBRRule, w routed, domain string, resolved bool) (taken, rest []routed) {
	s := w.piece.translated
	v := view{match: r.Match(), bound: r.Bound(), decidable: r.DecidableFor(domain != "")}
	if domain != "" {
		v = domainView(v, r.DstDomains(), r.DecidableFor(true), domain, resolved, s.Dst)
	}
	if v.skip {
		return nil, []routed{w}
	}
	match, bound, decidable := v.match, v.bound, v.decidable
	id := r.Spec().Policy + "/" + r.Spec().ID
	forward := func(t routed) []routed {
		t.policy = id
		exits := r.Egresses()
		if len(exits) == 0 {
			t.out = &hop{prefixLen: -1}
			return []routed{t}
		}
		out := make([]routed, 0, len(exits))
		for _, exit := range exits {
			t.out = &hop{vr: exit.Route.VirtualRouter, zone: exit.Zone, iface: exit.Interface, prefixLen: -1}
			out = append(out, t)
		}
		return out
	}
	if !decidable {
		maybe := s.Intersect(bound)
		if maybe.IsEmpty() {
			return nil, []routed{w}
		}
		yes := w.restrict(maybe)
		yes.conditions = append(slices.Clip(w.conditions), Condition{PolicyRoute: id, Matches: true})
		no := w.restrict(maybe)
		no.conditions = append(slices.Clip(w.conditions), Condition{PolicyRoute: id})
		return forward(yes), append([]routed{no}, w.restrictAll(s.Subtract(bound))...)
	}
	hit := s.Intersect(match)
	if hit.IsEmpty() {
		return nil, []routed{w}
	}
	t := w.restrict(hit)
	return forward(t), w.restrictAll(s.Subtract(match))
}

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
