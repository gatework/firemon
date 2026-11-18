package report

import (
	"cmp"
	"slices"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/design"
	"github.com/gatework/firemon/query"
	"github.com/gatework/firemon/traffic"
)

// Reason says why a candidate rule is not a safe one to modify.
type Reason string

// Reasons.
const (
	// ReasonSeveralDimensions: the rule lacks more than one dimension.
	ReasonSeveralDimensions Reason = "several-dimensions"
	// ReasonWider: a dimension the rule already covers is wider than the
	// request, so extending it would permit traffic nobody asked for.
	ReasonWider Reason = "wider-than-request"
	// ReasonZoneAny: the rule applies to every zone, so a change reaches
	// other zone pairs too.
	ReasonZoneAny Reason = "zone-any"
	// ReasonScheduled: the rule is time-limited.
	ReasonScheduled Reason = "scheduled"
	// ReasonApplications: the rule matches by application.
	ReasonApplications Reason = "applications"
	// ReasonUndecidable: the rule's match cannot be evaluated exactly.
	ReasonUndecidable Reason = "undecidable"
	// ReasonAfterDeny: a deny before the rule decides the traffic first.
	ReasonAfterDeny Reason = "after-deny"
)

// MaxCandidates is the number of candidates reported per firewall.
const MaxCandidates = 3

// Candidate is an existing permit rule that could carry the remaining
// traffic, with how each dimension relates to it (from the rule's point of
// view) and why it is or is not a good one to modify.
type Candidate struct {
	Rule        string           `json:"rule"`
	Name        string           `json:"name,omitempty"`
	From        string           `json:"from"`
	To          string           `json:"to"`
	Src         traffic.Relation `json:"src"`
	Dst         traffic.Relation `json:"dst"`
	Service     traffic.Relation `json:"service"`
	Covers      int              `json:"covers"`
	Extendable  bool             `json:"extendable"`
	Recommended bool             `json:"recommended,omitempty"`
	Reasons     []Reason         `json:"reasons,omitempty"`
	position    int
}

// pairNeed is what one zone pair still needs and the request scope there.
type pairNeed struct {
	from, to    string
	need, scope traffic.Region
	firstDeny   int // position of the first deny deciding part of the request; -1 when none
}

// candidates ranks the permit rules that could be modified to carry the
// remaining traffic of the paths.
func candidates(fw *firemon.Firewall, paths []query.Path, plan *design.Plan) []Candidate {
	recommended := ""
	if plan != nil {
		for _, ch := range plan.Changes {
			if x, ok := ch.(design.ExtendRule); ok {
				recommended = x.RuleID
			}
		}
	}
	var out []Candidate
	for _, pn := range needsByPair(paths) {
		for _, r := range fw.Rules() {
			if c, ok := assess(r, pn); ok {
				c.Recommended = c.Rule == recommended
				out = append(out, c)
			}
		}
	}
	slices.SortStableFunc(out, func(a, b Candidate) int {
		return cmp.Or(compareBool(b.Recommended, a.Recommended), compareBool(b.Extendable, a.Extendable),
			cmp.Compare(b.Covers, a.Covers), cmp.Compare(len(a.Reasons), len(b.Reasons)), cmp.Compare(a.position, b.position))
	})
	return out[:min(len(out), MaxCandidates)]
}

func needsByPair(paths []query.Path) []pairNeed {
	var out []pairNeed
	for _, p := range paths {
		i := slices.IndexFunc(out, func(n pairNeed) bool { return n.from == p.From && n.to == p.To })
		if i < 0 {
			out = append(out, pairNeed{from: p.From, to: p.To, firstDeny: -1})
			i = len(out) - 1
		}
		n := &out[i]
		n.scope = n.scope.Add(p.Policy)
		for _, d := range p.Decisions {
			if d.Outcome != query.OutcomeDeny && d.Outcome != query.OutcomeDefault {
				continue
			}
			n.need = n.need.Union(d.Space)
			if d.Rule != nil && (n.firstDeny < 0 || d.Rule.Position() < n.firstDeny) {
				n.firstDeny = d.Rule.Position()
			}
		}
	}
	return slices.DeleteFunc(out, func(n pairNeed) bool { return n.need.IsEmpty() })
}

// assess relates one rule to one zone pair's need.
func assess(r *firemon.Rule, pn pairNeed) (Candidate, bool) {
	spec := r.Spec()
	if r.Action() != firemon.ActionPermit || r.Ignored() || !r.Applies(pn.from, pn.to) {
		return Candidate{}, false
	}
	need, scope, m := pn.need.Bounds(), pn.scope.Bounds(), r.Match()
	c := Candidate{
		Rule: r.ID(), Name: spec.Name, From: pn.from, To: pn.to, position: r.Position(),
		Src: m.Src.Relation(need.Src), Dst: m.Dst.Relation(need.Dst), Service: m.Service.Relation(need.Service),
	}
	if c.Src == traffic.RelationDisjoint && c.Dst == traffic.RelationDisjoint && c.Service == traffic.RelationDisjoint {
		return Candidate{}, false
	}
	wider := false
	for _, d := range []struct {
		rel     traffic.Relation
		inScope bool
	}{
		{c.Src, scope.Src.ContainsSet(m.Src)},
		{c.Dst, scope.Dst.ContainsSet(m.Dst)},
		{c.Service, scope.Service.ContainsSet(m.Service)},
	} {
		if d.rel.Covers() {
			c.Covers++
			wider = wider || !d.inScope
		}
	}
	c.Reasons = reasons(r, pn, c.Covers, wider)
	c.Extendable = len(c.Reasons) == 0
	return c, true
}

func reasons(r *firemon.Rule, pn pairNeed, covers int, wider bool) []Reason {
	spec := r.Spec()
	var out []Reason
	if covers < 2 {
		out = append(out, ReasonSeveralDimensions)
	}
	if wider {
		out = append(out, ReasonWider)
	}
	if len(spec.From) == 0 || len(spec.To) == 0 {
		out = append(out, ReasonZoneAny)
	}
	if r.Scheduled() {
		out = append(out, ReasonScheduled)
	}
	if len(spec.Applications) > 0 {
		out = append(out, ReasonApplications)
	}
	if !r.Decidable() {
		out = append(out, ReasonUndecidable)
	}
	if pn.firstDeny >= 0 && r.Position() > pn.firstDeny {
		out = append(out, ReasonAfterDeny)
	}
	return out
}

// box returns the smallest space containing every space of r.
func compareBool(a, b bool) int {
	switch {
	case a == b:
		return 0
	case a:
		return 1
	default:
		return -1
	}
}
