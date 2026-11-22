package audit

import (
	"cmp"
	"slices"
	"strings"
	"time"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/traffic"
)

// Options configures an audit. The zero value audits at time.Now with a
// budget of DefaultMaxSpaces per rule.
type Options struct {
	Now       func() time.Time
	MaxSpaces int
}

// DefaultMaxSpaces bounds the remainder tracked for one rule.
const DefaultMaxSpaces = 5000

// Run audits fw.
func Run(fw *firemon.Firewall, opts Options) Report {
	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}
	budget := opts.MaxSpaces
	if budget <= 0 {
		budget = DefaultMaxSpaces
	}
	at := now()
	var r Report
	rules := fw.Rules()
	sure := make([]bool, len(rules))
	for i, rule := range rules {
		sure[i] = certain(rule, at)
	}
	for i, rule := range rules {
		r.Findings = append(r.Findings, ruleFindings(rule, at)...)
		if !sure[i] || rule.Match().IsEmpty() {
			continue
		}
		f, complete := shadowing(rule, rules[:i], sure[:i], budget)
		if !complete {
			r.Incomplete = append(r.Incomplete, rule.ID())
		}
		if f != nil {
			r.Findings = append(r.Findings, *f)
		}
	}
	r.Findings = append(r.Findings, objectFindings(fw)...)
	return r
}

// certain reports whether a rule's match is exact, enabled and
// unscheduled, so it is in effect at every instant. A rule restricted only
// by applications counts: its five-tuple match is exact, and coverage
// compares its applications (covers).
func certain(r *firemon.Rule, at time.Time) bool {
	exact := r.Decidable() || (r.DecidableWithout(firemon.IssueKindApplication) && !r.DefaultPorts())
	return exact && !r.Scheduled() && !r.InactiveAt(at)
}

func ruleFindings(r *firemon.Rule, at time.Time) []Finding {
	spec := r.Spec()
	var out []Finding
	switch {
	case spec.Incomplete != "":
		return []Finding{{Kind: KindIncomplete, Rule: r.ID(), Detail: spec.Incomplete}}
	case spec.Disabled:
		out = append(out, Finding{Kind: KindDisabled, Rule: r.ID()})
	case r.ExpiredAt(at):
		out = append(out, Finding{Kind: KindExpired, Rule: r.ID()})
	}
	if !r.Decidable() && !r.Conditional() {
		// Rules by application, user, URL category or domain are settled
		// by a query's premises (ADR 0017); only the rest is undecidable.
		out = append(out, Finding{Kind: KindUndecidable, Rule: r.ID(), Detail: joinIssues(r.Issues())})
	}
	m := r.Match()
	if r.Decidable() && m.IsEmpty() {
		out = append(out, Finding{Kind: KindNeverMatches, Rule: r.ID(), Detail: "an operand is empty"})
	}
	if r.Action() == firemon.ActionPermit && r.Decidable() && !spec.Disabled && anyFamily(m.Src, m.Dst) && m.Service.IsAny() {
		out = append(out, Finding{Kind: KindPermitAny, Rule: r.ID(), Detail: "zones " + zones(spec.From) + " -> " + zones(spec.To)})
	}
	return out
}

// shadowing finds the earlier rules covering r on every zone pair r applies
// to. It returns nil when part of r remains reachable.
// sure tells which earlier rules are certain.
func shadowing(r *firemon.Rule, earlier []*firemon.Rule, sure []bool, budget int) (*Finding, bool) {
	if !projectionsCovered(r, earlier, sure) {
		return nil, true // some packet of r no earlier rule can match
	}
	remaining := traffic.NewRegion(r.Match())
	var by []string
	opposite := false
	for i, e := range earlier {
		if remaining.IsEmpty() {
			break
		}
		if !sure[i] || !covers(e, r) || !remaining.Overlaps(e.Match()) {
			continue
		}
		by = append(by, e.ID())
		opposite = opposite || e.Action() != r.Action()
		remaining = remaining.Subtract(e.Match())
		if remaining.Len() > budget {
			return coveredAnyOrder(r, earlier, sure, budget)
		}
	}
	if !remaining.IsEmpty() {
		return nil, true
	}
	kind := KindRedundant
	if opposite {
		kind = KindShadowed
	}
	return &Finding{Kind: kind, Rule: r.ID(), By: by}, true
}

// projectionsCovered is a cheap, exact test that r is not covered: the
// earlier rules that may cover it must together hold its sources, its
// destinations and its services, each dimension on its own. A source no
// earlier rule names is a packet of r nothing before it matches. Broad
// rules ("any to any") end here instead of in a region that splits into
// thousands of pieces.
func projectionsCovered(r *firemon.Rule, earlier []*firemon.Rule, sure []bool) bool {
	m := r.Match()
	var src, dst traffic.AddressSet
	var svc traffic.ServiceSet
	for i, e := range earlier {
		if !sure[i] || !covers(e, r) {
			continue
		}
		em := e.Match()
		if !em.Overlaps(m) {
			continue
		}
		src, dst, svc = src.Union(em.Src.Intersect(m.Src)), dst.Union(em.Dst.Intersect(m.Dst)), svc.Union(em.Service.Intersect(m.Service))
	}
	return src.ContainsSet(m.Src) && dst.ContainsSet(m.Dst) && svc.ContainsSet(m.Service)
}

// covers reports whether e applies to every zone pair r applies to and to
// every application r matches: e matches any application, or r names
// applications that e all admits (directly or through a group).
func covers(e, r *firemon.Rule) bool {
	if apps := e.Applications(); len(apps) > 0 {
		rApps := r.Applications()
		if len(rApps) == 0 {
			return false
		}
		for _, a := range rApps {
			if !e.MatchesApplication(a) {
				return false
			}
		}
	}
	return zonesCover(e, r)
}

// zonesCover reports whether e applies to every zone pair r applies to.
func zonesCover(e, r *firemon.Rule) bool {
	eFrom, eTo := e.Zones()
	rFrom, rTo := r.Zones()
	return zoneSuperset(eFrom, rFrom) && zoneSuperset(eTo, rTo) && r.Scope().Covers(e.Scope())
}

func zoneSuperset(outer, inner []string) bool {
	if len(outer) == 0 {
		return true
	}
	if len(inner) == 0 {
		return false
	}
	for _, z := range inner {
		if !slices.Contains(outer, z) {
			return false
		}
	}
	return true
}

func zones(z []string) string {
	if len(z) == 0 {
		return "any"
	}
	return strings.Join(z, ",")
}

func joinIssues(issues []firemon.Issue) string {
	parts := make([]string, len(issues))
	for i, is := range issues {
		parts[i] = is.Reason
	}
	return strings.Join(parts, "; ")
}

// anyFamily reports whether src and dst both hold every address of one
// family.
func anyFamily(src, dst traffic.AddressSet) bool {
	for _, all := range []traffic.AddressSet{traffic.AnyIPv4(), traffic.AnyIPv6()} {
		if src.ContainsSet(all) && dst.ContainsSet(all) {
			return true
		}
	}
	return false
}

// coveredAnyOrder decides coverage when subtracting the earlier rules in
// device order splits r into too many pieces: whether r is covered does
// not depend on the order, so the rules covering most go first and the
// pieces stay few. Which rule decides each packet does: when the covering
// rules all share r's action, r is redundant; when one has the opposite
// action it may decide part of r, and r is reported shadowed, the reading
// that asks a person to look. Either way r never takes effect.
func coveredAnyOrder(r *firemon.Rule, earlier []*firemon.Rule, sure []bool, budget int) (*Finding, bool) {
	m := r.Match()
	var cands []*firemon.Rule
	for i, e := range earlier {
		if sure[i] && covers(e, r) && e.Match().Overlaps(m) {
			if e.Match().ContainsSpace(m) {
				return coverFinding(r, []*firemon.Rule{e}), true
			}
			cands = append(cands, e)
		}
	}
	slices.SortStableFunc(cands, func(a, b *firemon.Rule) int {
		return cmp.Compare(volume(b.Match().Intersect(m)), volume(a.Match().Intersect(m)))
	})
	remaining := traffic.NewRegion(m)
	var used []*firemon.Rule
	for _, e := range cands {
		if remaining.IsEmpty() {
			break
		}
		if !remaining.Overlaps(e.Match()) {
			continue
		}
		used = append(used, e)
		remaining = remaining.Subtract(e.Match())
		if remaining.Len() > budget {
			return nil, false
		}
	}
	if !remaining.IsEmpty() {
		return nil, true
	}
	slices.SortFunc(used, func(a, b *firemon.Rule) int { return cmp.Compare(a.Position(), b.Position()) })
	return coverFinding(r, used), true
}

// coverFinding reports r covered by rules.
func coverFinding(r *firemon.Rule, by []*firemon.Rule) *Finding {
	kind := KindRedundant
	ids := make([]string, len(by))
	for i, e := range by {
		ids[i] = e.ID()
		if e.Action() != r.Action() {
			kind = KindShadowed
		}
	}
	return &Finding{Kind: kind, Rule: r.ID(), By: ids}
}

// volume estimates how much traffic a space holds, for ordering.
func volume(s traffic.Space) float64 {
	count := func(a traffic.AddressSet) float64 {
		var n float64
		for _, rg := range a.Ranges() {
			from, to := rg.From().As16(), rg.To().As16()
			n += float64(uint32(to[12])<<24|uint32(to[13])<<16|uint32(to[14])<<8|uint32(to[15])) -
				float64(uint32(from[12])<<24|uint32(from[13])<<16|uint32(from[14])<<8|uint32(from[15])) + 1
		}
		return n
	}
	ports := 0.0
	for rg := range s.Service.All() {
		ports += float64(int(rg.ProtocolHigh)-int(rg.ProtocolLow)+1) * float64(int(rg.Dst.High)-int(rg.Dst.Low)+1)
	}
	return count(s.Src) * count(s.Dst) * ports
}
