package audit

import (
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
		if !sure[i] {
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
	r.Findings = append(r.Findings, unused(fw)...)
	return r
}

// certain reports whether a rule is decidable, enabled and unscheduled, so
// its match is in effect at every instant.
func certain(r *firemon.Rule, at time.Time) bool {
	return r.Decidable() && !r.Scheduled() && !r.InactiveAt(at)
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
	if !r.Decidable() {
		out = append(out, Finding{Kind: KindUndecidable, Rule: r.ID(), Detail: joinIssues(r.Issues())})
	}
	m := r.Match()
	if r.Action() == firemon.ActionPermit && r.Decidable() && m.Src.ContainsSet(traffic.AnyIPv4()) &&
		m.Dst.ContainsSet(traffic.AnyIPv4()) && m.Service.IsAny() {
		out = append(out, Finding{Kind: KindPermitAny, Rule: r.ID(), Detail: "zones " + zones(spec.From) + " -> " + zones(spec.To)})
	}
	return out
}

// shadowing finds the earlier rules covering r on every zone pair r applies
// to. It returns nil when part of r remains reachable.
// sure tells which earlier rules are certain.
func shadowing(r *firemon.Rule, earlier []*firemon.Rule, sure []bool, budget int) (*Finding, bool) {
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
			return nil, false
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

// covers reports whether e applies to every zone pair r applies to.
func covers(e, r *firemon.Rule) bool {
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
