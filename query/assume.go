package query

import (
	"slices"
	"strings"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/traffic"
)

// webPorts are the ports URL filtering inspects: a target whose
// applications use none of them is not web traffic.
var webPorts = traffic.PortService(traffic.ProtocolTCP, traffic.Port(80)).
	Union(traffic.PortService(traffic.ProtocolTCP, traffic.Port(443))).
	Union(traffic.PortService(traffic.ProtocolTCP, traffic.Port(8080))).
	Union(traffic.PortService(traffic.ProtocolTCP, traffic.Port(8443)))

// conditionView settles a rule's user and URL-category criteria (ADR 0017).
// They are matched against the request's users and categories when given.
// A URL category never matches an identified application that is not web
// traffic. Otherwise the rule is taken not to match and the path records
// the premise. A rule with any other unresolved part is left as it is: a
// possible match.
func (e *Engine) conditionView(r *firemon.Rule, p *Path, v view, named bool) view {
	conds := r.Spec().Conditions
	users := firemon.ConditionValues(conds, firemon.ConditionUser)
	cats := firemon.ConditionValues(conds, firemon.ConditionURLCategory)
	if p.strict || (len(users) == 0 && len(cats) == 0) {
		return v
	}
	settled := []firemon.IssueKind{firemon.IssueKindUser, firemon.IssueKindURLCategory}
	if named {
		settled = append(settled, firemon.IssueKindApplication)
	}
	if p.Domain != "" {
		settled = append(settled, firemon.IssueKindDestinationDomain)
	}
	if !r.DecidableWithout(settled...) {
		return v
	}
	assumed := false
	if len(cats) > 0 {
		switch {
		case named && !e.webTraffic(p):
			return view{skip: true}
		case len(p.urlCategories) == 0:
			assumed = true
		case !anyFold(cats, p.urlCategories):
			return view{skip: true}
		}
	}
	if len(users) > 0 {
		switch {
		case len(p.users) == 0:
			assumed = true
		case !anyFold(users, p.users):
			return view{skip: true}
		}
	}
	if assumed {
		return view{skip: true, assumed: true, bound: v.bound}
	}
	// Every criterion holds: the rule is exact on this target, unless the
	// application or domain view left it undecidable for other reasons.
	v.decidable = v.decidable || r.DecidableWithout(settled...)
	return v
}

// webTraffic reports whether the applications of a path may be web
// traffic: they use a web port, or the path is unidentified.
func (e *Engine) webTraffic(p *Path) bool {
	if p.AppUnidentified {
		return true
	}
	return e.webApps(p.matchApps())
}

// webApps reports whether one of apps uses a web port or has unknown ports.
func (e *Engine) webApps(apps []string) bool {
	for _, a := range apps {
		ports, ok := e.fw.ApplicationPorts(a)
		if !ok || ports.Overlaps(webPorts) {
			return true
		}
	}
	return false
}

func anyFold(values, wanted []string) bool {
	return slices.ContainsFunc(values, func(v string) bool {
		return slices.ContainsFunc(wanted, func(w string) bool { return strings.EqualFold(v, w) })
	})
}

// settledKinds are the issue kinds a premise settles on an address target:
// domain names a rule may resolve to, users and URL categories, and
// applications when the target is identified.
func (e *Engine) settledKinds(named bool) []firemon.IssueKind {
	out := []firemon.IssueKind{firemon.IssueKindDomain, firemon.IssueKindDestinationDomain, firemon.IssueKindUser, firemon.IssueKindURLCategory}
	if named {
		out = append(out, firemon.IssueKindApplication)
	}
	return out
}

// byDomain reports a rule with domain names among its operands.
func byDomain(r *firemon.Rule) bool {
	return slices.ContainsFunc(r.Issues(), func(is firemon.Issue) bool {
		return is.Kind == firemon.IssueKindDomain || is.Kind == firemon.IssueKindDestinationDomain
	})
}
