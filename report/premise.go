package report

import (
	"slices"
	"strconv"
	"strings"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/inventory"
	"github.com/gatework/firemon/query"
	"github.com/gatework/firemon/traffic"
)

// Premise kinds.
const (
	// PremiseApplication: the traffic is taken to be the standard
	// application of its ports.
	PremiseApplication = "application"
	// PremiseUser, PremiseURLCategory and PremiseSchedule: a rule whose
	// user, URL-category or schedule criterion the request does not settle
	// was taken not to match, and would change the result if it did.
	PremiseUser        = "user"
	PremiseURLCategory = "url-category"
	PremiseSchedule    = "schedule"
	// PremiseDomain: the requested addresses are taken not to be ones the
	// domain names of a rule resolve to.
	PremiseDomain = "domain"
)

// Premise is an assumption the result rests on (ADR 0017): stated, so the
// operator can confirm it or ask again with the criterion given.
type Premise struct {
	Kinds   []string `json:"kinds"`
	Cluster string   `json:"cluster,omitempty"`
	// Service and Applications describe an application premise; no
	// applications means the ports belong to no standard application.
	Service      string   `json:"service,omitempty"`
	Applications []string `json:"applications,omitempty"`
	// Rule, Name, Criteria and Action describe the rule a criterion
	// premise is about and what it does when its criterion holds; Traffic
	// is what it would decide, Decider the rule deciding it now.
	Rule     string         `json:"rule,omitempty"`
	Name     string         `json:"name,omitempty"`
	Criteria []string       `json:"criteria,omitempty"`
	Action   firemon.Action `json:"action,omitzero"`
	Traffic  string         `json:"traffic,omitempty"`
	Decider  string         `json:"decider,omitempty"`
}

// premisesOf collects the premises of one crossing: one application
// premise for every inferred path, and one premise per rule and decider
// whose traffic accumulates as spaces, written once and bounded.
func premisesOf(c inventory.Crossing) []Premise {
	var out []Premise
	var spaces [][]traffic.Space
	var appSvc traffic.ServiceSet
	var apps []string
	for _, p := range c.Paths {
		if p.AppInferred && p.AppDecisive {
			appSvc = appSvc.Union(p.Original.Service)
			apps = append(apps, p.AppFamily...)
		}
		for _, d := range p.Decisions {
			for _, r := range d.Conditional() {
				pr := rulePremise(c.Cluster, r, d)
				// One premise per rule: the rules it would take the traffic
				// from are listed together.
				i := slices.IndexFunc(out, func(x Premise) bool { return x.Rule == pr.Rule })
				if i < 0 {
					out, spaces = append(out, pr), append(spaces, nil)
					i = len(out) - 1
				} else if !slices.Contains(strings.Split(out[i].Decider, ","), pr.Decider) {
					out[i].Decider += "," + pr.Decider
				}
				spaces[i] = append(spaces[i], d.Space.Spaces()...)
			}
		}
	}
	for i := range out {
		out[i].Traffic = boundedText(spaces[i])
	}
	if !appSvc.IsEmpty() {
		ap := Premise{Kinds: []string{PremiseApplication}, Service: appSvc.String(), Applications: foldApps(apps)}
		out = append([]Premise{ap}, out...)
	}
	return out
}

func rulePremise(cluster string, r *firemon.Rule, d query.Decision) Premise {
	spec := r.Spec()
	pr := Premise{Cluster: cluster, Rule: spec.ID, Name: spec.Name, Action: spec.Action, Decider: hitID(d.Rule)}
	if users := firemon.ConditionValues(spec.Conditions, firemon.ConditionUser); len(users) > 0 {
		pr.Kinds, pr.Criteria = append(pr.Kinds, PremiseUser), append(pr.Criteria, users...)
	}
	if cats := firemon.ConditionValues(spec.Conditions, firemon.ConditionURLCategory); len(cats) > 0 {
		pr.Kinds, pr.Criteria = append(pr.Kinds, PremiseURLCategory), append(pr.Criteria, cats...)
	}
	if byDomainIssue(r) {
		pr.Kinds = append(pr.Kinds, PremiseDomain)
		names := r.DstDomains().Patterns()
		if len(names) > 3 {
			names = append(names[:3], "等 "+strconv.Itoa(len(r.DstDomains().Patterns()))+" 个域名")
		}
		pr.Criteria = append(pr.Criteria, names...)
	}
	if r.Scheduled() {
		pr.Kinds = append(pr.Kinds, PremiseSchedule)
		if spec.Schedule != "" {
			pr.Criteria = append(pr.Criteria, spec.Schedule)
		}
		if w := spec.Window; w != (firemon.TimeWindow{}) {
			pr.Criteria = append(pr.Criteria, windowText(w))
		}
	}
	return pr
}

// mergePremise adds pr to the report's premises: one application premise
// for every firewall, the services and applications joined.
func mergePremise(all []Premise, pr Premise) []Premise {
	if pr.Rule != "" || len(pr.Kinds) != 1 || pr.Kinds[0] != PremiseApplication {
		return append(all, pr)
	}
	i := slices.IndexFunc(all, func(x Premise) bool { return x.Rule == "" && slices.Equal(x.Kinds, pr.Kinds) })
	if i < 0 {
		return append([]Premise{pr}, all...)
	}
	a, _ := traffic.ParseServiceSet(all[i].Service)
	b, _ := traffic.ParseServiceSet(pr.Service)
	all[i].Service = a.Union(b).String()
	all[i].Applications = foldApps(append(slices.Clone(all[i].Applications), pr.Applications...))
	return all
}

func byDomainIssue(r *firemon.Rule) bool {
	return slices.ContainsFunc(r.Issues(), func(is firemon.Issue) bool {
		return is.Kind == firemon.IssueKindDomain || is.Kind == firemon.IssueKindDestinationDomain
	})
}
