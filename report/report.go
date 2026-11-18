package report

import (
	"slices"
	"strings"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/design"
	"github.com/gatework/firemon/intake"
	"github.com/gatework/firemon/inventory"
	"github.com/gatework/firemon/query"
	"github.com/gatework/firemon/traffic"
)

// Status classifies the access control result on one firewall.
type Status uint8

// Statuses, from best to worst for the requester.
const (
	StatusUnset Status = iota
	// StatusFullMatch: existing rules permit all of the request.
	StatusFullMatch
	// StatusPartialMatch: existing rules permit part of the request.
	StatusPartialMatch
	// StatusNeedNew: nothing permits the request and no rule blocks it.
	StatusNeedNew
	// StatusBlocked: specific deny rules block (part of) the request.
	StatusBlocked
	// StatusIndeterminate: rules that cannot be evaluated offline decide
	// part of the request.
	StatusIndeterminate
)

// String returns the status name used in JSON output.
func (s Status) String() string {
	switch s {
	case StatusUnset:
		return "unset"
	case StatusFullMatch:
		return "full-match"
	case StatusPartialMatch:
		return "partial-match"
	case StatusNeedNew:
		return "need-new"
	case StatusBlocked:
		return "blocked"
	case StatusIndeterminate:
		return "indeterminate"
	default:
		return "invalid"
	}
}

// MarshalText implements encoding.TextMarshaler.
func (s Status) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// Report is the answer to one request.
type Report struct {
	Notes     []intake.Note `json:"notes,omitempty"`
	Excluded  Excluded      `json:"excluded"`
	Ambiguous []string      `json:"ambiguous,omitempty"`
	// ZonesNeeded lists firewalls with layer-2 zones the request did not
	// name zones for.
	ZonesNeeded []string   `json:"zones_needed,omitempty"`
	Firewalls   []Firewall `json:"firewalls"`
	// Status is the worst status over the firewalls.
	Status Status `json:"status"`
}

// Excluded lists the traffic no firewall owns on either end.
type Excluded struct {
	Src string `json:"src,omitempty"`
	Dst string `json:"dst,omitempty"`
}

// Firewall is the result on one cluster.
type Firewall struct {
	Cluster   string              `json:"cluster"`
	Firewall  string              `json:"firewall"`
	Members   []string            `json:"members"`
	Ownership inventory.Ownership `json:"ownership"`
	Paths     []Path              `json:"paths"`
	Status    Status              `json:"status"`
	Permitted []Hit               `json:"permitted,omitempty"`
	Blocked   []Hit               `json:"blocked,omitempty"`
	Undecided []Hit               `json:"undecided,omitempty"`
	// UndecidedTraffic is the traffic the undecided rules may decide.
	UndecidedTraffic string `json:"undecided_traffic,omitempty"`
	// Otherwise are the rules (or the default action) that decide the
	// undecided traffic when the undecided rules do not match.
	Otherwise []Hit  `json:"otherwise,omitempty"`
	Remaining string `json:"remaining,omitempty"`
	// Unrouted is the destination part the firewall has no route for.
	Unrouted string `json:"unrouted,omitempty"`
	// Incomplete reports a cut-short evaluation.
	Incomplete  bool         `json:"incomplete,omitempty"`
	ZonesNeeded bool         `json:"zones_needed,omitempty"`
	Candidates  []Candidate  `json:"candidates,omitempty"`
	Plan        *design.Plan `json:"plan,omitempty"`
}

// Path summarizes one path through a firewall.
type Path struct {
	From        string            `json:"from"`
	To          string            `json:"to"`
	Ingress     string            `json:"ingress,omitempty"`
	Egress      string            `json:"egress,omitempty"`
	Domain      string            `json:"domain,omitempty"`
	Application string            `json:"application,omitempty"`
	PolicyRoute string            `json:"policy_route,omitempty"`
	Conditions  []query.Condition `json:"conditions,omitempty"`
	NAT         []NAT             `json:"nat,omitempty"`
	NATSkipped  []string          `json:"nat_skipped,omitempty"`
	Verdict     query.Verdict     `json:"verdict"`
}

// NAT is one translation applied on a path.
type NAT struct {
	Side       firemon.NATKind `json:"side"`
	Rule       string          `json:"rule"`
	Static     bool            `json:"static,omitempty"`
	Translated string          `json:"translated"`
	// Position is the one-based place of the rule in its NAT list; zero for
	// static mappings and uncertain entries.
	Position  int    `json:"position,omitempty"`
	Traffic   string `json:"traffic,omitempty"`
	Uncertain bool   `json:"uncertain,omitempty"`
}

// Hit is a rule and the part of the request it decides.
type Hit struct {
	Rule    string   `json:"rule"`
	Name    string   `json:"name,omitempty"`
	Traffic string   `json:"traffic"`
	Reasons []string `json:"reasons,omitempty"`
}

// Build assembles the report. fws maps clusters to the evaluated firewall,
// for candidate analysis; plans are optional.
func Build(notes []intake.Note, t inventory.Trace, fws map[string]*firemon.Firewall, plans []inventory.ClusterPlan) Report {
	r := Report{Notes: notes, Ambiguous: t.Ambiguous, ZonesNeeded: t.ZonesNeeded}
	if !t.Excluded.Src.IsEmpty() {
		r.Excluded.Src = t.Excluded.Src.String()
	}
	if !t.Excluded.Dst.IsEmpty() {
		r.Excluded.Dst = t.Excluded.Dst.String()
	}
	for _, c := range t.Crossings {
		f := firewallReport(c)
		f.Plan = planFor(plans, c.Cluster)
		if fw := fws[c.Cluster]; fw != nil && (f.Status == StatusPartialMatch || f.Status == StatusNeedNew || f.Status == StatusBlocked) {
			f.Candidates = candidates(fw, c.Paths, f.Plan)
		}
		r.Firewalls = append(r.Firewalls, f)
		r.Status = max(r.Status, f.Status)
	}
	return r
}

func planFor(plans []inventory.ClusterPlan, cluster string) *design.Plan {
	for _, p := range plans {
		if p.Cluster == cluster {
			return p.Plan
		}
	}
	return nil
}

// firewallReport classifies one crossing.
func firewallReport(c inventory.Crossing) Firewall {
	f := Firewall{
		Cluster: c.Cluster, Firewall: c.Firewall, Members: c.Members, Ownership: c.Ownership,
		Incomplete: c.Incomplete,
	}
	if !c.Unrouted.IsEmpty() {
		f.Unrouted = c.Unrouted.String()
	}
	var permitted, blocked, deflt, unknown traffic.Region
	var acc hitSets
	for _, p := range c.Paths {
		f.Paths = append(f.Paths, pathSummary(p))
		for _, d := range p.Decisions {
			switch d.Outcome {
			case query.OutcomePermit:
				permitted = permitted.Union(d.Space)
				acc.add(&acc.permitted, d.Rule, p, d.Space, nil)
			case query.OutcomeDeny:
				blocked = blocked.Union(d.Space)
				acc.add(&acc.blocked, d.Rule, p, d.Space, nil)
			case query.OutcomeDefault:
				deflt = deflt.Union(d.Space)
			case query.OutcomeUnknown:
				unknown = unknown.Union(d.Space)
				acc.unknown = append(acc.unknown, labelled{p, d.Space})
				for _, pr := range d.Possible {
					acc.add(&acc.undecided, pr, p, traffic.Region{}, summarize(pr.Issues()))
				}
				if len(d.Possible) == 0 {
					acc.add(&acc.undecided, nil, p, traffic.Region{}, p.NATUncertain)
				}
				acc.add(&acc.otherwise, d.Rule, p, d.Space, []string{d.Final.String()})
			case query.OutcomeUnset:
			}
		}
	}
	f.Permitted, f.Blocked = acc.permitted.hits(), acc.blocked.hits()
	f.Undecided, f.Otherwise = acc.undecided.hits(), acc.otherwise.hits()
	f.UndecidedTraffic = describeAll(acc.unknown)
	if rest := blocked.Union(deflt); !rest.IsEmpty() {
		f.Remaining = rest.String()
	}
	f.Status = classify(!permitted.IsEmpty(), !blocked.IsEmpty(), !deflt.IsEmpty() || f.Unrouted != "", !unknown.IsEmpty() || c.Incomplete)
	return f
}

// labelled is a region decided on one path.
type labelled struct {
	path query.Path
	r    traffic.Region
}

// hitList accumulates, per rule, the traffic it decides.
type hitList struct {
	order   []string
	names   map[string]string
	reasons map[string][]string
	traffic map[string][]labelled
}

type hitSets struct {
	permitted, blocked, undecided, otherwise hitList
	unknown                                  []labelled
}

func (hitSets) add(l *hitList, r *firemon.Rule, p query.Path, s traffic.Region, reasons []string) {
	if l.names == nil {
		l.names, l.reasons, l.traffic = map[string]string{}, map[string][]string{}, map[string][]labelled{}
	}
	id, name := "(default)", ""
	if r != nil {
		id, name = r.ID(), r.Spec().Name
	}
	if _, ok := l.names[id]; !ok {
		l.order = append(l.order, id)
		l.names[id] = name
		l.reasons[id] = reasons
	}
	if !s.IsEmpty() {
		l.traffic[id] = append(l.traffic[id], labelled{p, s})
	}
}

func (l hitList) hits() []Hit {
	out := make([]Hit, 0, len(l.order))
	for _, id := range l.order {
		out = append(out, Hit{Rule: id, Name: l.names[id], Traffic: describeAll(l.traffic[id]), Reasons: l.reasons[id]})
	}
	return out
}

// describeAll merges the regions of each path and writes them, using the
// domain name on unresolved domain paths.
func describeAll(ls []labelled) string {
	var parts []string
	var plain traffic.Region
	for _, x := range ls {
		if x.path.Domain != "" && !x.path.DomainResolved {
			parts = append(parts, describe(x.r, x.path))
			continue
		}
		plain = plain.Union(x.r)
	}
	if !plain.IsEmpty() {
		parts = append([]string{compact(plain)}, parts...)
	}
	return strings.Join(slices.Compact(parts), "; ")
}

// compact writes a region as one box when that box holds exactly the
// region, which is the common case after merging pieces.
func compact(r traffic.Region) string {
	b := box(r)
	if traffic.NewRegion(b).SubtractRegion(r).IsEmpty() {
		return b.String()
	}
	return r.String()
}

// summarize shortens a rule's issues into its kinds.
func summarize(issues []string) []string {
	var out []string
	for _, i := range issues {
		kind := "other"
		switch {
		case strings.Contains(i, "fqdn"), strings.HasPrefix(i, "domain-book"):
			kind = "domain"
		case strings.HasPrefix(i, "application"):
			kind = "application"
		case strings.HasPrefix(i, "source-user"), strings.HasPrefix(i, "user"):
			kind = "user"
		case strings.HasPrefix(i, "category"):
			kind = "url-category"
		case strings.Contains(i, "schedule"):
			kind = "schedule"
		case strings.Contains(i, "unknown"):
			kind = "unknown-object"
		}
		if !slices.Contains(out, kind) {
			out = append(out, kind)
		}
	}
	return out
}

func classify(permitted, blocked, deflt, unknown bool) Status {
	switch {
	case unknown:
		return StatusIndeterminate
	case permitted && !blocked && !deflt:
		return StatusFullMatch
	case permitted:
		return StatusPartialMatch
	case blocked:
		return StatusBlocked
	default:
		return StatusNeedNew
	}
}

func pathSummary(p query.Path) Path {
	out := Path{
		From: p.From, To: p.To, Ingress: p.Ingress, Egress: p.Egress, Domain: p.Domain, Application: p.Application,
		PolicyRoute: p.PolicyRoute, Conditions: p.Conditions, NATSkipped: p.NATSkipped, Verdict: p.Verdict,
	}
	if h := p.DestinationNAT; h != nil {
		out.NAT = append(out.NAT, natLine(*h))
	}
	for _, h := range p.SourceNAT {
		out.NAT = append(out.NAT, natLine(h))
	}
	for _, id := range p.NATUncertain {
		out.NAT = append(out.NAT, NAT{Rule: id, Uncertain: true})
	}
	return out
}

func natLine(h query.NATHit) NAT {
	n := NAT{Side: h.Side, Translated: h.Translated.String()}
	if !h.Space.IsEmpty() {
		n.Traffic = compact(h.Space)
	}
	switch {
	case h.Rule != nil:
		n.Rule, n.Position = h.Rule.Spec().ID, h.Position+1
	case h.Static != nil:
		n.Rule, n.Static = h.Static.Spec().ID, true
	}
	return n
}

// describe writes a decided region; on an unresolved domain path the
// destination is the domain name rather than the address share it stands for.
func describe(r traffic.Region, p query.Path) string {
	if p.Domain == "" || p.DomainResolved {
		return r.String()
	}
	parts := make([]string, 0, r.Len())
	for _, s := range r.Spaces() {
		parts = append(parts, s.Src.String()+" -> "+p.Domain+" "+s.Service.String())
	}
	return strings.Join(parts, "; ")
}
