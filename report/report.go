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
		return "no-firewall" // the request crosses no firewall of the inventory
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

// Settled reports a request that crosses no firewall because both ends
// sit in the same zone of the firewalls they reach: no rule is involved.
// Ends no firewall claims are not settled: the inventory may miss them.
func (r Report) Settled() bool {
	return r.Status == StatusUnset && len(r.Inside) > 0 && r.Excluded.Src == "" && r.Excluded.Dst == "" &&
		len(r.ZonesNeeded) == 0 && len(r.Ambiguous) == 0
}

// Report is the answer to one request.
type Report struct {
	Notes     []intake.Note `json:"notes,omitempty"`
	Excluded  Excluded      `json:"excluded"`
	Ambiguous []string      `json:"ambiguous,omitempty"`
	// ZonesNeeded lists firewalls with layer-2 zones the request did not
	// name zones for.
	ZonesNeeded []string `json:"zones_needed,omitempty"`
	// Inside is traffic that stays on one side of a firewall.
	Inside    []Inside   `json:"inside,omitempty"`
	Firewalls []Firewall `json:"firewalls"`
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
	// Basis says which ends of the request fall in networks the firewall
	// owns: why the request reaches it.
	Basis     []Basis `json:"basis,omitempty"`
	Paths     []Path  `json:"paths"`
	Status    Status  `json:"status"`
	Permitted []Hit   `json:"permitted,omitempty"`
	Blocked   []Hit   `json:"blocked,omitempty"`
	Undecided []Hit   `json:"undecided,omitempty"`
	// UndecidedTraffic is the traffic the undecided rules may decide.
	UndecidedTraffic string `json:"undecided_traffic,omitempty"`
	// Otherwise are the rules (or the default action) that decide the
	// undecided traffic when the undecided rules do not match.
	Otherwise []Hit  `json:"otherwise,omitempty"`
	Remaining string `json:"remaining,omitempty"`
	// Defaulted is the traffic no rule decides: the default action denies it.
	Defaulted string `json:"defaulted,omitempty"`
	// Unrouted is the destination part the firewall has no route for.
	Unrouted string `json:"unrouted,omitempty"`
	// Incomplete reports a cut-short evaluation.
	Incomplete  bool        `json:"incomplete,omitempty"`
	ZonesNeeded bool        `json:"zones_needed,omitempty"`
	Candidates  []Candidate `json:"candidates,omitempty"`
	// Rules are the definitions of the rules that decide the request,
	// objects expanded, for comparing with the device.
	Rules []RuleDetail `json:"rules,omitempty"`
	Plan  *design.Plan `json:"plan,omitempty"`
	// Scripts are the commands and rollback of the verified plans, one per
	// part of the request crossing the firewall; filled by the caller,
	// which knows the vendor.
	Scripts []design.Script `json:"scripts,omitempty"`
}

// Basis is one end of the request a firewall owns.
type Basis struct {
	Source    bool                `json:"source"`
	Addresses string              `json:"addresses"`
	Zone      string              `json:"zone,omitempty"`
	Networks  []string            `json:"networks,omitempty"`
	Ownership inventory.Ownership `json:"ownership"`
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
	NATSkipped  []query.NATRef    `json:"nat_skipped,omitempty"`
	// AppPorts are the application rules judged by their applications'
	// standard ports, which do not include the request's.
	AppPorts []AppPorts    `json:"app_ports,omitempty"`
	Verdict  query.Verdict `json:"verdict"`
}

// AppPorts is an application rule taken not to match the request because
// the request's ports are not its applications' standard ports.
type AppPorts struct {
	Rule         string   `json:"rule"`
	Name         string   `json:"name,omitempty"`
	Applications []string `json:"applications"`
	Ports        string   `json:"ports"`
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
	// Action is what an undecided rule would do if it matched.
	Action firemon.Action `json:"action,omitzero"`
	// Final is the outcome the rule (or the default action) gives, for
	// the rules that decide traffic when undecidable rules do not match.
	Final query.Outcome `json:"final,omitzero"`
}

// Build assembles the report. fws maps clusters to the evaluated firewall,
// for candidate analysis; plans are optional.
func Build(notes []intake.Note, t inventory.Trace, fws map[string]*firemon.Firewall, plans []inventory.ClusterPlan) Report {
	r := Report{Notes: notes, Ambiguous: t.Ambiguous, ZonesNeeded: t.ZonesNeeded, Firewalls: []Firewall{}}
	for _, in := range t.Inside {
		r.Inside = append(r.Inside, Inside{Cluster: in.Cluster, Zone: in.Zone, Traffic: in.Src.String() + " -> " + in.Dst.String()})
	}
	if !t.Excluded.Src.IsEmpty() {
		r.Excluded.Src = t.Excluded.Src.String()
	}
	if !t.Excluded.Dst.IsEmpty() {
		r.Excluded.Dst = t.Excluded.Dst.String()
	}
	for _, c := range t.Crossings {
		f := firewallReport(c)
		f.Plan = planFor(plans, c.Cluster)
		f.Status = max(f.Status, natStatus(f.Plan))
		f.Rules = details(fws[c.Cluster], decidingRules(f), decidedSpaces(c))
		if fw := fws[c.Cluster]; fw != nil && f.Status != StatusFullMatch && f.Status != StatusUnset {
			f.Candidates = candidates(fw, c.Paths, f.Plan)
		}
		r.Firewalls = append(r.Firewalls, f)
		r.Status = max(r.Status, f.Status)
	}
	if len(r.ZonesNeeded) > 0 {
		// A firewall the request may cross could not be evaluated.
		r.Status = max(r.Status, StatusIndeterminate)
	}
	return r
}

// decidedSpaces bounds, per rule, the traffic it decides on the crossing.
func decidedSpaces(c inventory.Crossing) map[string]traffic.Space {
	regions := map[string]traffic.Region{}
	for _, p := range c.Paths {
		for _, d := range p.Decisions {
			if d.Rule != nil {
				regions[d.Rule.ID()] = regions[d.Rule.ID()].Union(d.Space)
			}
		}
	}
	out := make(map[string]traffic.Space, len(regions))
	for id, r := range regions {
		out[id] = r.Bounds()
	}
	return out
}

// decidingRules are the rules that decide part of the request: they
// permit or block it, or decide it when undecidable rules do not match.
func decidingRules(f Firewall) []string {
	var out []string
	for _, hs := range [][]Hit{f.Permitted, f.Blocked, f.Otherwise} {
		for _, h := range hs {
			if h.Rule != hitID(nil) && !slices.Contains(out, h.Rule) {
				out = append(out, h.Rule)
			}
		}
	}
	return out
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
	for _, b := range c.Basis {
		f.Basis = append(f.Basis, Basis{Source: b.Source, Addresses: b.Addresses.String(), Zone: b.Zone, Networks: b.Networks, Ownership: b.Ownership})
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
				// Only the rules that would change the outcome matter: a
				// deny that might match first cannot block traffic that is
				// denied anyway.
				for _, pr := range d.Deciders() {
					acc.add(&acc.undecided, pr, p, traffic.Region{}, summarize(pr.Issues()))
					acc.undecided.action(pr)
				}
				if len(d.Possible) == 0 {
					acc.add(&acc.undecided, nil, p, traffic.Region{}, []string{"nat"})
				}
				acc.add(&acc.otherwise, d.Rule, p, d.Space, nil)
				acc.otherwise.final(d.Rule, d.Final)
			case query.OutcomeUnset:
			}
		}
	}
	f.Permitted, f.Blocked = acc.permitted.hits(), acc.blocked.hits()
	f.Undecided, f.Otherwise = acc.undecided.hits(), acc.otherwise.hits()
	f.UndecidedTraffic = describeAll(acc.unknown)
	if !deflt.IsEmpty() {
		f.Defaulted = compact(deflt)
	}
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
	finals  map[string]query.Outcome
	actions map[string]firemon.Action
	traffic map[string][]labelled
}

// final records the outcome rule r gives.
func (l *hitList) final(r *firemon.Rule, o query.Outcome) {
	if l.finals == nil {
		l.finals = map[string]query.Outcome{}
	}
	l.finals[hitID(r)] = o
}

func hitID(r *firemon.Rule) string {
	if r == nil {
		return "(default)"
	}
	return r.ID()
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
	}
	for _, r := range reasons {
		if !slices.Contains(l.reasons[id], r) {
			l.reasons[id] = append(l.reasons[id], r)
		}
	}
	if !s.IsEmpty() {
		l.traffic[id] = append(l.traffic[id], labelled{p, s})
	}
}

func (l *hitList) hits() []Hit {
	out := make([]Hit, 0, len(l.order))
	for _, id := range l.order {
		out = append(out, Hit{Rule: id, Name: l.names[id], Traffic: describeAll(l.traffic[id]), Reasons: l.reasons[id], Final: l.finals[id], Action: l.actions[id]})
	}
	return out
}

// action records what rule r does when it matches.
func (l *hitList) action(r *firemon.Rule) {
	if l.actions == nil {
		l.actions = map[string]firemon.Action{}
	}
	l.actions[hitID(r)] = r.Action()
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
	b := r.Bounds()
	if traffic.NewRegion(b).SubtractRegion(r).IsEmpty() {
		return b.String()
	}
	return r.String()
}

// summarize shortens a rule's issues into its kinds.
func summarize(issues []firemon.Issue) []string {
	var out []string
	for _, i := range issues {
		kind := issueLabel(i.Kind)
		if !slices.Contains(out, kind) {
			out = append(out, kind)
		}
	}
	return out
}

// issueLabel groups issue kinds into the labels the report shows.
func issueLabel(k firemon.IssueKind) string {
	switch k {
	case firemon.IssueKindDomain, firemon.IssueKindDestinationDomain:
		return "domain"
	case firemon.IssueKindApplication:
		return "application"
	case firemon.IssueKindUser:
		return "user"
	case firemon.IssueKindURLCategory:
		return "url-category"
	case firemon.IssueKindSchedule:
		return "schedule"
	case firemon.IssueKindObject, firemon.IssueKindZone:
		return "unknown-object"
	case firemon.IssueKindUnset, firemon.IssueKindAction, firemon.IssueKindUnsupported, firemon.IssueKindConfig:
		return "other"
	default:
		return "other"
	}
}

// classify names the result: a part certainly permitted with any other
// part (denied or undecided) is partial, since the request is not fully
// served either way; undecided traffic with nothing permitted needs a
// person.
func classify(permitted, blocked, deflt, unknown bool) Status {
	switch {
	case permitted && !blocked && !deflt && !unknown:
		return StatusFullMatch
	case permitted:
		return StatusPartialMatch
	case unknown:
		return StatusIndeterminate
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
	for _, a := range p.AppPorts {
		spec := a.Rule.Spec()
		out.AppPorts = append(out.AppPorts, AppPorts{Rule: spec.ID, Name: spec.Name, Applications: spec.Applications, Ports: a.Ports.String()})
	}
	if h := p.DestinationNAT; h != nil {
		out.NAT = append(out.NAT, natLine(*h))
	}
	for _, h := range p.SourceNAT {
		out.NAT = append(out.NAT, natLine(h))
	}
	for _, ref := range p.NATUncertain {
		out.NAT = append(out.NAT, NAT{Rule: ref.ID(), Static: ref.Static != nil, Uncertain: true})
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

// natStatus is the status the NAT part of a plan imposes: a translation
// still to add needs new configuration like an access rule does.
func natStatus(p *design.Plan) Status {
	if p == nil || p.NAT == nil {
		return StatusUnset
	}
	switch p.NAT.Status {
	case design.NATStatusAdded:
		return StatusNeedNew
	case design.NATStatusNeedsAddress, design.NATStatusIndeterminate:
		return StatusIndeterminate
	case design.NATStatusConflict:
		return StatusBlocked
	case design.NATStatusSatisfied, design.NATStatusUnset:
	}
	return StatusUnset
}

// Inside is traffic both of whose ends sit behind one interface of a
// firewall: it does not cross it.
type Inside struct {
	Cluster string `json:"cluster"`
	Zone    string `json:"zone"`
	Traffic string `json:"traffic"`
}
