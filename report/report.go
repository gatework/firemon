package report

import (
	"slices"

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
	Firewalls []Firewall    `json:"firewalls"`
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
	Cluster    string              `json:"cluster"`
	Firewall   string              `json:"firewall"`
	Members    []string            `json:"members"`
	Ownership  inventory.Ownership `json:"ownership"`
	Paths      []Path              `json:"paths"`
	Status     Status              `json:"status"`
	Permitted  []Hit               `json:"permitted,omitempty"`
	Blocked    []Hit               `json:"blocked,omitempty"`
	Undecided  []Hit               `json:"undecided,omitempty"`
	Remaining  string              `json:"remaining,omitempty"`
	Candidates []Candidate         `json:"candidates,omitempty"`
	Plan       *design.Plan        `json:"plan,omitempty"`
}

// Path summarizes one path through a firewall.
type Path struct {
	From        string        `json:"from"`
	To          string        `json:"to"`
	Ingress     string        `json:"ingress,omitempty"`
	Egress      string        `json:"egress,omitempty"`
	Domain      string        `json:"domain,omitempty"`
	Application string        `json:"application,omitempty"`
	NAT         []NAT         `json:"nat,omitempty"`
	Verdict     query.Verdict `json:"verdict"`
}

// NAT is one translation applied on a path.
type NAT struct {
	Side       firemon.NATKind `json:"side"`
	Rule       string          `json:"rule"`
	Static     bool            `json:"static,omitempty"`
	Translated string          `json:"translated"`
	Uncertain  bool            `json:"uncertain,omitempty"`
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
	r := Report{Notes: notes, Ambiguous: t.Ambiguous}
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
	f := Firewall{Cluster: c.Cluster, Firewall: c.Firewall, Members: c.Members, Ownership: c.Ownership}
	var permitted, blocked, deflt, unknown traffic.Region
	for _, p := range c.Paths {
		f.Paths = append(f.Paths, pathSummary(p))
		for _, d := range p.Decisions {
			switch d.Outcome {
			case query.OutcomePermit:
				permitted = permitted.Union(d.Space)
				f.Permitted = addHit(f.Permitted, d.Rule, d.Space, nil)
			case query.OutcomeDeny:
				blocked = blocked.Union(d.Space)
				f.Blocked = addHit(f.Blocked, d.Rule, d.Space, nil)
			case query.OutcomeDefault:
				deflt = deflt.Union(d.Space)
			case query.OutcomeUnknown:
				unknown = unknown.Union(d.Space)
				for _, pr := range d.Possible {
					f.Undecided = addHit(f.Undecided, pr, d.Space, pr.Issues())
				}
				if len(d.Possible) == 0 {
					f.Undecided = addHit(f.Undecided, nil, d.Space, p.NATUncertain)
				}
			case query.OutcomeUnset:
			}
		}
	}
	if rest := blocked.Union(deflt); !rest.IsEmpty() {
		f.Remaining = rest.String()
	}
	f.Status = classify(!permitted.IsEmpty(), !blocked.IsEmpty(), !deflt.IsEmpty(), !unknown.IsEmpty())
	return f
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
	out := Path{From: p.From, To: p.To, Ingress: p.Ingress, Egress: p.Egress, Domain: p.Domain, Application: p.Application, Verdict: p.Verdict}
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
	switch {
	case h.Rule != nil:
		n.Rule = h.Rule.Spec().ID
	case h.Static != nil:
		n.Rule, n.Static = h.Static.Spec().ID, true
	}
	return n
}

// addHit merges the space a rule decides into its hit.
func addHit(hits []Hit, r *firemon.Rule, s traffic.Region, reasons []string) []Hit {
	id, name := "(default)", ""
	if r != nil {
		id, name = r.ID(), r.Spec().Name
	}
	i := slices.IndexFunc(hits, func(h Hit) bool { return h.Rule == id })
	if i < 0 {
		return append(hits, Hit{Rule: id, Name: name, Traffic: s.String(), Reasons: reasons})
	}
	hits[i].Traffic += "; " + s.String()
	return hits
}
