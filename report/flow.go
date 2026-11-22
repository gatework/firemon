package report

import (
	"cmp"
	"math"
	"slices"
	"strings"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/inventory"
	"github.com/gatework/firemon/query"
	"github.com/gatework/firemon/traffic"
)

// FlowStatus is the answer for one flow across every firewall it crosses.
type FlowStatus uint8

// Flow statuses.
const (
	FlowUnset FlowStatus = iota
	// FlowAllowed: every firewall on the way permits the flow.
	FlowAllowed
	// FlowNoFirewall: the flow crosses no firewall of the inventory.
	FlowNoFirewall
	// FlowNeedChange: a firewall on the way denies part of the flow.
	FlowNeedChange
	// FlowIndeterminate: a firewall cannot be evaluated offline for it.
	FlowIndeterminate
	// FlowUnlocated: no firewall of the inventory owns either end.
	FlowUnlocated
)

// String returns the status name used in JSON output.
func (s FlowStatus) String() string {
	switch s {
	case FlowUnset:
		return "unset"
	case FlowAllowed:
		return "allowed"
	case FlowNoFirewall:
		return "no-firewall"
	case FlowNeedChange:
		return "need-change"
	case FlowIndeterminate:
		return "indeterminate"
	case FlowUnlocated:
		return "unlocated"
	default:
		return "invalid"
	}
}

// MarshalText implements encoding.TextMarshaler.
func (s FlowStatus) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// Flow is one source item to one destination item of the request, the
// unit an operator asks about, with each firewall it crosses in order.
type Flow struct {
	Src     string `json:"src"`
	Dst     string `json:"dst"`
	Service string `json:"service"`
	// Applications are those the firewalls identify the flow as (inferred
	// from the ports unless the request named them).
	Applications []string   `json:"applications,omitempty"`
	Hops         []Hop      `json:"hops,omitempty"`
	Status       FlowStatus `json:"status"`
	// Inside names the firewall and zone both ends sit behind when the flow
	// crosses no firewall.
	Inside *Inside       `json:"inside,omitempty"`
	space  traffic.Space // the flow as asked
}

// Hop is one firewall on a flow's way and what decides the flow there.
type Hop struct {
	Cluster string           `json:"cluster"`
	Device  inventory.Device `json:"device"`
	From    string           `json:"from,omitempty"`
	To      string           `json:"to,omitempty"`
	// Decisions are the rules (or the default action) deciding the flow on
	// this firewall, in rule order; usually one.
	Decisions []HopDecision `json:"decisions"`
	// Via names the earlier firewall whose NAT translated the flow, and
	// the traffic this firewall sees.
	Via *Via `json:"via,omitempty"`
	// space is the flow as this firewall sees it (translated by NAT
	// upstream).
	space traffic.Space
}

// Via is the NAT hand-off a hop receives the flow through.
type Via struct {
	Cluster    string `json:"cluster"`
	Translated string `json:"translated"`
}

// HopDecision is one rule deciding (part of) a flow on a firewall.
type HopDecision struct {
	Outcome  query.Outcome `json:"outcome"`
	Rule     string        `json:"rule,omitempty"` // empty for the default action
	Name     string        `json:"name,omitempty"`
	Position int           `json:"position,omitempty"` // one-based
	Traffic  string        `json:"traffic"`
	spaces   []traffic.Space
}

// maxFlows bounds the flows listed; larger requests are one flow.
const maxFlows = 64

// Flows splits the request into its source and destination items and
// follows each pair through the firewalls of the trace: source owners
// first, destination owners last.
//
// fws (by cluster) spells the applications the way each configuration does.
func Flows(t inventory.Trace, fws map[string]*firemon.Firewall, srcs, dsts []traffic.AddressSet, service traffic.ServiceSet) []Flow {
	if len(srcs) == 0 || len(dsts) == 0 || len(srcs)*len(dsts) > maxFlows {
		srcs, dsts = []traffic.AddressSet{traffic.UnionAll(srcs...)}, []traffic.AddressSet{traffic.UnionAll(dsts...)}
	}
	var out []Flow
	for _, s := range srcs {
		for _, d := range dsts {
			if f, ok := flowOf(t, fws, s, d, service); ok {
				out = append(out, f)
			}
		}
	}
	return out
}

func flowOf(t inventory.Trace, fws map[string]*firemon.Firewall, src, dst traffic.AddressSet, service traffic.ServiceSet) (Flow, bool) {
	f := Flow{Src: src.String(), Dst: dst.String(), Service: service.String(), space: traffic.Space{Src: src, Dst: dst, Service: service}}
	if src.IsEmpty() || dst.IsEmpty() || src.Equal(dst) {
		return f, false
	}
	space := traffic.Space{Src: src, Dst: dst, Service: service}
	type ordered struct {
		hop       Hop
		rank, seq int
	}
	var hops []ordered
	unknown, denied := false, false
	for _, c := range t.Crossings {
		h, ok := hopOf(c, fws[c.Cluster], space, &f)
		if !ok {
			continue
		}
		for _, d := range h.Decisions {
			switch d.Outcome {
			case query.OutcomeUnknown, query.OutcomeUnset:
				unknown = true
			case query.OutcomeDeny, query.OutcomeDefault:
				denied = true
			case query.OutcomePermit:
			}
		}
		hops = append(hops, ordered{h, hopRank(c, src, dst), c.Seq})
	}
	// Per flow: the firewall owning its source first, the one owning its
	// destination last; between them (transit) the order routes hand the
	// traffic on. Two firewalls routing to each other carry flows both
	// ways, which only ownership tells apart.
	slices.SortStableFunc(hops, func(a, b ordered) int { return cmp.Or(cmp.Compare(a.rank, b.rank), cmp.Compare(a.seq, b.seq)) })
	for _, h := range hops {
		f.Hops = append(f.Hops, h.hop)
	}
	f.Applications = foldApps(f.Applications)
	switch {
	case unknown:
		f.Status = FlowIndeterminate
	case denied:
		f.Status = FlowNeedChange
	case len(f.Hops) > 0:
		f.Status = FlowAllowed
	default:
		for _, in := range t.Inside {
			if in.Src.ContainsSet(src) && in.Dst.ContainsSet(dst) {
				f.Inside = &Inside{Cluster: in.Cluster, Zone: in.Zone, Traffic: f.Src + " -> " + f.Dst}
				f.Status = FlowNoFirewall
				return f, true
			}
		}
		f.Status = FlowUnlocated
	}
	return f, true
}

// hopRank places a firewall on a flow: 0 owns its source, 2 its
// destination (or receives it through NAT), 1 is transit.
func hopRank(c inventory.Crossing, src, dst traffic.AddressSet) int {
	ownsSrc, ownsDst := false, false
	for _, b := range c.Basis {
		if b.Source && b.Addresses.Overlaps(src) {
			ownsSrc = true
		}
		if !b.Source && b.Addresses.Overlaps(dst) {
			ownsDst = true
		}
	}
	switch {
	case ownsSrc && !(ownsDst && len(c.Upstream) > 0):
		return 0
	case ownsDst || len(c.Upstream) > 0:
		return 2
	default:
		return 1
	}
}

// hopOf collects the decisions of one crossing on a flow. A crossing
// receiving the flow through an earlier firewall's NAT evaluates its
// translation. Decisions are in policy terms: on a path whose policy
// addresses differ from the original ones, the sources and services still
// narrow them to the flow, the destinations do not.
func hopOf(c inventory.Crossing, fw *firemon.Firewall, space traffic.Space, f *Flow) (Hop, bool) {
	h := Hop{Cluster: c.Cluster, Device: inventory.Device{Name: c.Firewall, Evaluated: true}}
	if len(c.Devices) > 0 {
		h.Device = c.Devices[0]
	}
	for _, up := range c.Upstream {
		if up.Original.Overlaps(space) {
			space = up.Translated
			h.Via = &Via{Cluster: up.Cluster, Translated: up.Translated.String()}
		}
	}
	h.space = space
	found := false
	for _, p := range c.Paths {
		orig := p.Original.Intersect(space)
		if orig.IsEmpty() {
			continue
		}
		found = true
		h.From, h.To = cmp.Or(h.From, p.From), cmp.Or(h.To, p.To)
		for _, a := range flowApps(p) {
			if fw != nil {
				a = fw.ApplicationDisplay(a)
			}
			f.Applications = append(f.Applications, a)
		}
		translated := !p.Original.Src.Equal(p.Policy.Src) || !p.Original.Dst.Equal(p.Policy.Dst)
		for _, d := range p.Decisions {
			part := d.Space.Intersect(orig)
			if translated {
				narrow := traffic.Space{Src: space.Src, Dst: traffic.AnyAddress(), Service: space.Service}
				if !p.Original.Src.Equal(p.Policy.Src) {
					narrow.Src = traffic.AnyAddress()
				}
				part = d.Space.Intersect(narrow)
			}
			if part.IsEmpty() {
				continue
			}
			addDecision(&h, d.Rule, d.Outcome, part.Spaces())
		}
	}
	for i := range h.Decisions {
		h.Decisions[i].Traffic = boundedText(h.Decisions[i].spaces)
		h.Decisions[i].spaces = nil
	}
	return h, found
}

func flowApps(p query.Path) []string {
	switch {
	case len(p.AppFamily) > 0:
		return p.AppFamily
	case p.Application != "":
		return []string{p.Application}
	default:
		return nil
	}
}

func addDecision(h *Hop, r *firemon.Rule, o query.Outcome, spaces []traffic.Space) {
	id, name, pos := "", "", 0
	if r != nil {
		id, name, pos = r.ID(), r.Spec().Name, r.Position()+1
	}
	for i := range h.Decisions {
		d := &h.Decisions[i]
		if d.Rule == id && d.Outcome == o {
			d.spaces = append(d.spaces, spaces...)
			return
		}
	}
	h.Decisions = append(h.Decisions, HopDecision{Outcome: o, Rule: id, Name: name, Position: pos, spaces: spaces})
	order := func(d HopDecision) int {
		if d.Rule == "" {
			return math.MaxInt // the default action decides last
		}
		return d.Position
	}
	slices.SortStableFunc(h.Decisions, func(a, b HopDecision) int { return cmp.Compare(order(a), order(b)) })
}

// FlowCounts are the flows crossing one firewall by what it does to them.
type FlowCounts struct {
	Allowed    int `json:"allowed"`
	NeedChange int `json:"need_change"`
	Unknown    int `json:"unknown"`
}

// WithFlows returns the report with its flows, counting on each firewall
// the flows it permits, denies (so needs a change) or cannot decide.
func (r Report) WithFlows(flows []Flow) Report {
	r.Flows = flows
	r.Firewalls = slices.Clone(r.Firewalls)
	for i := range r.Firewalls {
		fw := &r.Firewalls[i]
		var c FlowCounts
		for _, f := range flows {
			for _, h := range f.Hops {
				if h.Cluster != fw.Cluster {
					continue
				}
				switch hopOutcome(h) {
				case query.OutcomePermit:
					c.Allowed++
				case query.OutcomeUnknown, query.OutcomeUnset:
					c.Unknown++
				case query.OutcomeDeny, query.OutcomeDefault:
					c.NeedChange++
				}
			}
		}
		fw.FlowCounts = c
	}
	r.Devices = deviceViews(r)
	return r
}

// hopOutcome is the worst outcome of a hop: unknown, then denied, then
// permitted.
func hopOutcome(h Hop) query.Outcome {
	out := query.OutcomePermit
	for _, d := range h.Decisions {
		switch d.Outcome {
		case query.OutcomeUnknown, query.OutcomeUnset:
			return query.OutcomeUnknown
		case query.OutcomeDeny, query.OutcomeDefault:
			out = query.OutcomeDeny
		case query.OutcomePermit:
		}
	}
	return out
}

// foldApps sorts application names and keeps one spelling of each,
// ignoring case: firewalls of one request may spell them differently.
func foldApps(apps []string) []string {
	out := slices.Clone(apps)
	slices.SortFunc(out, func(a, b string) int { return cmp.Compare(strings.ToLower(a), strings.ToLower(b)) })
	return slices.CompactFunc(out, strings.EqualFold)
}
