package report

import (
	"cmp"
	"slices"
	"strings"

	"github.com/gatework/firemon/design"
	"github.com/gatework/firemon/inventory"
	"github.com/gatework/firemon/query"
)

// DeviceView is what one firewall does to the request, the way an operator
// reads a change ticket: which existing rules already permit which flows,
// which rules block them, and the rules to add or modify, with their risks.
// The views of a report follow the order the flows cross the firewalls.
type DeviceView struct {
	Cluster string           `json:"cluster"`
	Device  inventory.Device `json:"device"`
	// Peers are the HA members that receive the change by synchronization.
	Peers   []inventory.Device `json:"peers,omitempty"`
	Allowed []RuleUse          `json:"allowed,omitempty"`
	Blocked []RuleUse          `json:"blocked,omitempty"`
	Unknown []RuleUse          `json:"unknown,omitempty"`
	Added   []PlannedUse       `json:"added,omitempty"`
	// Modified are existing rules the plan extends.
	Modified []PlannedUse  `json:"modified,omitempty"`
	Risks    []design.Risk `json:"risks,omitempty"`
	// Designed reports that a plan was asked for; Unplanned says why the
	// blocked flows got no verified change.
	Designed  bool   `json:"designed,omitempty"`
	Unplanned string `json:"unplanned,omitempty"`
}

// RuleUse is an existing rule (or the default action, Rule empty) and the
// flows of the request it decides on one firewall, numbered from 1.
type RuleUse struct {
	Rule         string   `json:"rule,omitempty"`
	Name         string   `json:"name,omitempty"`
	Position     int      `json:"position,omitempty"`
	From         []string `json:"from,omitempty"`
	To           []string `json:"to,omitempty"`
	Applications []string `json:"applications,omitempty"`
	// TimeBound reports a rule a schedule or validity period limits.
	TimeBound bool  `json:"time_bound,omitempty"`
	Flows     []int `json:"flows"`
}

// PlannedUse is a planned rule and the flows of the request it opens.
type PlannedUse struct {
	PlannedRule
	Flows []int `json:"flows"`
}

// deviceViews groups the report by firewall.
func deviceViews(r Report) []DeviceView {
	var order []string
	for _, f := range r.Flows {
		for _, h := range f.Hops {
			if !slices.Contains(order, h.Cluster) {
				order = append(order, h.Cluster)
			}
		}
	}
	for _, f := range r.Firewalls {
		if !slices.Contains(order, f.Cluster) {
			order = append(order, f.Cluster)
		}
	}
	out := make([]DeviceView, 0, len(order))
	for _, cluster := range order {
		i := slices.IndexFunc(r.Firewalls, func(f Firewall) bool { return f.Cluster == cluster })
		if i < 0 {
			continue
		}
		out = append(out, deviceView(r, r.Firewalls[i]))
	}
	return out
}

func deviceView(r Report, f Firewall) DeviceView {
	v := DeviceView{Cluster: f.Cluster, Device: Device(f), Risks: f.Risks, Designed: f.Plan != nil}
	if len(f.Devices) > 1 {
		v.Peers = f.Devices[1:]
	}
	for n, fl := range r.Flows {
		for _, h := range fl.Hops {
			if h.Cluster != f.Cluster {
				continue
			}
			for _, d := range h.Decisions {
				use := ruleUse(f, d)
				switch d.Outcome {
				case query.OutcomePermit:
					v.Allowed = addUse(v.Allowed, use, n+1)
				case query.OutcomeDeny, query.OutcomeDefault:
					v.Blocked = addUse(v.Blocked, use, n+1)
				case query.OutcomeUnknown, query.OutcomeUnset:
					v.Unknown = addUse(v.Unknown, use, n+1)
				}
			}
		}
	}
	for _, pr := range f.Planned {
		use := PlannedUse{PlannedRule: pr, Flows: plannedFlows(r, f.Cluster, pr)}
		if pr.Kind == "add" {
			v.Added = append(v.Added, use)
		} else {
			v.Modified = append(v.Modified, use)
		}
	}
	if p := f.Plan; p != nil && len(v.Blocked) > 0 && len(f.Planned) == 0 {
		reasons := slices.Clone(p.Unknown)
		for _, c := range p.Conflicts {
			reasons = append(reasons, "rule "+c.RuleID+" denies "+c.Text)
		}
		v.Unplanned = cmp.Or(p.VerifyError, strings.Join(reasons, "; "), "no verified change")
	}
	return v
}

// Device is the evaluated member of a firewall's cluster.
func Device(f Firewall) inventory.Device {
	if len(f.Devices) > 0 {
		return f.Devices[0]
	}
	return inventory.Device{Name: cmp.Or(f.Firewall, f.Cluster), Evaluated: true}
}

// ruleUse describes the rule of a decision from the firewall's details.
func ruleUse(f Firewall, d HopDecision) RuleUse {
	u := RuleUse{Rule: d.Rule, Name: d.Name, Position: d.Position}
	if i := slices.IndexFunc(f.Rules, func(rd RuleDetail) bool { return rd.Rule == d.Rule }); i >= 0 && d.Rule != "" {
		rd := f.Rules[i]
		u.From, u.To, u.Applications = rd.From, rd.To, rd.Applications
		u.TimeBound = rd.Schedule != nil || rd.Window != ""
	}
	return u
}

// addUse adds flow n to the use of the same rule, or appends use.
func addUse(uses []RuleUse, use RuleUse, n int) []RuleUse {
	i := slices.IndexFunc(uses, func(u RuleUse) bool { return u.Rule == use.Rule })
	if i < 0 {
		use.Flows = []int{n}
		uses = append(uses, use)
		slices.SortStableFunc(uses, func(a, b RuleUse) int { return cmp.Compare(usePosition(a), usePosition(b)) })
		return uses
	}
	if !slices.Contains(uses[i].Flows, n) {
		uses[i].Flows = append(uses[i].Flows, n)
	}
	return uses
}

// usePosition orders rules by device order, the default action last.
func usePosition(u RuleUse) int {
	if u.Rule == "" {
		return int(^uint(0) >> 1)
	}
	return u.Position
}

// plannedFlows are the flows crossing cluster that a planned change opens.
func plannedFlows(r Report, cluster string, pr PlannedRule) []int {
	var out []int
	for n, fl := range r.Flows {
		for _, h := range fl.Hops {
			if h.Cluster != cluster || hopOutcome(h) == query.OutcomePermit {
				continue
			}
			if slices.ContainsFunc(pr.opens, h.space.Overlaps) {
				out = append(out, n+1)
				break
			}
		}
	}
	return out
}
