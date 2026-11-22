package report

import (
	"slices"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/design"
	"github.com/gatework/firemon/traffic"
)

// PlannedRule is a security rule a verified plan adds or modifies, in full,
// as it will be on the device: what an operator reviews before the change.
type PlannedRule struct {
	// Kind is "add" or "modify".
	Kind string `json:"kind"`
	// Before is the rule a new rule goes before; empty means the end.
	Before string `json:"before,omitempty"`
	// Rule is the rule after the change; Original the rule before a
	// modification, and Fields the dimensions modified.
	Rule     RuleDetail  `json:"rule"`
	Original *RuleDetail `json:"original,omitempty"`
	Fields   []string    `json:"fields,omitempty"`
	// Created names the objects the plan creates.
	Created []string `json:"created,omitempty"`
	// opens is the traffic the change starts to match: the new rule's
	// match, or what an extension adds; it maps changes to flows.
	opens []traffic.Space
}

// plannedRules applies the plan to a copy of fw and describes every rule
// it adds or modifies. A plan that does not apply describes nothing.
func plannedRules(fw *firemon.Firewall, plan *design.Plan) []PlannedRule {
	if fw == nil || plan == nil || len(plan.Changes) == 0 {
		return nil
	}
	cfg := fw.Config()
	if design.Apply(cfg, plan.Changes) != nil {
		return nil
	}
	after, err := firemon.Compile(cfg)
	if err != nil {
		return nil
	}
	created := createdNames(plan.Changes)
	var out []PlannedRule
	for _, c := range plan.Changes {
		switch x := c.(type) {
		case design.AddRule:
			if pr, ok := addedRule(after, x, created); ok {
				out = append(out, pr)
			}
		case design.ExtendRule:
			if i := slices.IndexFunc(out, func(p PlannedRule) bool { return p.Kind == "modify" && p.Rule.Rule == x.RuleID }); i >= 0 {
				if !slices.Contains(out[i].Fields, x.Field.String()) {
					out[i].Fields = append(out[i].Fields, x.Field.String())
				}
				continue
			}
			if pr, ok := extendedRule(fw, after, x, created); ok {
				out = append(out, pr)
			}
		}
	}
	return out
}

// createdNames are the objects a plan creates.
func createdNames(changes []design.Change) []string {
	var out []string
	for _, c := range changes {
		switch x := c.(type) {
		case design.AddAddress:
			out = append(out, x.Address.Name)
		case design.AddService:
			out = append(out, x.Service.Name)
		case design.AddAddressGroup:
			out = append(out, x.Group.Name)
		case design.AddServiceGroup:
			out = append(out, x.Group.Name)
		}
	}
	return out
}

// addedRule describes a rule the plan adds, as the firewall will hold it.
func addedRule(after *firemon.Firewall, x design.AddRule, created []string) (PlannedRule, bool) {
	d := details(after, []string{x.Rule.ID}, nil)
	if len(d) != 1 {
		return PlannedRule{}, false
	}
	pr := PlannedRule{Kind: "add", Before: x.Before, Rule: d[0], Created: created}
	if r, ok := after.Rule(x.Rule.ID); ok {
		pr.opens = []traffic.Space{r.Match()}
	}
	return pr, true
}

// extendedRule describes a rule the plan extends, before and after.
func extendedRule(fw, after *firemon.Firewall, x design.ExtendRule, created []string) (PlannedRule, bool) {
	was, now := details(fw, []string{x.RuleID}, nil), details(after, []string{x.RuleID}, nil)
	if len(was) != 1 || len(now) != 1 {
		return PlannedRule{}, false
	}
	pr := PlannedRule{Kind: "modify", Rule: now[0], Original: &was[0], Fields: []string{x.Field.String()}, Created: created}
	a, ok1 := after.Rule(x.RuleID)
	b, ok2 := fw.Rule(x.RuleID)
	if ok1 && ok2 {
		pr.opens = a.Match().Subtract(b.Match())
	}
	return pr, true
}
