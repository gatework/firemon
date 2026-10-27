package analysis

import (
	"context"
	"reflect"
	"slices"
	"strings"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/policy"
)

type Converger struct {
	Planner plan.Planner
	From    time.Time
}

// Plan merges an explicit selection into the earliest native rule. Both the
// declaration union and the entire resulting rulebase must be equivalent.
func (c Converger) Plan(ctx context.Context, fw *fm.Firewall, ids []fm.ID) (*plan.Plan, error) {
	if fw == nil || !fw.Complete() || len(ids) < 2 || len(ids) > 100 {
		return nil, ErrInvalid
	}
	selected := make(map[fm.ID]bool)
	var rules []fm.RuleRecord
	for _, id := range ids {
		if selected[id] || fw.Rule(id) == nil {
			return nil, ErrInvalid
		}
		selected[id] = true
		r := fw.Rule(id).Record()
		if r.Builtin || r.Log == fm.Unknown || r.LogStart == fm.Unknown || r.LogEnd == fm.Unknown || len(r.Unsupported) > 0 {
			return nil, plan.ErrUnsafe
		}
		rules = append(rules, r)
	}
	slices.SortFunc(rules, func(a, b fm.RuleRecord) int {
		if a.Position < b.Position {
			return -1
		}
		if a.Position > b.Position {
			return 1
		}
		return strings.Compare(string(a.ID), string(b.ID))
	})
	signature := func(r fm.RuleRecord) fm.RuleRecord {
		r.Object = fm.Object{Scope: r.Scope}
		r.Position = 0
		r.Match.Sources, r.Match.Destinations, r.Match.Services = nil, nil, nil
		return r
	}
	merged := rules[0]
	change := plan.Change{Kind: plan.AppendMembers, Rule: merged.ID}
	for _, r := range rules[1:] {
		if !reflect.DeepEqual(signature(rules[0]), signature(r)) {
			return nil, plan.ErrUnsafe
		}
		for _, ref := range r.Match.Sources {
			if !slices.Contains(merged.Match.Sources, ref) {
				merged.Match.Sources = append(merged.Match.Sources, ref)
				change.Sources = append(change.Sources, ref)
			}
		}
		for _, ref := range r.Match.Destinations {
			if !slices.Contains(merged.Match.Destinations, ref) {
				merged.Match.Destinations = append(merged.Match.Destinations, ref)
				change.Destinations = append(change.Destinations, ref)
			}
		}
		for _, ref := range r.Match.Services {
			if !slices.Contains(merged.Match.Services, ref) {
				merged.Match.Services = append(merged.Match.Services, ref)
				change.Services = append(change.Services, ref)
			}
		}
	}
	contexts, err := c.Planner.Engine.Contexts(ctx, c.From, fw)
	if err != nil {
		return nil, err
	}
	visits := 0
	for _, q := range contexts {
		if q.Scope != merged.Scope || q.RuleSet != merged.RuleSet {
			continue
		}
		var union flow.Traffic
		for _, r := range rules {
			visits++
			if visits > 100000 {
				return nil, policy.ErrBudget
			}
			hit, known, err := c.Planner.Engine.Match(ctx, fw, r.Match, q, q.Traffic)
			if err != nil {
				return nil, err
			}
			if !known {
				return nil, plan.ErrUnsafe
			}
			union, err = union.Union(hit, 4096)
			if err != nil {
				return nil, err
			}
		}
		hit, known, err := c.Planner.Engine.Match(ctx, fw, merged.Match, q, q.Traffic)
		if err != nil {
			return nil, err
		}
		if !known {
			return nil, plan.ErrUnsafe
		}
		if equal, err := equalTraffic(union, hit); err != nil {
			return nil, err
		} else if !equal {
			return nil, plan.ErrUnsafe
		}
	}
	d := fw.Export()
	d.Rules = nil
	for _, r := range fw.Rules() {
		row := r.Record()
		if row.ID == merged.ID {
			d.Rules = append(d.Rules, merged)
		} else if !selected[row.ID] {
			d.Rules = append(d.Rules, row)
		}
	}
	var changes []plan.Change
	if len(change.Sources)+len(change.Destinations)+len(change.Services) > 0 {
		changes = append(changes, change)
	}
	for _, r := range rules[1:] {
		changes = append(changes, plan.Change{Kind: plan.RemoveRule, Rule: r.ID})
	}
	after, err := fm.Seal(d)
	if err != nil {
		return nil, err
	}
	return c.Planner.Preserve(ctx, fw, after, changes, c.From)
}

func equalTraffic(a, b flow.Traffic) (bool, error) {
	x, err := a.Difference(b, 4096)
	if err != nil || !x.Empty() {
		return false, err
	}
	x, err = b.Difference(a, 4096)
	return err == nil && x.Empty(), err
}
