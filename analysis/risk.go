package analysis

import (
	"context"
	"slices"
	"strings"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/policy"
)

type RiskMode uint8

const (
	Declared RiskMode = iota + 1
	Effective
)

type Relation uint8

const (
	Intersects Relation = iota + 1
	Contains
	Within
	Equal
	NotEqual
)

type RiskDefinition struct {
	ID, Version string
	Mode        RiskMode
	Relation    Relation
	// Traffic is the explicit paired standard against which actual traffic is
	// compared. No dynamic evaluator, expression code or implicit network is used.
	Traffic flow.Traffic
	Actions []fm.Action
}
type RiskFinding struct {
	PolicyID, PolicyVersion, GraphDigest string
	Rule                                 fm.ID
	Mode                                 RiskMode
	Value                                Truth
	Traffic                              flow.Traffic
}
type RiskAnalyzer struct{ Engine policy.Engine }

// Assess evaluates one versioned standard in an explicit context/traffic scope.
// Declared mode evaluates potential matches; effective mode uses first-match
// ownership at q.At. Disabled/shadowed rules have no effective exposure.
func (a RiskAnalyzer) Assess(ctx context.Context, fw *fm.Firewall, q policy.Request, definition RiskDefinition) ([]RiskFinding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if fw == nil || q.Traffic.Empty() || definition.Traffic.Empty() || strings.TrimSpace(definition.ID) == "" || strings.TrimSpace(definition.Version) == "" || (definition.Mode != Declared && definition.Mode != Effective) || definition.Relation < Intersects || definition.Relation > NotEqual {
		return nil, ErrInvalid
	}
	actions := slices.Clone(definition.Actions)
	if len(actions) == 0 {
		actions = []fm.Action{fm.Permit}
	}
	for _, action := range actions {
		if !action.Valid() {
			return nil, ErrInvalid
		}
	}
	if q.RuleSet == "" {
		q.RuleSet = "security"
	}
	var rows []RiskFinding
	for _, rule := range fw.Rules() {
		r := rule.Record()
		if r.Scope == q.Scope && r.RuleSet == q.RuleSet {
			rows = append(rows, RiskFinding{PolicyID: definition.ID, PolicyVersion: definition.Version, GraphDigest: fw.SemanticDigest(), Rule: r.ID, Mode: definition.Mode})
		}
	}
	if !fw.Complete() {
		return rows, nil
	}
	effective := make(map[fm.ID]flow.Traffic)
	if definition.Mode == Effective {
		r, err := a.Engine.Query(ctx, fw, q)
		if err != nil {
			return nil, err
		}
		if !r.Complete || !r.Unknown.Empty() {
			return rows, nil
		}
		for _, trace := range r.Trace {
			effective[trace.Rule] = trace.Traffic
		}
	}
	budget := a.Engine.Limits.Rules
	if budget <= 0 {
		budget = 100000
	}
	limit := a.Engine.Limits.Regions
	if limit <= 0 {
		limit = 4096
	}
	for i := range rows {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if i >= budget {
			return nil, policy.ErrBudget
		}
		r := fw.Rule(rows[i].Rule).Record()
		if !slices.Contains(actions, r.Action) {
			rows[i].Value = False
			continue
		}
		actual := effective[r.ID]
		if definition.Mode == Declared {
			var known bool
			var err error
			actual, known, err = a.Engine.Match(ctx, fw, r.Match, q, q.Traffic)
			if err != nil {
				return nil, err
			}
			if !known {
				continue
			}
		}
		rows[i].Traffic = actual
		if actual.Empty() {
			rows[i].Value = False
			continue
		}
		value, err := compareTraffic(actual, definition.Traffic, definition.Relation, limit)
		if err != nil {
			return nil, err
		}
		rows[i].Value = False
		if value {
			rows[i].Value = True
		}
	}
	return rows, nil
}

func compareTraffic(actual, standard flow.Traffic, relation Relation, limit int) (bool, error) {
	switch relation {
	case Intersects:
		hit, err := actual.Intersection(standard, limit)
		return !hit.Empty(), err
	case Contains:
		return actual.Contains(standard, limit)
	case Within:
		return standard.Contains(actual, limit)
	case Equal, NotEqual:
		a, err := actual.Contains(standard, limit)
		if err != nil {
			return false, err
		}
		b, err := standard.Contains(actual, limit)
		if relation == NotEqual {
			return !(a && b), err
		}
		return a && b, err
	default:
		return false, ErrInvalid
	}
}
