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
	// Expression is an alternative to the paired Traffic/Relation standard.
	Expression *RiskExpression
}

// Dimension identifies one rule match role. Service retains the complete
// protocol/port/ICMP tuple; source and destination are independent address sets.
type Dimension uint8

const (
	Source Dimension = iota + 1
	Destination
	Service
)

type RiskPredicate struct {
	Dimension Dimension
	Relation  Relation
	Addresses flow.Set
	Services  []fm.ServiceTerm
}

// RiskExpression has exactly one of Predicate, All (AND), or Any (OR).
// Unknown follows three-valued logic: false dominates AND, true dominates OR.
type RiskExpression struct {
	Predicate *RiskPredicate
	All       []RiskExpression
	Any       []RiskExpression
}
type RiskFinding struct {
	PolicyID, PolicyVersion, GraphDigest string
	Rule                                 fm.ID
	Mode                                 RiskMode
	Value                                Truth
	Traffic                              flow.Traffic
}
type RiskAnalyzer struct{ Engine policy.Engine }

// Analyze evaluates one versioned standard in an explicit context/traffic scope.
// Declared mode evaluates potential matches; effective mode uses first-match
// ownership at q.At. Disabled/shadowed rules have no effective exposure.
func (a RiskAnalyzer) Analyze(ctx context.Context, fw *fm.Firewall, q policy.Request, definition RiskDefinition) ([]RiskFinding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if fw == nil || q.Traffic.Empty() || strings.TrimSpace(definition.ID) == "" || strings.TrimSpace(definition.Version) == "" || (definition.Mode != Declared && definition.Mode != Effective) {
		return nil, ErrInvalid
	}
	limit := a.Engine.Limits.MaxRegions
	if limit <= 0 {
		limit = 4096
	}
	comparisons := a.Engine.Limits.MaxCombinations
	if comparisons <= 0 {
		comparisons = 4096
	}
	if definition.Expression == nil {
		if definition.Traffic.Empty() || definition.Relation < Intersects || definition.Relation > NotEqual {
			return nil, ErrInvalid
		}
	} else {
		if !definition.Traffic.Empty() || definition.Relation != 0 {
			return nil, ErrInvalid
		}
		validationBudget := comparisons
		if err := validateRiskExpression(ctx, *definition.Expression, limit, &validationBudget, 0); err != nil {
			return nil, err
		}
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
		if rule.Chain() == q.Chain() {
			rows = append(rows, RiskFinding{PolicyID: definition.ID, PolicyVersion: definition.Version, GraphDigest: fw.SemanticDigest(), Rule: rule.ID(), Mode: definition.Mode})
		}
	}
	if !fw.Complete() && (definition.Expression == nil || definition.Mode == Effective) {
		return rows, nil
	}
	if hasUnassignedDiagnostics(fw) {
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
	budget := a.Engine.Limits.MaxVisits
	if budget <= 0 {
		budget = 100000
	}
	for i := range rows {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if i >= budget {
			return nil, policy.ErrBudget
		}
		r := fw.Rule(rows[i].Rule).Record()
		if !r.Action.Valid() || len(r.Unsupported) > 0 {
			continue
		}
		if !slices.Contains(actions, r.Action) {
			rows[i].Value = False
			continue
		}
		actual := effective[r.ID]
		known := true
		if definition.Mode == Declared {
			var err error
			actual, known, err = a.Engine.Match(ctx, fw, r.Match, q, q.Traffic)
			if err != nil {
				return nil, err
			}
			if !known && definition.Expression == nil {
				continue
			}
		}
		if known {
			rows[i].Traffic = actual
		}
		if known && actual.Empty() {
			rows[i].Value = False
			continue
		}
		if definition.Expression != nil {
			value, err := a.assessExpression(ctx, fw, r, q, definition.Mode, actual, *definition.Expression, limit, &comparisons)
			if err != nil {
				return nil, err
			}
			rows[i].Value = value
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

func hasUnassignedDiagnostics(fw *fm.Firewall) bool {
	for _, diagnostic := range fw.Diagnostics() {
		if diagnostic.Object == "" {
			return true
		}
	}
	return false
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
