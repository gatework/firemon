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
	limits := a.Engine.Limits.WithDefaults()
	limit, comparisons := limits.MaxRegions, limits.MaxCombinations
	budget := visitBudget(limits.MaxVisits)
	var prepared preparedRiskExpression
	if definition.Expression == nil {
		if definition.Traffic.Empty() || definition.Relation < Intersects || definition.Relation > NotEqual {
			return nil, ErrInvalid
		}
	} else {
		if !definition.Traffic.Empty() || definition.Relation != 0 {
			return nil, ErrInvalid
		}
		preparation := riskPreparation{limit: limit, nodes: comparisons, regions: limit}
		var err error
		prepared, err = preparation.compile(ctx, *definition.Expression, 0)
		if err != nil {
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
	if err := budget.take(ctx, fw.RuleCount()); err != nil {
		return nil, err
	}
	var rows []RiskFinding
	for _, rule := range fw.Rules() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
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
	for i := range rows {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := budget.take(ctx, 1); err != nil {
			return nil, err
		}
		rule := fw.Rule(rows[i].Rule)
		if !rule.Action().Valid() || rule.HasUnsupported() {
			continue
		}
		if !slices.Contains(actions, rule.Action()) {
			rows[i].Value = False
			continue
		}
		r := rule.Record()
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
			value, remaining, err := a.assessPrepared(ctx, fw, r, q, definition.Mode, actual, prepared, limit, comparisons)
			comparisons = remaining
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
