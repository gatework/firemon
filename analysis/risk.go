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
	Addresses flow.AddressSet
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
	Evidence                             RiskEvidence
}
type RiskAnalyzer struct{ Engine policy.Engine }

// Analyze evaluates one versioned standard in an explicit context/traffic scope.
// Declared mode evaluates potential matches; effective mode uses first-match
// ownership at q.At. Disabled/shadowed rules have no effective exposure.
func (a RiskAnalyzer) Analyze(ctx context.Context, fw *fm.Firewall, q policy.Request, definition RiskDefinition) ([]RiskFinding, error) {
	rows, err := a.AnalyzeBatch(ctx, fw, []policy.Request{q}, []RiskDefinition{definition})
	if err != nil {
		return nil, err
	}
	return rows[0].Findings, nil
}

type RiskContextFindings struct {
	Context    int           `json:"context"`
	Definition int           `json:"definition"`
	Findings   []RiskFinding `json:"findings"`
}

type preparedRiskDefinition struct {
	definition RiskDefinition
	expression preparedRiskExpression
	actions    []fm.Action
}

// AnalyzeBatch prepares each definition once, then evaluates in context-major,
// definition-minor order. Preparation capacity and evaluation visits/nodes are
// cumulative across this call; delegated engine queries retain their own limits.
// Any failure discards partial findings.
func (a RiskAnalyzer) AnalyzeBatch(ctx context.Context, fw *fm.Firewall, contexts []policy.Request, definitions []RiskDefinition) ([]RiskContextFindings, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if fw == nil || len(contexts) == 0 || len(definitions) == 0 {
		return nil, ErrInvalid
	}
	limits := a.Engine.Limits.WithDefaults()
	if len(contexts) > limits.MaxCombinations/len(definitions) {
		return nil, policy.ErrBudget
	}
	for _, q := range contexts {
		if q.Traffic.Empty() {
			return nil, ErrInvalid
		}
		if q.Traffic.RegionCount() > limits.MaxRegions {
			return nil, flow.ErrBudget
		}
	}
	preparation := riskPreparation{limit: limits.MaxRegions, nodes: limits.MaxCombinations, regions: limits.MaxRegions}
	prepared := make([]preparedRiskDefinition, 0, len(definitions))
	for _, definition := range definitions {
		if strings.TrimSpace(definition.ID) == "" || strings.TrimSpace(definition.Version) == "" || (definition.Mode != Declared && definition.Mode != Effective) {
			return nil, ErrInvalid
		}
		p := preparedRiskDefinition{definition: definition, actions: slices.Clone(definition.Actions)}
		if definition.Expression == nil {
			if definition.Traffic.Empty() || definition.Relation < Intersects || definition.Relation > NotEqual {
				return nil, ErrInvalid
			}
			if definition.Traffic.RegionCount() > preparation.regions {
				return nil, flow.ErrBudget
			}
			preparation.regions -= definition.Traffic.RegionCount()
		} else {
			if !definition.Traffic.Empty() || definition.Relation != 0 {
				return nil, ErrInvalid
			}
			var err error
			p.expression, err = preparation.compile(ctx, *definition.Expression, 0)
			if err != nil {
				return nil, err
			}
		}
		if len(p.actions) == 0 {
			p.actions = []fm.Action{fm.Permit}
		}
		for _, action := range p.actions {
			if !action.Valid() {
				return nil, ErrInvalid
			}
		}
		prepared = append(prepared, p)
	}
	budget := visitBudget(limits.MaxVisits)
	comparisons := limits.MaxCombinations
	retained := limits.MaxRegions
	var out []RiskContextFindings
	for ci, q := range contexts {
		for di, p := range prepared {
			rows, err := a.analyzePrepared(ctx, fw, q, p, &budget, &comparisons, &retained)
			if err != nil {
				return nil, err
			}
			out = append(out, RiskContextFindings{Context: ci, Definition: di, Findings: rows})
		}
	}
	return out, nil
}

func (a RiskAnalyzer) analyzePrepared(ctx context.Context, fw *fm.Firewall, q policy.Request, p preparedRiskDefinition, budget *visitBudget, comparisons, retained *int) ([]RiskFinding, error) {
	definition, prepared, actions := p.definition, p.expression, p.actions
	limit := a.Engine.Limits.WithDefaults().MaxRegions
	if q.RuleSet == "" {
		q.RuleSet = "security"
	}
	if err := budget.take(ctx, fw.RuleCount()); err != nil {
		return nil, err
	}
	if err := budget.take(ctx, fw.DiagnosticCount()); err != nil {
		return nil, err
	}
	diagnostics := make(map[fm.ID][]string)
	for _, diagnostic := range fw.Diagnostics() {
		diagnostics[diagnostic.Object] = append(diagnostics[diagnostic.Object], "diagnostic:"+diagnostic.Code)
	}
	var rows []RiskFinding
	for _, rule := range fw.Rules() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if rule.Chain() == q.Chain() {
			var schedule fm.ID
			if s := rule.Schedule(); s != nil {
				schedule = s.ID()
			}
			count := len(diagnostics[""]) + len(diagnostics[rule.ID()])
			if schedule != "" {
				count += len(diagnostics[schedule])
			}
			if err := budget.take(ctx, count); err != nil {
				return nil, err
			}
			rows = append(rows, RiskFinding{PolicyID: definition.ID, PolicyVersion: definition.Version, GraphDigest: fw.SemanticDigest(), Rule: rule.ID(), Mode: definition.Mode, Evidence: riskEvidence(fw, rule, q, definition.Mode, diagnostics)})
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
			for i := range rows {
				rows[i].Evidence.Reasons = append(rows[i].Evidence.Reasons, "effective-partition-unknown")
			}
			return rows, nil
		}
		for _, decision := range r.Decisions {
			effective[decision.Rule] = decision.Traffic
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
				rows[i].Evidence.Reasons = append(rows[i].Evidence.Reasons, "unresolved-match")
				continue
			}
		}
		if known {
			if actual.RegionCount() > *retained {
				return nil, flow.ErrBudget
			}
			*retained -= actual.RegionCount()
			rows[i].Traffic = actual
		}
		if known && actual.Empty() {
			rows[i].Value = False
			rows[i].Evidence.Reasons = append(rows[i].Evidence.Reasons, "no-exposure-in-context")
			continue
		}
		if definition.Expression != nil {
			value, remaining, err := a.assessPrepared(ctx, fw, r, q, definition.Mode, actual, prepared, limit, *comparisons)
			*comparisons = remaining
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
