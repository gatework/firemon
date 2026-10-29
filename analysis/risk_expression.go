package analysis

import (
	"context"
	"net/netip"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/policy"
)

// preparedRiskExpression owns normalized standards for one Analyze call. A zero
// dimension denotes a logical node; leaf standards share no caller-owned slices.
type preparedRiskExpression struct {
	dimension Dimension
	relation  Relation
	standard  flow.Traffic
	any       bool
	children  []preparedRiskExpression
}

type riskPreparation struct {
	limit          int
	nodes, regions int
}

func (p *riskPreparation) compile(ctx context.Context, expression RiskExpression, depth int) (preparedRiskExpression, error) {
	if err := ctx.Err(); err != nil {
		return preparedRiskExpression{}, err
	}
	if p.nodes <= 0 || depth >= 64 {
		return preparedRiskExpression{}, policy.ErrBudget
	}
	p.nodes--
	kinds := 0
	if expression.Predicate != nil {
		kinds++
	}
	if len(expression.All) > 0 {
		kinds++
	}
	if len(expression.Any) > 0 {
		kinds++
	}
	if kinds != 1 {
		return preparedRiskExpression{}, ErrInvalid
	}
	if predicate := expression.Predicate; predicate != nil {
		if predicate.Relation < Intersects || predicate.Relation > NotEqual {
			return preparedRiskExpression{}, ErrInvalid
		}
		standard, err := riskStandard(ctx, *predicate, p.limit)
		if err != nil {
			return preparedRiskExpression{}, err
		}
		count := standard.RegionCount()
		if count > p.regions {
			return preparedRiskExpression{}, flow.ErrBudget
		}
		p.regions -= count
		return preparedRiskExpression{dimension: predicate.Dimension, relation: predicate.Relation, standard: standard}, nil
	}
	children := expression.All
	out := preparedRiskExpression{any: len(expression.Any) > 0}
	if out.any {
		children = expression.Any
	}
	// Do not allocate from an unbounded caller slice before checking node capacity.
	if len(children) > p.nodes {
		return preparedRiskExpression{}, policy.ErrBudget
	}
	out.children = make([]preparedRiskExpression, 0, len(children))
	for _, child := range children {
		prepared, err := p.compile(ctx, child, depth+1)
		if err != nil {
			return preparedRiskExpression{}, err
		}
		out.children = append(out.children, prepared)
	}
	return out, nil
}

type riskDimension struct {
	traffic      flow.Traffic
	ready, known bool
}

// riskEvaluation is confined to one rule/context. Even reused projections charge
// every logical expression node, so caching cannot expand the work allowance.
type riskEvaluation struct {
	engine      policy.Engine
	firewall    *fm.Firewall
	rule        fm.RuleRecord
	request     policy.Request
	mode        RiskMode
	actual      flow.Traffic
	limit       int
	comparisons int
	dimensions  [3]riskDimension
}

// Keep expression-only evaluation state out of the paired-standard fast path.
func (a RiskAnalyzer) assessPrepared(ctx context.Context, fw *fm.Firewall, rule fm.RuleRecord, request policy.Request, mode RiskMode, actual flow.Traffic, expression preparedRiskExpression, limit, comparisons int) (Truth, int, error) {
	evaluation := riskEvaluation{engine: a.Engine, firewall: fw, rule: rule, request: request, mode: mode, actual: actual, limit: limit, comparisons: comparisons}
	value, err := evaluation.assess(ctx, expression)
	return value, evaluation.comparisons, err
}

func (e *riskEvaluation) projection(ctx context.Context, dimension Dimension) (flow.Traffic, bool, error) {
	cached := &e.dimensions[int(dimension)-1]
	if cached.ready {
		return cached.traffic, cached.known, nil
	}
	actual, known := e.actual, true
	if e.mode == Declared {
		match := e.rule.Match
		if dimension != Source {
			match.Sources, match.AnySource = nil, true
		}
		if dimension != Destination {
			match.Destinations, match.AnyDestination = nil, true
		}
		if dimension != Service {
			match.Services, match.AnyService = nil, true
		}
		var err error
		actual, known, err = e.engine.Match(ctx, e.firewall, match, e.request, e.request.Traffic)
		if err != nil {
			return flow.Traffic{}, false, err
		}
	}
	var projected flow.Traffic
	if known && !actual.Empty() {
		var err error
		projected, err = riskProjection(actual, dimension, e.limit)
		if err != nil {
			return flow.Traffic{}, false, err
		}
	}
	*cached = riskDimension{traffic: projected, ready: true, known: known}
	return projected, known, nil
}

func (e *riskEvaluation) assess(ctx context.Context, expression preparedRiskExpression) (Truth, error) {
	if err := ctx.Err(); err != nil {
		return Unknown, err
	}
	if e.comparisons <= 0 {
		return Unknown, policy.ErrBudget
	}
	e.comparisons--
	if expression.dimension != 0 {
		projected, known, err := e.projection(ctx, expression.dimension)
		if err != nil {
			return Unknown, err
		}
		if !known {
			return Unknown, nil
		}
		if projected.Empty() {
			return False, nil
		}
		value, err := compareTraffic(projected, expression.standard, expression.relation, e.limit)
		if err != nil {
			return Unknown, err
		}
		if value {
			return True, nil
		}
		return False, nil
	}
	identity, decisive := True, False
	if expression.any {
		identity, decisive = False, True
	}
	value := identity
	for _, child := range expression.children {
		result, err := e.assess(ctx, child)
		if err != nil {
			return Unknown, err
		}
		if result == decisive {
			return decisive, nil
		}
		if result == Unknown {
			value = Unknown
		}
	}
	return value, nil
}

func riskProjection(traffic flow.Traffic, dimension Dimension, limit int) (flow.Traffic, error) {
	boxes := traffic.Boxes()
	for i, b := range boxes {
		switch dimension {
		case Source, Destination:
			address := b.Source
			if dimension == Destination {
				address = b.Destination
			}
			zero := netip.IPv4Unspecified()
			if address.First.Is6() {
				zero = netip.IPv6Unspecified()
			}
			boxes[i] = flow.Box{Source: address, Destination: flow.Range{First: zero, Last: zero}}
		case Service:
			zero := netip.IPv4Unspecified()
			b.Source, b.Destination = flow.Range{First: zero, Last: zero}, flow.Range{First: zero, Last: zero}
			boxes[i] = b
		default:
			return flow.Traffic{}, ErrInvalid
		}
	}
	return flow.NewTraffic(limit, boxes...)
}

func riskStandard(ctx context.Context, predicate RiskPredicate, limit int) (flow.Traffic, error) {
	if err := ctx.Err(); err != nil {
		return flow.Traffic{}, err
	}
	var boxes []flow.Box
	switch predicate.Dimension {
	case Source, Destination:
		if predicate.Addresses.Empty() || len(predicate.Services) != 0 {
			return flow.Traffic{}, ErrInvalid
		}
		if predicate.Addresses.RangeCount() > limit {
			return flow.Traffic{}, flow.ErrBudget
		}
		boxes = make([]flow.Box, 0, predicate.Addresses.RangeCount())
		for _, address := range predicate.Addresses.Ranges() {
			if err := ctx.Err(); err != nil {
				return flow.Traffic{}, err
			}
			zero := netip.IPv4Unspecified()
			if address.First.Is6() {
				zero = netip.IPv6Unspecified()
			}
			boxes = append(boxes, flow.Box{Source: address, Destination: flow.Range{First: zero, Last: zero}})
		}
	case Service:
		if !predicate.Addresses.Empty() || len(predicate.Services) == 0 {
			return flow.Traffic{}, ErrInvalid
		}
		zero := netip.IPv4Unspecified()
		if len(predicate.Services) > limit {
			return flow.Traffic{}, flow.ErrBudget
		}
		boxes = make([]flow.Box, 0, len(predicate.Services))
		for _, term := range predicate.Services {
			if err := ctx.Err(); err != nil {
				return flow.Traffic{}, err
			}
			boxes = append(boxes, flow.Box{Source: flow.Range{First: zero, Last: zero}, Destination: flow.Range{First: zero, Last: zero}, Protocol: term.Protocol, SourcePort: term.SourcePort, DestinationPort: term.DestinationPort, ICMPType: term.ICMPType, ICMPCode: term.ICMPCode})
		}
	default:
		return flow.Traffic{}, ErrInvalid
	}
	return flow.NewTraffic(limit, boxes...)
}
