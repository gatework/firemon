package analysis

import (
	"context"
	"net/netip"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/policy"
)

func validateRiskExpression(ctx context.Context, expression RiskExpression, limit int, budget *int, depth int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if *budget <= 0 || depth >= 64 {
		return policy.ErrBudget
	}
	*budget--
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
		return ErrInvalid
	}
	if p := expression.Predicate; p != nil {
		if p.Relation < Intersects || p.Relation > NotEqual {
			return ErrInvalid
		}
		_, err := riskStandard(*p, limit)
		return err
	}
	children := expression.All
	if len(expression.Any) > 0 {
		children = expression.Any
	}
	for _, child := range children {
		if err := validateRiskExpression(ctx, child, limit, budget, depth+1); err != nil {
			return err
		}
	}
	return nil
}

func (a RiskAnalyzer) assessExpression(ctx context.Context, fw *fm.Firewall, rule fm.RuleRecord, q policy.Request, mode RiskMode, actual flow.Traffic, expression RiskExpression, limit int, budget *int) (Truth, error) {
	if err := ctx.Err(); err != nil {
		return Unknown, err
	}
	if *budget <= 0 {
		return Unknown, policy.ErrBudget
	}
	*budget--
	if predicate := expression.Predicate; predicate != nil {
		if mode == Declared {
			dimensionMatch := rule.Match
			if predicate.Dimension != Source {
				dimensionMatch.Sources, dimensionMatch.AnySource = nil, true
			}
			if predicate.Dimension != Destination {
				dimensionMatch.Destinations, dimensionMatch.AnyDestination = nil, true
			}
			if predicate.Dimension != Service {
				dimensionMatch.Services, dimensionMatch.AnyService = nil, true
			}
			var known bool
			var err error
			actual, known, err = a.Engine.Match(ctx, fw, dimensionMatch, q, q.Traffic)
			if err != nil {
				return Unknown, err
			}
			if !known {
				return Unknown, nil
			}
		}
		if actual.Empty() {
			return False, nil
		}
		projected, err := riskProjection(actual, predicate.Dimension, limit)
		if err != nil {
			return Unknown, err
		}
		standard, err := riskStandard(*predicate, limit)
		if err != nil {
			return Unknown, err
		}
		value, err := compareTraffic(projected, standard, predicate.Relation, limit)
		if err != nil {
			return Unknown, err
		}
		if value {
			return True, nil
		}
		return False, nil
	}
	children, identity, decisive := expression.All, True, False
	if len(expression.Any) > 0 {
		children, identity, decisive = expression.Any, False, True
	}
	value := identity
	for _, child := range children {
		result, err := a.assessExpression(ctx, fw, rule, q, mode, actual, child, limit, budget)
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

func riskStandard(predicate RiskPredicate, limit int) (flow.Traffic, error) {
	var boxes []flow.Box
	switch predicate.Dimension {
	case Source, Destination:
		if predicate.Addresses.Empty() || len(predicate.Services) != 0 {
			return flow.Traffic{}, ErrInvalid
		}
		for _, address := range predicate.Addresses.Ranges() {
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
		for _, term := range predicate.Services {
			boxes = append(boxes, flow.Box{Source: flow.Range{First: zero, Last: zero}, Destination: flow.Range{First: zero, Last: zero}, Protocol: term.Protocol, SourcePort: term.SourcePort, DestinationPort: term.DestinationPort, ICMPType: term.ICMPType, ICMPCode: term.ICMPCode})
		}
	default:
		return flow.Traffic{}, ErrInvalid
	}
	return flow.NewTraffic(limit, boxes...)
}
