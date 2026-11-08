// Package policy evaluates ordered firewall policies and native NAT relations.
package policy

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
)

var ErrInvalid = errors.New("policy: invalid input")

var ErrBudget = errors.New("policy evaluation budget exceeded")

// Limits bounds each evaluation algorithm independently. MaxRegions bounds both
// input and retained traffic regions, or address intervals for route resolution.
// Nonpositive values use defaults.
type Limits struct{ MaxRegions, MaxVisits, MaxCombinations int }

// WithDefaults returns effective limits without changing the receiver.
func (l Limits) WithDefaults() Limits {
	if l.MaxRegions <= 0 {
		l.MaxRegions = 4096
	}
	if l.MaxVisits <= 0 {
		l.MaxVisits = 100000
	}
	if l.MaxCombinations <= 0 {
		l.MaxCombinations = 4096
	}
	return l
}

func (l Limits) checkRegions(count int) error {
	if count > l.WithDefaults().MaxRegions {
		return ErrBudget
	}
	return nil
}

type Engine struct{ Limits Limits }
type Request struct {
	Traffic          flow.Traffic
	Scope, RuleSet   string
	FromZone, ToZone fm.ID
	EgressInterface  fm.ID
	At               time.Time
}

// RuleDecision records the effective traffic consumed by one ordered rule.
type RuleDecision struct {
	Rule    fm.ID
	Action  fm.Action
	Traffic flow.Traffic
	// Known requires an established match, active schedule and valid action.
	Known bool
}

// Result partitions the requested traffic by its established policy outcome.
// Complete reports that every outcome was established. Any Unknown traffic
// clears Complete, so a Complete result never carries Unknown traffic; proofs
// may still check both. Decisions follow native evaluation order.
type Result struct {
	Allowed, Denied, Unknown, Unmatched flow.Traffic
	Decisions                           []RuleDecision
	Complete                            bool
}

func (e Engine) Query(ctx context.Context, fw *fm.Firewall, q Request) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if fw == nil {
		return Result{}, ErrInvalid
	}
	if err := e.Limits.checkRegions(q.Traffic.RegionCount()); err != nil {
		return Result{}, err
	}
	// Unknown top-level syntax may introduce earlier policy. Do not retain
	// certain denies, unmatched traffic or rule ownership from a partial graph.
	for _, d := range fw.Diagnostics() {
		if d.Object == "" {
			return Result{Unknown: q.Traffic}, nil
		}
	}
	return semantics(fw.Metadata().Vendor).queryPolicy(e, ctx, fw, q)
}

// queryRules evaluates one native policy view. selectRule only adapts a copied
// declaration; it cannot alter the immutable graph or native order.
func (e Engine) queryRules(ctx context.Context, fw *fm.Firewall, q Request, selectRule func(fm.RuleRecord) (fm.RuleRecord, bool)) (Result, error) {
	limits := e.Limits.WithDefaults()
	remainingTraffic := q.Traffic
	result := Result{Complete: true}
	cache := &resolutionCache{firewall: fw, remaining: limits.MaxCombinations}
	if q.RuleSet == "" {
		q.RuleSet = "security"
	}
	visitedRules := 0
	copies := limits.MaxVisits
	for rule := range fw.OrderedRules() {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		if remainingTraffic.Empty() {
			break
		}
		if visitedRules >= limits.MaxVisits {
			return Result{}, ErrBudget
		}
		visitedRules++
		// Eligibility precedes declaration matching; order is native rule order.
		if rule.Disabled() || rule.Chain() != q.Chain() {
			continue
		}
		// Visit and copy budgets are independent: skipped rules still count as
		// visits, while only owned declarations consume nested-copy capacity.
		if err := chargeVisits(ctx, &copies, rule.DeclarationSize()); err != nil {
			return Result{}, err
		}
		ruleRecord := rule.Record()
		if selectRule != nil {
			var include bool
			ruleRecord, include = selectRule(ruleRecord)
			if !include {
				continue
			}
		}
		matchedTraffic, matchKnown, err := e.match(ctx, fw, ruleRecord.Match, q, remainingTraffic, cache)
		if err != nil {
			return Result{}, err
		}
		if matchedTraffic.Empty() {
			continue
		}
		if len(ruleRecord.Unsupported) > 0 {
			matchKnown = false
		}
		// Known inactive schedules do not consume traffic.
		scheduleActive, scheduleKnown := schedule(fw, ruleRecord.Match.Schedule, q.At)
		if scheduleKnown && !scheduleActive {
			continue
		}
		decisionKnown := matchKnown && scheduleKnown && ruleRecord.Action.Valid()
		if !decisionKnown {
			result.Unknown, err = result.Unknown.Union(matchedTraffic, limits.MaxRegions)
			result.Complete = false
		} else if ruleRecord.Action == fm.Permit {
			result.Allowed, err = result.Allowed.Union(matchedTraffic, limits.MaxRegions)
		} else {
			result.Denied, err = result.Denied.Union(matchedTraffic, limits.MaxRegions)
		}
		if err != nil {
			return Result{}, err
		}
		result.Decisions = append(result.Decisions, RuleDecision{Rule: ruleRecord.ID, Action: ruleRecord.Action, Traffic: matchedTraffic, Known: decisionKnown})
		// Potential unknown matches consume before later rules, just like known matches.
		remainingTraffic, err = remainingTraffic.Difference(matchedTraffic, limits.MaxRegions)
		if err != nil {
			return Result{}, err
		}
	}
	result.Unmatched = remainingTraffic
	return result, nil
}
func schedule(fw *fm.Firewall, id fm.ID, at time.Time) (bool, bool) {
	if id == "" {
		return true, true
	}
	s := fw.Schedule(id)
	if s == nil || at.IsZero() {
		return true, false
	}
	return s.ActiveAt(at)
}

// AddressSet is immutable; wildcard and unresolved matches can share the same
// universe instead of rebuilding its IPv4/IPv6 indexes for every rule.
var allAddresses = func() flow.AddressSet {
	a, _ := flow.PrefixRange(netip.MustParsePrefix("0.0.0.0/0"))
	b, _ := flow.PrefixRange(netip.MustParsePrefix("::/0"))
	s, _ := flow.NewAddressSet(a, b)
	return s
}()

func zoneMatch(zones []fm.ID, any bool, q fm.ID) (bool, bool) {
	if any {
		return true, true
	}
	if q == "" {
		return true, false
	}
	return slices.Contains(zones, q), true
}

// Match returns a conservative possible match and whether that match is semantically certain.
func (e Engine) Match(ctx context.Context, fw *fm.Firewall, m fm.Match, q Request, input flow.Traffic) (flow.Traffic, bool, error) {
	return e.match(ctx, fw, m, q, input, nil)
}

func (e Engine) match(ctx context.Context, fw *fm.Firewall, m fm.Match, q Request, input flow.Traffic, cache *resolutionCache) (flow.Traffic, bool, error) {
	budget := &resolutionBudget{ctx: ctx, limit: e.Limits.WithDefaults().MaxCombinations, cache: cache}
	return e.matchTraffic(ctx, fw, m, q, input, budget)
}

func (e Engine) matchTraffic(ctx context.Context, fw *fm.Firewall, m fm.Match, q Request, input flow.Traffic, budget *resolutionBudget) (flow.Traffic, bool, error) {
	if err := ctx.Err(); err != nil {
		return flow.Traffic{}, false, err
	}
	if fw == nil {
		return flow.Traffic{}, false, ErrInvalid
	}
	if err := e.Limits.checkRegions(input.RegionCount()); err != nil {
		return flow.Traffic{}, false, err
	}
	if normalize := semantics(fw.Metadata().Vendor).normalizeRequest; normalize != nil {
		q = normalize(q)
	}
	limits := e.Limits.WithDefaults()
	relationKnown := true
	if m.ZoneRelation != fm.AnyZoneRelation {
		from, to := fw.Zone(q.FromZone), fw.Zone(q.ToZone)
		relationKnown = from != nil && to != nil
		if relationKnown {
			relationKnown = !from.HasUnsupported() && !to.HasUnsupported()
		}
		if m.ZoneRelation != fm.SameZone && m.ZoneRelation != fm.DifferentZones {
			relationKnown = false
		}
		if relationKnown && (m.ZoneRelation == fm.SameZone && q.FromZone != q.ToZone || m.ZoneRelation == fm.DifferentZones && q.FromZone == q.ToZone) {
			return flow.Traffic{}, true, nil
		}
	}
	fromZoneMatches, fromZoneKnown := zoneMatch(m.FromZones, m.AnyFromZone, q.FromZone)
	toZoneMatches, toZoneKnown := zoneMatch(m.ToZones, m.AnyToZone, q.ToZone)
	if !fromZoneMatches || !toZoneMatches {
		return flow.Traffic{}, true, nil
	}
	sourceAddresses, sourceKnown, err := resolveAddresses(fw, m.Sources, m.AnySource, budget)
	if err != nil {
		return flow.Traffic{}, false, err
	}
	destinationAddresses, destinationKnown, err := resolveAddresses(fw, m.Destinations, m.AnyDestination, budget)
	if err != nil {
		return flow.Traffic{}, false, err
	}
	serviceTerms, serviceKnown, err := resolveServices(fw, m.Services, m.AnyService, budget)
	if err != nil {
		return flow.Traffic{}, false, err
	}
	for _, zones := range [][]fm.ID{m.FromZones, m.ToZones} {
		for _, id := range zones {
			zone := fw.Zone(id)
			if zone == nil || zone.HasUnsupported() {
				fromZoneKnown = false
			}
		}
	}

	matchKnown := relationKnown && fromZoneKnown && toZoneKnown && sourceKnown && destinationKnown && serviceKnown && len(m.Unsupported) == 0 && len(m.Applications) == 0 && len(m.Users) == 0
	var matchedTraffic flow.Traffic
	for src := range sourceAddresses.All() {
		for dst := range destinationAddresses.All() {
			if src.First.BitLen() != dst.First.BitLen() {
				continue
			}
			for _, service := range serviceTerms {
				if err := ctx.Err(); err != nil {
					return flow.Traffic{}, false, err
				}
				if err := budget.charge(); err != nil {
					return flow.Traffic{}, false, err
				}
				region := flow.TrafficRegion{Source: src, Destination: dst, Protocol: service.Protocol, SourcePort: service.SourcePort, DestinationPort: service.DestinationPort, ICMPType: service.ICMPType, ICMPCode: service.ICMPCode}
				intersection, err := input.Clip(region, limits.MaxRegions)
				if err != nil {
					return flow.Traffic{}, false, err
				}
				if intersection.Empty() {
					continue
				}
				matchedTraffic, err = matchedTraffic.Union(intersection, limits.MaxRegions)
				if err != nil {
					return flow.Traffic{}, false, err
				}
			}
		}
	}
	return matchedTraffic, matchKnown, nil
}

// Chain returns the native chain without changing the request's wire representation.
func (r Request) Chain() fm.PolicyChain { return fm.PolicyChain{Scope: r.Scope, RuleSet: r.RuleSet} }

// SameContext compares policy evaluation contexts, treating an omitted rule set
// as security. Time equality uses the instant, not location or monotonic metadata.
func (r Request) SameContext(other Request) bool {
	ruleSet := r.RuleSet
	if ruleSet == "" {
		ruleSet = "security"
	}
	otherRuleSet := other.RuleSet
	if otherRuleSet == "" {
		otherRuleSet = "security"
	}
	return r.Scope == other.Scope && ruleSet == otherRuleSet && r.FromZone == other.FromZone && r.ToZone == other.ToZone && r.EgressInterface == other.EgressInterface && r.At.Equal(other.At)
}
