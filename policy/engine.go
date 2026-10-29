// Package policy evaluates ordered firewall policies and native NAT relations.
package policy

import (
	"context"
	"errors"
	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"net/netip"
	"slices"
	"time"
)

var ErrInvalid = errors.New("policy: invalid input")

var ErrBudget = errors.New("policy evaluation budget exceeded")

type Limits struct{ Regions, Rules, Combinations int }

func (l Limits) defaults() Limits {
	if l.Regions <= 0 {
		l.Regions = 4096
	}
	if l.Rules <= 0 {
		l.Rules = 100000
	}
	if l.Combinations <= 0 {
		l.Combinations = 4096
	}
	return l
}

type Engine struct{ Limits Limits }
type Request struct {
	Traffic          flow.Traffic
	Scope, RuleSet   string
	FromZone, ToZone fm.ID
	EgressInterface  fm.ID
	At               time.Time
}
type Trace struct {
	Rule    fm.ID
	Action  fm.Action
	Traffic flow.Traffic
	Certain bool
}
type Result struct {
	Allowed, Denied, Unknown, Unmatched flow.Traffic
	Trace                               []Trace
	Complete                            bool
}

func (e Engine) Query(ctx context.Context, fw *fm.Firewall, q Request) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if fw == nil {
		return Result{}, ErrInvalid
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
	limits := e.Limits.defaults()
	remaining := q.Traffic
	result := Result{Complete: true}
	cache := &resolutionCache{firewall: fw, remaining: limits.Combinations}
	if q.RuleSet == "" {
		q.RuleSet = "security"
	}
	i := 0
	for rule := range fw.OrderedRules() {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		if remaining.Empty() {
			break
		}
		if i >= limits.Rules {
			return Result{}, ErrBudget
		}
		i++
		r := rule.Record()
		if r.Disabled || r.Scope != q.Scope || r.RuleSet != q.RuleSet {
			continue
		}
		if selectRule != nil {
			var include bool
			r, include = selectRule(r)
			if !include {
				continue
			}
		}
		hit, certain, err := e.match(ctx, fw, r.Match, q, remaining, cache)
		if err != nil {
			return Result{}, err
		}
		if hit.Empty() {
			continue
		}
		if len(r.Unsupported) > 0 {
			certain = false
		}
		active, known := schedule(fw, r.Match.Schedule, q.At)
		if known && !active {
			continue
		}
		certain = certain && known
		if !certain || !r.Action.Valid() {
			result.Unknown, err = result.Unknown.Union(hit, limits.Regions)
			result.Complete = false
		} else if r.Action == fm.Permit {
			result.Allowed, err = result.Allowed.Union(hit, limits.Regions)
		} else {
			result.Denied, err = result.Denied.Union(hit, limits.Regions)
		}
		if err != nil {
			return Result{}, err
		}
		result.Trace = append(result.Trace, Trace{Rule: r.ID, Action: r.Action, Traffic: hit, Certain: certain})
		remaining, err = remaining.Difference(hit, limits.Regions)
		if err != nil {
			return Result{}, err
		}
	}
	result.Unmatched = remaining
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
	r := s.Record()
	if len(r.Unsupported) > 0 || len(r.Recurring) > 0 || len(r.Windows) == 0 {
		return true, false
	}
	for _, w := range r.Windows {
		if !at.Before(w.Start) && at.Before(w.End) {
			return true, true
		}
	}
	return false, true
}
func allAddresses() flow.Set {
	a, _ := flow.PrefixRange(netip.MustParsePrefix("0.0.0.0/0"))
	b, _ := flow.PrefixRange(netip.MustParsePrefix("::/0"))
	s, _ := flow.NewSet(a, b)
	return s
}
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
	if err := ctx.Err(); err != nil {
		return flow.Traffic{}, false, err
	}
	if fw == nil {
		return flow.Traffic{}, false, ErrInvalid
	}
	if normalize := semantics(fw.Metadata().Vendor).normalizeRequest; normalize != nil {
		q = normalize(q)
	}
	limits := e.Limits.defaults()
	budget := &resolutionBudget{ctx: ctx, limit: limits.Combinations, cache: cache}
	relationKnown := true
	if m.ZoneRelation != fm.AnyZoneRelation {
		from, to := fw.Zone(q.FromZone), fw.Zone(q.ToZone)
		relationKnown = from != nil && to != nil
		if relationKnown {
			relationKnown = len(from.Record().Unsupported) == 0 && len(to.Record().Unsupported) == 0
		}
		if m.ZoneRelation != fm.SameZone && m.ZoneRelation != fm.DifferentZones {
			relationKnown = false
		}
		if relationKnown && (m.ZoneRelation == fm.SameZone && q.FromZone != q.ToZone || m.ZoneRelation == fm.DifferentZones && q.FromZone == q.ToZone) {
			return flow.Traffic{}, true, nil
		}
	}
	from, fk := zoneMatch(m.FromZones, m.AnyFromZone, q.FromZone)
	to, tk := zoneMatch(m.ToZones, m.AnyToZone, q.ToZone)
	if !from || !to {
		return flow.Traffic{}, true, nil
	}
	sources, sk, err := resolveAddresses(fw, m.Sources, m.AnySource, budget)
	if err != nil {
		return flow.Traffic{}, false, err
	}
	destinations, dk, err := resolveAddresses(fw, m.Destinations, m.AnyDestination, budget)
	if err != nil {
		return flow.Traffic{}, false, err
	}
	services, vk, err := resolveServices(fw, m.Services, m.AnyService, budget)
	if err != nil {
		return flow.Traffic{}, false, err
	}
	for _, id := range append(slices.Clone(m.FromZones), m.ToZones...) {
		zone := fw.Zone(id)
		if zone == nil || len(zone.Record().Unsupported) > 0 {
			fk = false
		}
	}

	known := relationKnown && fk && tk && sk && dk && vk && len(m.Unsupported) == 0 && len(m.Applications) == 0 && len(m.Users) == 0
	var out flow.Traffic
	for _, src := range sources.Ranges() {
		for _, dst := range destinations.Ranges() {
			if src.First.BitLen() != dst.First.BitLen() {
				continue
			}
			for _, service := range services {
				if err := ctx.Err(); err != nil {
					return flow.Traffic{}, false, err
				}
				if err := budget.charge(); err != nil {
					return flow.Traffic{}, false, err
				}
				box := flow.Box{Source: src, Destination: dst, Protocol: service.Protocol, SourcePort: service.SourcePort, DestinationPort: service.DestinationPort, ICMPType: service.ICMPType, ICMPCode: service.ICMPCode}
				candidate, err := flow.NewTraffic(limits.Regions, box)
				if err != nil {
					return flow.Traffic{}, false, err
				}
				hit, err := input.Intersection(candidate, limits.Regions)
				if err != nil {
					return flow.Traffic{}, false, err
				}
				out, err = out.Union(hit, limits.Regions)
				if err != nil {
					return flow.Traffic{}, false, err
				}
			}
		}
	}
	return out, known, nil
}

// Chain returns the native chain without changing the request's wire representation.
func (r Request) Chain() fm.PolicyChain { return fm.PolicyChain{Scope: r.Scope, RuleSet: r.RuleSet} }
