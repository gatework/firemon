package plan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/internal/servicecoverage"
	"github.com/gatework/firemon/policy"
)

func sameZones(m fm.Match, q policy.Request) bool {
	from := q.FromZone == "" && m.AnyFromZone || !m.AnyFromZone && len(m.FromZones) == 1 && m.FromZones[0] == q.FromZone
	to := q.ToZone == "" && m.AnyToZone || !m.AnyToZone && len(m.ToZones) == 1 && m.ToZones[0] == q.ToZone
	return from && to
}

func generatedID(prefix string, value any) fm.ID {
	b, _ := json.Marshal(value)
	sum := sha256.Sum256(b)
	return fm.ID(prefix + hex.EncodeToString(sum[:8]))
}

func (p Planner) appendCandidate(ctx context.Context, fw *fm.Firewall, rule fm.RuleRecord, gap flow.Traffic, visits *visitBudget) (*fm.Firewall, []Change, Cost, error) {
	if err := visits.take(ctx, fw.RecordCount()); err != nil {
		return nil, nil, Cost{}, err
	}
	d := fw.Export()
	catalog, err := newObjectCatalog(ctx, fw, &d, p.Engine.Limits.WithDefaults(), visits)
	if err != nil {
		return nil, nil, Cost{}, err
	}
	objects := len(d.Addresses) + len(d.Services)
	change := Change{Kind: AppendMembers, Rule: rule.ID}
	sourceAddresses, known, err := p.Engine.ResolveAddresses(ctx, fw, rule.Match.Sources, rule.Match.AnySource)
	if err != nil {
		return nil, nil, Cost{}, err
	}
	if !known {
		return nil, nil, Cost{}, ErrUnsafe
	}
	destinationAddresses, known, err := p.Engine.ResolveAddresses(ctx, fw, rule.Match.Destinations, rule.Match.AnyDestination)
	if err != nil {
		return nil, nil, Cost{}, err
	}
	if !known {
		return nil, nil, Cost{}, ErrUnsafe
	}
	serviceTerms, known, err := p.Engine.ResolveServices(ctx, fw, rule.Match.Services, rule.Match.AnyService)
	if err != nil {
		return nil, nil, Cost{}, err
	}
	if !known {
		return nil, nil, Cost{}, ErrUnsafe
	}
	limit := p.Engine.Limits.WithDefaults().MaxRegions
	if err := visits.take(ctx, len(serviceTerms)); err != nil {
		return nil, nil, Cost{}, err
	}
	serviceCoverage, err := servicecoverage.FromTerms(ctx, serviceTerms, limit)
	if err != nil {
		return nil, nil, Cost{}, err
	}
	if err := visits.take(ctx, gap.RegionCount()); err != nil {
		return nil, nil, Cost{}, err
	}
	for _, region := range gap.Regions() {
		if err := ctx.Err(); err != nil {
			return nil, nil, Cost{}, err
		}
		addresses, _ := flow.NewAddressSet(region.Source)
		if !sourceAddresses.Contains(addresses) {
			ref, err := catalog.ensureAddress(ctx, region.Source, rule.Match.FromZones, rule.Scope)
			if err != nil {
				return nil, nil, Cost{}, err
			}
			if !slices.Contains(change.Sources, ref) {
				change.Sources = append(change.Sources, ref)
				rule.Match.Sources = append(rule.Match.Sources, ref)
			}
			sourceAddresses = sourceAddresses.Union(addresses)
		}
		addresses, _ = flow.NewAddressSet(region.Destination)
		if !destinationAddresses.Contains(addresses) {
			ref, err := catalog.ensureAddress(ctx, region.Destination, rule.Match.ToZones, rule.Scope)
			if err != nil {
				return nil, nil, Cost{}, err
			}
			if !slices.Contains(change.Destinations, ref) {
				change.Destinations = append(change.Destinations, ref)
				rule.Match.Destinations = append(rule.Match.Destinations, ref)
			}
			destinationAddresses = destinationAddresses.Union(addresses)
		}
		term := serviceTermFromRegion(region)
		requestedService, err := servicecoverage.FromTerms(ctx, []fm.ServiceTerm{term}, limit)
		if err != nil {
			return nil, nil, Cost{}, err
		}
		covered, err := serviceCoverage.Contains(requestedService, limit)
		if err != nil {
			return nil, nil, Cost{}, err
		}
		if !covered {
			ref, err := catalog.ensureService(ctx, term, rule.Scope)
			if err != nil {
				return nil, nil, Cost{}, err
			}
			if !slices.Contains(change.Services, ref) {
				change.Services = append(change.Services, ref)
				rule.Match.Services = append(rule.Match.Services, ref)
				serviceCoverage, err = serviceCoverage.Union(requestedService, limit)
				if err != nil {
					return nil, nil, Cost{}, err
				}
			}
		}
	}
	count := len(change.Sources) + len(change.Destinations) + len(change.Services)
	if count == 0 {
		return nil, nil, Cost{}, nil
	}
	if err := visits.take(ctx, len(d.Rules)); err != nil {
		return nil, nil, Cost{}, err
	}
	for i := range d.Rules {
		if d.Rules[i].ID == rule.ID {
			d.Rules[i] = rule
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, Cost{}, err
	}
	next, err := fm.Seal(d)
	cost := Cost{AppendedMembers: count, NewObjects: len(d.Addresses) + len(d.Services) - objects, ModifiedRules: 1, Position: rule.Position, ID: string(rule.ID)}
	return next, []Change{change}, cost, err
}

func (p Planner) createCandidate(ctx context.Context, fw *fm.Firewall, q policy.Request, gap flow.Traffic, visits *visitBudget) (*fm.Firewall, []Change, Cost, error) {
	if err := visits.take(ctx, fw.RecordCount()); err != nil {
		return nil, nil, Cost{}, err
	}
	d := fw.Export()
	catalog, err := newObjectCatalog(ctx, fw, &d, p.Engine.Limits.WithDefaults(), visits)
	if err != nil {
		return nil, nil, Cost{}, err
	}
	objects := len(d.Addresses) + len(d.Services)
	if err := visits.take(ctx, gap.RegionCount()); err != nil {
		return nil, nil, Cost{}, err
	}
	boxes := gap.Regions()
	var changes []Change
	var newRules []fm.RuleRecord
	for i, box := range boxes {
		if err := ctx.Err(); err != nil {
			return nil, nil, Cost{}, err
		}
		m, err := catalog.match(ctx, box, q)
		if err != nil {
			return nil, nil, Cost{}, err
		}
		rule := fm.RuleRecord{Object: fm.Object{Scope: q.Scope}, RuleSet: q.RuleSet, Position: i, Match: m, Action: fm.Permit, Log: fm.Irrelevant, LogStart: fm.Irrelevant, LogEnd: fm.Irrelevant}
		id, err := catalog.names.rule(ctx, generatedID("fm-new-", box), rule)
		if err != nil {
			return nil, nil, Cost{}, err
		}
		rule.ID, rule.Name = id, string(id)
		newRules = append(newRules, rule)
		changes = append(changes, Change{Kind: CreateRule, Rule: id, Sources: m.Sources, Destinations: m.Destinations, Services: m.Services})
	}
	if err := visits.take(ctx, len(d.Rules)); err != nil {
		return nil, nil, Cost{}, err
	}
	// Preserve prior relative order, including sparse native positions.
	slices.SortStableFunc(d.Rules, func(a, b fm.RuleRecord) int {
		if a.Position < b.Position {
			return -1
		}
		if a.Position > b.Position {
			return 1
		}
		return strings.Compare(string(a.ID), string(b.ID))
	})
	if err := visits.take(ctx, len(d.Rules)); err != nil {
		return nil, nil, Cost{}, err
	}
	for i := range d.Rules {
		d.Rules[i].Position = i + len(newRules)
	}
	d.Rules = append(newRules, d.Rules...)
	if err := ctx.Err(); err != nil {
		return nil, nil, Cost{}, err
	}
	next, err := fm.Seal(d)
	cost := Cost{NewRules: len(changes), NewObjects: len(d.Addresses) + len(d.Services) - objects}
	return next, changes, cost, err
}
