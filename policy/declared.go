package policy

import (
	"context"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
)

// RuleMatch is a declaration's possible geometric coverage, before ordered
// consumption, activation dates or its disabled flag are applied.
type RuleMatch struct {
	Rule    fm.ID
	Traffic flow.Traffic
	Known   bool
}

// Declared explains matching declarations, including inactive and disabled
// rules. Native VIP eligibility is preserved. With path, q must be a retained
// NativeRequest and returned traffic uses path.Policy coordinates. Without path,
// traffic uses Engine.Query coordinates. It does not assert effective permission.
func (e Engine) Declared(ctx context.Context, fw *fm.Firewall, q Request, path *PacketPath) ([]RuleMatch, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if fw == nil {
		return nil, ErrInvalid
	}
	limits := e.Limits.WithDefaults()
	budget := packetProofBudget{limits: limits, remaining: limits.MaxVisits}
	if q.Traffic.RegionCount() > limits.MaxRegions {
		return nil, ErrBudget
	}
	if err := budget.take(ctx, fw.DeclarationSize(), q.Traffic.RegionCount()); err != nil {
		return nil, err
	}
	if q.RuleSet == "" {
		q.RuleSet = "security"
	}
	views, err := e.declarationViews(ctx, fw, q, path, &budget)
	if err != nil {
		return nil, err
	}
	known := true
	for _, d := range fw.Diagnostics() {
		known = known && d.Object != ""
	}
	cache := &resolutionCache{firewall: fw, remaining: limits.MaxCombinations}
	resolution := &resolutionBudget{ctx: ctx, cache: cache}
	matches := make(map[fm.ID]RuleMatch)
	regions := 0
	for _, view := range views {
		if err := e.declaredRules(ctx, fw, view, known, matches, &regions, resolution, &budget); err != nil {
			return nil, err
		}
	}
	out := make([]RuleMatch, 0, len(matches))
	for rule := range fw.OrderedRules() {
		if err := budget.take(ctx, 1); err != nil {
			return nil, err
		}
		if match, ok := matches[rule.ID()]; ok {
			out = append(out, match)
		}
	}
	return out, nil
}

type declarationView struct {
	request  Request
	nat      NATRelation
	original bool
	known    bool
}

func (e Engine) declarationViews(ctx context.Context, fw *fm.Firewall, q Request, path *PacketPath, budget *packetProofBudget) ([]declarationView, error) {
	if path == nil {
		if fw.Metadata().Vendor != "fortinet" {
			return []declarationView{{request: q, known: true}}, nil
		}
		nat, err := e.fortinetDestinations(ctx, fw, q, &budget.remaining)
		if err != nil {
			return nil, err
		}
		if len(nat.Relations) > budget.limits.MaxCombinations {
			return nil, ErrBudget
		}
		if err := budget.take(ctx, len(nat.Relations)+1); err != nil {
			return nil, err
		}
		var views []declarationView
		for _, part := range natParts(nat) {
			if len(views) >= budget.limits.MaxCombinations {
				return nil, ErrBudget
			}
			request := q
			request.Traffic = part.Translated
			views = append(views, declarationView{request: request, nat: part, original: true, known: nat.Complete})
		}
		return views, nil
	}
	if len(path.NativeRequests) > budget.limits.MaxCombinations {
		return nil, ErrBudget
	}
	if err := budget.take(ctx, len(path.NativeRequests)); err != nil {
		return nil, err
	}
	found := false
	for _, native := range path.NativeRequests {
		if !q.SameContext(native) {
			continue
		}
		same, err := budget.equal(ctx, q.Traffic, native.Traffic)
		if err != nil {
			return nil, err
		}
		found = found || same
	}
	if !found {
		return nil, ErrInvalid
	}
	mapping, err := policyCoordinates(ctx, fw, *path, budget)
	if err != nil {
		return nil, err
	}
	view := declarationView{request: q, known: true, nat: NATRelation{Original: path.Original, Translated: mapping.traffic, Steps: path.PolicyNAT}}
	if fw.Metadata().Vendor == "fortinet" {
		if len(path.PolicyNAT) > 1 {
			return nil, ErrNAT
		}
		if len(path.PolicyNAT) == 1 {
			view.nat.Kind, view.nat.ID = path.PolicyNAT[0].Kind, path.PolicyNAT[0].ID
		}
		view.request.Traffic = mapping.traffic
	} else {
		if err := budget.traffic(ctx, q.Traffic, mapping.traffic); err != nil {
			return nil, err
		}
		view.request.Traffic, err = q.Traffic.Intersection(mapping.traffic, budget.limits.MaxRegions)
		if err != nil {
			return nil, err
		}
	}
	return []declarationView{view}, nil
}

func (e Engine) declaredRules(ctx context.Context, fw *fm.Firewall, view declarationView, known bool, matches map[fm.ID]RuleMatch, regions *int, resolution *resolutionBudget, budget *packetProofBudget) error {
	if err := budget.take(ctx, fw.DeclarationSize()); err != nil {
		return err
	}
	var selected map[fm.ID]fm.RuleRecord
	var err error
	if fw.Metadata().Vendor == "fortinet" {
		selected, err = e.fortinetRules(ctx, fw, view.request, view.nat, &budget.remaining, true)
		if err != nil {
			return err
		}
	}
	var mapping policyMapping
	if view.original {
		mapping, err = policyCoordinates(ctx, fw, PacketPath{Original: view.nat.Original, PolicyNAT: view.nat.Steps}, budget)
		if err != nil {
			return err
		}
	}
	for rule := range fw.OrderedRules() {
		if err := budget.take(ctx, 1); err != nil {
			return err
		}
		if rule.Chain() != view.request.Chain() {
			continue
		}
		r := rule.Record()
		if selected != nil {
			var include bool
			r, include = selected[r.ID]
			if !include {
				continue
			}
		}
		r.Match.Schedule = ""
		spent := resolution.spent
		resolution.limit = min(budget.limits.MaxCombinations, spent+budget.remaining)
		traffic, matchKnown, err := e.matchTraffic(ctx, fw, r.Match, view.request, view.request.Traffic, resolution)
		if err != nil {
			return err
		}
		if _, err := budget.product(ctx, resolution.spent-spent, max(1, view.request.Traffic.RegionCount())); err != nil {
			return err
		}
		if traffic.Empty() {
			continue
		}
		if view.original {
			traffic, err = mapping.original(ctx, traffic, budget)
			if err != nil {
				return err
			}
		}
		match, exists := matches[r.ID]
		if !exists {
			if len(matches) >= budget.limits.MaxCombinations {
				return ErrBudget
			}
			match = RuleMatch{Rule: r.ID, Known: true}
		}
		*regions -= match.Traffic.RegionCount()
		match.Traffic, err = budget.union(ctx, match.Traffic, traffic)
		if err != nil {
			return err
		}
		*regions += match.Traffic.RegionCount()
		if *regions > budget.limits.MaxRegions {
			return ErrBudget
		}
		match.Known = match.Known && known && view.known && matchKnown && len(r.Unsupported) == 0
		matches[r.ID] = match
	}
	return nil
}
