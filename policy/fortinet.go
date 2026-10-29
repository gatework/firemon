package policy

import (
	"context"
	"errors"
	"slices"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
)

// FortiOS binds VIPs to policies and gives those policies (and match-vip deny
// policies) their own lookup class. A public VIP address is not an ordinary
// address match, even when its port-forward condition does not match.
func (e Engine) fortinetQuery(ctx context.Context, fw *fm.Firewall, q Request) (Result, error) {
	budget := e.Limits.WithDefaults().MaxVisits
	pre, err := e.fortinetDestinations(ctx, fw, q, &budget)
	if err != nil {
		return Result{}, err
	}
	out := Result{Complete: pre.Complete, Unknown: pre.Unknown}
	type decisionKey struct {
		rule   fm.ID
		action fm.Action
		known  bool
	}
	decisionIndexes := make(map[decisionKey]int)
	for _, view := range natParts(pre) {
		part, err := e.fortinetPolicy(ctx, fw, q, view, &budget)
		if err != nil {
			return Result{}, err
		}
		part, err = fortinetOriginalResult(fw, view, part, e.Limits.WithDefaults().MaxRegions)
		if err != nil {
			return Result{}, err
		}
		for _, pair := range []struct {
			dst *flow.Traffic
			src flow.Traffic
		}{{&out.Allowed, part.Allowed}, {&out.Denied, part.Denied}, {&out.Unknown, part.Unknown}, {&out.Unmatched, part.Unmatched}} {
			*pair.dst, err = pair.dst.Union(pair.src, e.Limits.WithDefaults().MaxRegions)
			if err != nil {
				return Result{}, err
			}
		}
		for _, decision := range part.Decisions {
			key := decisionKey{decision.Rule, decision.Action, decision.Known}
			if i, exists := decisionIndexes[key]; exists {
				out.Decisions[i].Traffic, err = out.Decisions[i].Traffic.Union(decision.Traffic, e.Limits.WithDefaults().MaxRegions)
				if err != nil {
					return Result{}, err
				}
			} else {
				if len(out.Decisions) >= e.Limits.WithDefaults().MaxRegions {
					return Result{}, ErrBudget
				}
				decisionIndexes[key] = len(out.Decisions)
				out.Decisions = append(out.Decisions, decision)
			}
		}
		out.Complete = out.Complete && part.Complete
	}
	return out, nil
}

func (e Engine) fortinetDestinations(ctx context.Context, fw *fm.Firewall, q Request, budget *int) (NATResult, error) {
	limit := e.Limits.WithDefaults().MaxRegions
	out := NATResult{Complete: true}
	var covered flow.Traffic
	for _, entry := range fw.NATSequence() {
		if err := ctx.Err(); err != nil {
			return NATResult{}, err
		}
		if *budget <= 0 {
			return NATResult{}, ErrBudget
		}
		*budget--
		if entry.Scope != q.Scope || entry.Order.Section != "vip" {
			continue
		}
		step := NATStep{Kind: entry.Kind, ID: entry.ID}
		n, err := transform(fw, step)
		if err != nil {
			return NATResult{}, err
		}
		if n.disabled {
			continue
		}
		// extintf constrains policy use. srcintf-filter, when supported, is the
		// listener restriction. A VIP must not become ordinary routed traffic
		// simply because its external interface is different.
		match := n.match
		match.FromZones = nil
		match.AnyFromZone = true
		hit, known, err := e.Match(ctx, fw, match, q, q.Traffic)
		if err != nil {
			return NATResult{}, err
		}
		hit, err = restrictMappings(hit, n.destination, false, limit)
		if err != nil {
			return NATResult{}, err
		}
		if hit.Empty() {
			continue
		}
		overlap, err := covered.Intersection(hit, limit)
		if err != nil {
			return NATResult{}, err
		}
		out.Unknown, err = out.Unknown.Union(overlap, limit)
		if err != nil {
			return NATResult{}, err
		}
		covered, err = covered.Union(hit, limit)
		if err != nil {
			return NATResult{}, err
		}
		if !known || !n.known {
			out.Unknown, err = out.Unknown.Union(hit, limit)
			if err != nil {
				return NATResult{}, err
			}
			continue
		}
		translated, exact, possible, err := n.apply(hit, limit)
		if errors.Is(err, flow.ErrBudget) {
			return NATResult{}, err
		}
		if err != nil {
			out.Unknown, err = out.Unknown.Union(hit, limit)
			if err != nil {
				return NATResult{}, err
			}
			continue
		}
		if len(out.Relations) >= limit {
			return NATResult{}, ErrBudget
		}
		out.Relations = append(out.Relations, NATRelation{Kind: entry.Kind, ID: entry.ID, Steps: []NATStep{step}, Original: hit, Translated: translated, Exact: exact, PossibleAllocation: possible})
	}
	out.Complete = out.Unknown.Empty()
	var err error
	out.Unmatched, err = q.Traffic.Difference(covered, limit)
	if err != nil {
		return NATResult{}, err
	}
	var selected []NATRelation
	for _, part := range out.Relations {
		var err error
		part.Original, err = part.Original.Difference(out.Unknown, limit)
		if err != nil {
			return NATResult{}, err
		}
		if part.Original.Empty() {
			continue
		}
		n, err := transform(fw, part.Steps[0])
		if err != nil {
			return NATResult{}, err
		}
		part.Translated, _, _, err = n.apply(part.Original, limit)
		if err != nil {
			return NATResult{}, err
		}
		selected = append(selected, part)
	}
	out.Relations = selected
	return out, nil
}

// Split destination references once per rule, preserving ordinary objects while
// retaining VIP identity across nested groups. Traversal is bounded and memoized.
func fortinetDestRefs(fw *fm.Firewall, refs []fm.AddressRef, budget *resolutionBudget) ([]fm.AddressRef, map[fm.NATRef]bool, bool, error) {
	var ordinary []fm.AddressRef
	vips := make(map[fm.NATRef]bool)
	states := make(map[fm.AddressRef]uint8)
	known := true
	var visit func(fm.AddressRef) error
	visit = func(ref fm.AddressRef) error {
		if err := budget.charge(); err != nil {
			return err
		}
		if states[ref] == 1 {
			known = false
			return nil
		}
		if states[ref] == 2 {
			return nil
		}
		states[ref] = 1
		switch ref.Kind {
		case fm.AddressObject:
			a := fw.Address(ref.ID)
			if a != nil && a.Record().VIP != (fm.NATRef{}) {
				if a.VIPStaticNAT() == nil && a.VIPDynamicNAT() == nil {
					known = false
				} else {
					vips[a.Record().VIP] = true
				}
			} else {
				ordinary = append(ordinary, ref)
			}
			if a == nil || len(a.Record().Unsupported) > 0 {
				known = false
			}
		case fm.AddressGroupObject:
			g := fw.AddressGroup(ref.ID)
			if g == nil {
				known = false
				break
			}
			if len(g.Record().Unsupported) > 0 {
				known = false
			}
			for _, member := range g.Record().Members {
				if err := visit(member); err != nil {
					return err
				}
			}
		default:
			known = false
		}
		states[ref] = 2
		return nil
	}
	for _, ref := range refs {
		if err := visit(ref); err != nil {
			return nil, nil, false, err
		}
	}
	return ordinary, vips, known, nil
}

func (e Engine) fortinetPolicy(ctx context.Context, fw *fm.Firewall, q Request, view NATRelation, budget *int) (Result, error) {
	rules := fw.Rules()
	if len(rules) > *budget {
		return Result{}, ErrBudget
	}
	*budget -= len(rules)
	resolver := &resolutionBudget{ctx: ctx, limit: e.Limits.WithDefaults().MaxCombinations}
	selected := make(map[fm.ID]fm.RuleRecord)
	for _, rule := range rules {
		r := rule.Record()
		if r.Disabled || r.Scope != q.Scope {
			continue
		}
		normal, vips, known, err := fortinetDestRefs(fw, r.Match.Destinations, resolver)
		if err != nil {
			return Result{}, err
		}
		if !known {
			r.Unsupported = append(r.Unsupported, "unresolved native VIP destination")
			r.Match.AnyDestination = true
		}
		if view.ID == "" {
			r.Match.Destinations = normal
			if known && !r.Match.AnyDestination && len(normal) == 0 {
				continue
			}
		} else if vips[fm.NATRef{Kind: view.Kind, ID: view.ID}] {
			r.Match.Destinations = nil
			r.Match.AnyDestination = true
			n, err := transform(fw, view.Steps[0])
			if err != nil {
				return Result{}, err
			}
			if !n.match.AnyFromZone {
				if q.FromZone == "" {
					r.Match.Unsupported = append(r.Match.Unsupported, "VIP ingress interface is unknown")
				} else if !slices.Contains(n.match.FromZones, q.FromZone) {
					continue
				}
			}
		} else if !r.Builtin {
			if r.Action != fm.Deny || r.MatchVIP == fm.Irrelevant {
				continue
			}
			r.Match.Destinations = normal
			if r.MatchVIP == fm.Unknown {
				r.Unsupported = append(r.Unsupported, "version-dependent match-vip default")
			}
		}
		// Vendor documentation differs about a service restricted to only one
		// side of a translated port. Establish results only when both views
		// agree; otherwise preserve a possible first match as unknown.
		if view.ID != "" && !r.Builtin && len(view.Steps) == 1 {
			n, err := transform(fw, view.Steps[0])
			if err != nil {
				return Result{}, err
			}
			if len(n.destinationPorts) > 0 {
				if *budget < 2 {
					return Result{}, ErrBudget
				}
				*budget -= 2
				match := r.Match
				match.AnyDestination = true
				match.Destinations = nil
				before, k1, err := e.Match(ctx, fw, match, q, view.Original)
				if err != nil {
					return Result{}, err
				}
				after, k2, err := e.Match(ctx, fw, match, q, view.Translated)
				if err != nil {
					return Result{}, err
				}
				after, err = srxOriginal(fw, view, after, e.Limits.WithDefaults().MaxRegions)
				if err != nil {
					return Result{}, err
				}
				a, err := before.Difference(after, e.Limits.WithDefaults().MaxRegions)
				if err != nil {
					return Result{}, err
				}
				b, err := after.Difference(before, e.Limits.WithDefaults().MaxRegions)
				if err != nil {
					return Result{}, err
				}
				if !k1 || !k2 || !a.Empty() || !b.Empty() {
					r.Unsupported = append(r.Unsupported, "unproven translated service view")
					r.Match.AnyService = true
					r.Match.Services = nil
				}
			}
		}
		selected[r.ID] = r
	}
	q.Traffic = view.Translated
	return e.queryRules(ctx, fw, q, func(r fm.RuleRecord) (fm.RuleRecord, bool) { v, ok := selected[r.ID]; return v, ok })
}

func fortinetOriginalResult(fw *fm.Firewall, view NATRelation, part Result, limit int) (Result, error) {
	for _, v := range []*flow.Traffic{&part.Allowed, &part.Denied, &part.Unknown, &part.Unmatched} {
		var err error
		*v, err = srxOriginal(fw, view, *v, limit)
		if err != nil {
			return Result{}, err
		}
	}
	for i := range part.Decisions {
		var err error
		part.Decisions[i].Traffic, err = srxOriginal(fw, view, part.Decisions[i].Traffic, limit)
		if err != nil {
			return Result{}, err
		}
	}
	return part, nil
}
