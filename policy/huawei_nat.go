package policy

import (
	"context"
	"strings"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
)

// Huawei server maps precede policy NAT. Policy NAT selects an entire original
// packet rule (both actions together); a destination rule is not followed by a
// separately selected source rule. ToZone denotes the post-DNAT destination zone.
func (e Engine) huaweiNAT(ctx context.Context, fw *fm.Firewall, q Request, budget *int) (NATResult, error) {
	if q.Scope != "" {
		return NATResult{}, ErrNAT
	}
	// NAT VPN selectors are not represented by this parser yet. A global NAT
	// declaration cannot be assumed to apply across a zone's VPN interfaces.
	for _, i := range fw.Interfaces() {
		r := i.Record()
		if r.Scope != "" && (strings.EqualFold(string(r.Zone), string(q.FromZone)) || strings.EqualFold(string(r.Zone), string(q.ToZone))) {
			return NATResult{Unknown: q.Traffic}, nil
		}
	}
	return e.huaweiSelected(ctx, fw, q, budget, func(request Request, steps []NATStep) (NATResult, error) {
		return e.natChain(ctx, fw, request, steps, budget)
	})
}

func (e Engine) huaweiSelected(ctx context.Context, fw *fm.Firewall, q Request, budget *int, chain func(Request, []NATStep) (NATResult, error)) (NATResult, error) {
	q.FromZone, q.ToZone = fm.ID(strings.ToLower(string(q.FromZone))), fm.ID(strings.ToLower(string(q.ToZone)))
	var servers, policies []NATStep
	for _, entry := range fw.NATSequence() {
		if err := ctx.Err(); err != nil {
			return NATResult{}, err
		}
		if *budget <= 0 {
			return NATResult{}, ErrBudget
		}
		*budget--
		if entry.Scope != q.Scope {
			continue
		}
		step := NATStep{Kind: entry.Kind, ID: entry.ID}
		switch entry.Order.Section {
		case "nat-server":
			if entry.Order.Stage != 0 {
				return NATResult{}, ErrNAT
			}
			servers = append(servers, step)
			if step.Kind == fm.StaticNATObject && fw.StaticNAT(step.ID).Record().Bidirectional {
				step.Reverse = true
				servers = append(servers, step)
			}
		case "nat-policy":
			if entry.Kind != fm.DynamicNATObject || (entry.Order.Stage != 1 && entry.Order.Stage != 2) {
				return NATResult{}, ErrNAT
			}
			policies = append(policies, step)
		default:
			return NATResult{}, ErrNAT
		}
	}
	limit := e.Limits.defaults().Regions
	out := NATResult{Complete: true}
	var covered flow.Traffic
	for _, step := range servers {
		part, err := chain(q, []NATStep{step})
		if err != nil {
			return NATResult{}, err
		}
		hit, err := q.Traffic.Difference(part.Unmatched, limit)
		if err != nil {
			return NATResult{}, err
		}
		overlap, err := covered.Intersection(hit, limit)
		if err != nil {
			return NATResult{}, err
		}
		for _, unknown := range []flow.Traffic{part.Unknown, overlap} {
			out.Unknown, err = out.Unknown.Union(unknown, limit)
			if err != nil {
				return NATResult{}, err
			}
		}
		covered, err = covered.Union(hit, limit)
		if err != nil {
			return NATResult{}, err
		}
		if len(out.Relations)+len(part.Relations) > limit {
			return NATResult{}, ErrBudget
		}
		out.Relations = append(out.Relations, part.Relations...)
	}
	// Overlapping server maps have no configuration-order tie breaker. Trim all
	// candidates to their proven domain, preserving unknown overlap as consumed.
	selected := out.Relations[:0]
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
		mixed, err := e.huaweiMixed(ctx, fw, q, part, n, policies, budget)
		if err != nil {
			return NATResult{}, err
		}
		if mixed {
			out.Unknown, err = out.Unknown.Union(part.Original, limit)
			if err != nil {
				return NATResult{}, err
			}
			continue
		}
		part.Translated, part.Exact, part.PossibleAllocation, err = n.apply(part.Original, limit)
		if err != nil {
			return NATResult{}, err
		}
		selected = append(selected, part)
	}
	out.Relations = selected
	request := q
	var err error
	request.Traffic, err = q.Traffic.Difference(covered, limit)
	if err != nil {
		return NATResult{}, err
	}
	part, err := chain(request, policies)
	if err != nil {
		return NATResult{}, err
	}
	if len(out.Relations)+len(part.Relations) > limit {
		return NATResult{}, ErrBudget
	}
	out.Relations = append(out.Relations, part.Relations...)
	out.Unknown, err = out.Unknown.Union(part.Unknown, limit)
	if err != nil {
		return NATResult{}, err
	}
	out.Unmatched = part.Unmatched
	out.Complete = out.Unknown.Empty()
	return out, nil
}

// A server map's precedence in one direction does not establish whether an
// opposite-direction policy action also executes. Until that composition has
// native version evidence, retain unknown for either possible address view.
func (e Engine) huaweiMixed(ctx context.Context, fw *fm.Firewall, q Request, part NATRelation, server natTransform, policies []NATStep, budget *int) (bool, error) {
	for _, step := range policies {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		if *budget <= 0 {
			return false, ErrBudget
		}
		*budget--
		r := fw.DynamicNAT(step.ID).Record()
		if r.Disabled {
			continue
		}
		if !(len(server.destination) > 0 && r.SourceMode != fm.NoTranslation || len(server.source) > 0 && r.DestinationMode != fm.NoTranslation) {
			continue
		}
		for _, view := range []flow.Traffic{part.Original, part.Translated} {
			hit, _, err := e.Match(ctx, fw, r.Match, q, view)
			if err != nil {
				return false, err
			}
			if !hit.Empty() {
				return true, nil
			}
		}
	}
	return false, nil
}
