package policy

import (
	"context"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
)

// ScreenOS policy NAT belongs to the first selected permit policy. A preceding
// deny, ordinary permit or unresolved policy consumes traffic before NAT lookup.
func (e Engine) netscreenNAT(ctx context.Context, fw *fm.Firewall, q Request, budget *int) (NATResult, error) {
	if q.Scope != "" {
		return NATResult{}, ErrNAT
	}
	entries := fw.NATSequence()
	if len(entries) > *budget {
		return NATResult{}, ErrBudget
	}
	*budget -= len(entries)
	var interfaces []NATStep
	owned := make(map[fm.ID]NATStep)
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return NATResult{}, err
		}
		step := NATStep{Kind: entry.Kind, ID: entry.ID}
		switch entry.Order.Section {
		case "mip":
			if entry.Kind != fm.StaticNATObject {
				return NATResult{}, ErrNAT
			}
			interfaces = append(interfaces, step)
			step.Reverse = true
			interfaces = append(interfaces, step)
		case "vip":
			if entry.Kind != fm.DynamicNATObject {
				return NATResult{}, ErrNAT
			}
			interfaces = append(interfaces, step)
		case "policy":
			if entry.Kind != fm.DynamicNATObject {
				return NATResult{}, ErrNAT
			}
			n := fw.DynamicNAT(entry.ID)
			id := n.Record().Rule
			if id == "" || n.Rule() == nil || owned[id].ID != "" {
				return NATResult{}, ErrNAT
			}
			owned[id] = step
		default:
			return NATResult{}, ErrNAT
		}
	}
	rules := len(fw.Rules())
	if rules > *budget {
		return NATResult{}, ErrBudget
	}
	*budget -= rules
	evaluated, err := e.Query(ctx, fw, q)
	if err != nil {
		return NATResult{}, err
	}
	out := NATResult{Complete: evaluated.Complete, Unknown: evaluated.Unknown}
	out.Unmatched, err = evaluated.Denied.Union(evaluated.Unmatched, e.Limits.WithDefaults().MaxRegions)
	if err != nil {
		return NATResult{}, err
	}
	for _, decision := range evaluated.Decisions {
		if !decision.Known || decision.Action != fm.Permit {
			continue
		}
		request := q
		request.Traffic = decision.Traffic
		// MIP and VIP take priority over policy translation. Overlapping interface
		// mappings need native composition evidence and are deliberately unknown.
		shared := flow.Traffic{}
		owner := fw.DynamicNAT(owned[decision.Rule].ID)
		for _, step := range interfaces {
			if *budget <= 0 {
				return NATResult{}, ErrBudget
			}
			*budget--
			part, err := e.natChain(ctx, fw, request, []NATStep{step}, budget)
			if err != nil {
				return NATResult{}, err
			}
			for _, n := range part.Relations {
				// Interface DNAT combined with policy SNAT (or the reverse) needs
				// direction-wise composition. Retain uncertainty until established;
				// selecting an interface mapping must not erase the other direction.
				if owner != nil && ((!step.Reverse && owner.Record().SourceMode != fm.NoTranslation) || (step.Reverse && owner.Record().DestinationMode != fm.NoTranslation)) {
					out.Unknown, err = out.Unknown.Union(n.Original, e.Limits.WithDefaults().MaxRegions)
					if err != nil {
						return NATResult{}, err
					}
					out.Complete = false
				}
				overlap, err := shared.Intersection(n.Original, e.Limits.WithDefaults().MaxRegions)
				if err != nil {
					return NATResult{}, err
				}
				if !overlap.Empty() {
					out.Unknown, err = out.Unknown.Union(overlap, e.Limits.WithDefaults().MaxRegions)
					if err != nil {
						return NATResult{}, err
					}
					out.Complete = false
				}
				shared, err = shared.Union(n.Original, e.Limits.WithDefaults().MaxRegions)
				if err != nil {
					return NATResult{}, err
				}
			}
		}
		request.Traffic, err = request.Traffic.Difference(out.Unknown, e.Limits.WithDefaults().MaxRegions)
		if err != nil {
			return NATResult{}, err
		}
		steps := append([]NATStep{}, interfaces...)
		if step := owned[decision.Rule]; step.ID != "" {
			steps = append(steps, step)
		}
		part, err := e.natChain(ctx, fw, request, steps, budget)
		if err != nil {
			return NATResult{}, err
		}
		if len(out.Relations)+len(part.Relations) > e.Limits.WithDefaults().MaxRegions {
			return NATResult{}, ErrBudget
		}
		out.Relations = append(out.Relations, part.Relations...)
		out.Unknown, err = out.Unknown.Union(part.Unknown, e.Limits.WithDefaults().MaxRegions)
		if err != nil {
			return NATResult{}, err
		}
		out.Unmatched, err = out.Unmatched.Union(part.Unmatched, e.Limits.WithDefaults().MaxRegions)
		if err != nil {
			return NATResult{}, err
		}
		out.Complete = out.Complete && part.Complete
	}
	return out, nil
}
