package policy

import (
	"context"
	"strings"

	fm "github.com/gatework/firemon"
)

// hillstoneNAT selects DNAT and SNAT independently on the original packet, with
// BNAT taking priority in each direction. The two selections are joined only on
// their original traffic intersection, so distinct request pairs remain distinct.
func (e Engine) hillstoneNAT(ctx context.Context, fw *fm.Firewall, q Request, budget *int) (NATResult, error) {
	entries := fw.NATSequence()
	limits := e.Limits.defaults()
	if len(entries) > limits.Rules {
		return NATResult{}, ErrBudget
	}
	var source, destination, fixedSource, fixedDestination []NATStep
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return NATResult{}, err
		}
		if entry.Scope != q.Scope {
			continue
		}
		step := NATStep{Kind: entry.Kind, ID: entry.ID}
		switch entry.Kind {
		case fm.StaticNATObject:
			r := fw.StaticNAT(entry.ID).Record()
			if r.Disabled {
				continue
			}
			if r.Bidirectional {
				if len(r.Destination) > 0 || len(r.Source) == 0 {
					return NATResult{}, ErrNAT
				}
				fixedSource = append(fixedSource, step)
				step.Reverse = true
				fixedDestination = append(fixedDestination, step)
			} else if len(r.Source) > 0 && len(r.Destination) == 0 {
				source = append(source, step)
			} else if len(r.Destination) > 0 && len(r.Source) == 0 {
				destination = append(destination, step)
			} else {
				return NATResult{}, ErrNAT
			}
		case fm.DynamicNATObject:
			r := fw.DynamicNAT(entry.ID).Record()
			if r.Disabled {
				continue
			}
			// Section preserves no-NAT's native chain; its modes alone cannot
			// distinguish a source exemption from a destination exemption.
			switch r.Order.Section {
			case "dnat":
				destination = append(destination, step)
			case "snat":
				source = append(source, step)
			case "":
				if r.SourceMode != fm.NoTranslation && r.DestinationMode != fm.NoTranslation {
					return NATResult{}, ErrNAT
				}
				if r.DestinationMode != fm.NoTranslation {
					destination = append(destination, step)
				} else {
					source = append(source, step)
				}
			default:
				return NATResult{}, ErrNAT
			}
		default:
			return NATResult{}, ErrNAT
		}
	}
	// Older StoneOS releases differ in which destination address SNAT matches.
	// Only the documented 5.5R8 delayed-rewrite pipeline is currently established
	// for a mixed regular chain. Unconditional BNAT inverses do not depend on it.
	if (len(source) > 0 && len(destination)+len(fixedDestination) > 0 || len(destination) > 0 && len(fixedSource) > 0) && !stoneOS55R8(fw.Metadata().Software) {
		return NATResult{}, ErrNAT
	}
	source = append(fixedSource, source...)
	destination = append(fixedDestination, destination...)
	dnat, err := e.natChain(ctx, fw, q, destination, budget)
	if err != nil {
		return NATResult{}, err
	}
	out := NATResult{Complete: dnat.Complete, Unknown: dnat.Unknown}
	parts := dnat.Relations
	if !dnat.Unmatched.Empty() {
		parts = append(parts, NATRelation{Original: dnat.Unmatched, Translated: dnat.Unmatched, Exact: true})
	}
	for _, d := range parts {
		request := q
		request.Traffic = d.Original
		snat, err := e.natChain(ctx, fw, request, source, budget)
		if err != nil {
			return NATResult{}, err
		}
		out.Unknown, err = out.Unknown.Union(snat.Unknown, limits.Regions)
		if err != nil {
			return NATResult{}, err
		}
		out.Complete = out.Complete && snat.Complete
		pieces := snat.Relations
		if !snat.Unmatched.Empty() {
			pieces = append(pieces, NATRelation{Original: snat.Unmatched, Translated: snat.Unmatched, Exact: true})
		}
		for _, s := range pieces {
			steps := append(append([]NATStep(nil), d.Steps...), s.Steps...)
			if len(steps) == 0 {
				out.Unmatched, err = out.Unmatched.Union(s.Original, limits.Regions)
				if err != nil {
					return NATResult{}, err
				}
				continue
			}
			r := NATRelation{Steps: steps, Original: s.Original, Translated: s.Original, Exact: true}
			if len(steps) == 1 {
				r.Kind, r.ID = steps[0].Kind, steps[0].ID
			}
			for _, step := range steps {
				n, err := transform(fw, step)
				if err != nil {
					return NATResult{}, err
				}
				var exact, possible bool
				r.Translated, exact, possible, err = n.apply(r.Translated, limits.Regions)
				if err != nil {
					return NATResult{}, err
				}
				r.Exact = r.Exact && exact
				r.PossibleAllocation = r.PossibleAllocation || possible
			}
			if len(out.Relations) >= limits.Regions {
				return NATResult{}, ErrBudget
			}
			out.Relations = append(out.Relations, r)
		}
	}
	return out, nil
}

func stoneOS55R8(version string) bool {
	version = strings.TrimSpace(strings.TrimPrefix(version, "StoneOS "))
	return version == "5.5R8" || strings.HasPrefix(version, "5.5R8P")
}
