package policy

import (
	"context"
	"errors"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
)

// AliasView distinguishes pre-source-NAT real coordinates from final translation.
type AliasView string

const (
	RealView       AliasView = "real"
	TranslatedView AliasView = "translated"
)

// View returns only established coordinates. A possible allocation cannot prove
// a final translated alias, but does not invalidate independently known Real.
func (p PacketPath) View(view AliasView) (flow.Traffic, bool) {
	switch view {
	case RealView:
		return p.Real, !p.Real.Empty()
	case TranslatedView:
		return p.NAT.Translated, p.NAT.Exact && !p.NAT.PossibleAllocation && !p.NAT.Translated.Empty()
	default:
		return flow.Traffic{}, false
	}
}

type AliasCandidate struct {
	Business, Wire flow.Traffic
	Steps          []NATStep
}
type AliasResult struct {
	Candidates                    []AliasCandidate
	Ambiguous, Unknown, Unmatched flow.Traffic
}
type provenAlias struct {
	candidate AliasCandidate
	inverse   natTransform
}

// DiscoverStaticAliases enumerates reversible static mappings only, then queries
// the real ordered packet pipeline. Catalog order never chooses between two
// valid wire aliases. Unknown, ambiguous and unmatched business fractions remain
// explicit; no source or ingress zone is derived from reverse routing.
func (e Engine) DiscoverStaticAliases(ctx context.Context, fw *fm.Firewall, q PacketRequest, view AliasView) (AliasResult, error) {
	if err := ctx.Err(); err != nil {
		return AliasResult{}, err
	}
	if fw == nil || q.FromZone == "" || (view != RealView && view != TranslatedView) {
		return AliasResult{}, ErrInvalid
	}
	if err := e.Limits.checkRegions(q.Traffic.RegionCount()); err != nil {
		return AliasResult{}, err
	}
	if !fw.Complete() {
		return AliasResult{Unknown: q.Traffic}, nil
	}
	limits := e.Limits.WithDefaults()
	budget := limits.MaxVisits
	if err := chargeVisits(ctx, &budget, fw.RecordCount(), q.Traffic.RegionCount()); err != nil {
		return AliasResult{}, err
	}
	var proven []provenAlias
	candidateRegions := 0
	out := AliasResult{}
	for _, entry := range fw.NATSequence() {
		if err := chargeVisits(ctx, &budget, 1); err != nil {
			return AliasResult{}, err
		}
		if entry.Scope != q.Scope {
			continue
		}
		steps := []NATStep{{Kind: entry.Kind, ID: entry.ID}}
		if entry.Kind == fm.StaticNATObject && fw.StaticNAT(entry.ID).Record().Bidirectional {
			steps = append(steps, NATStep{Kind: entry.Kind, ID: entry.ID, Reverse: true})
		}
		for _, step := range steps {
			forward, err := transform(fw, step)
			if err != nil {
				return AliasResult{}, err
			}
			if forward.disabled {
				continue
			}
			// Real coordinates exclude all source translations; the destination part
			// remains the concrete native mapping. Final allocation is never inverted.
			if view == RealView {
				forward.source = nil
				forward.sourcePorts = nil
			}
			forward, err = e.aliasGeometry(ctx, fw, forward, &budget)
			if err != nil {
				return AliasResult{}, err
			}
			if len(forward.source)+len(forward.destination)+len(forward.sourcePorts)+len(forward.destinationPorts) == 0 {
				continue
			}
			inverses, err := staticInverses(ctx, forward, limits.MaxCombinations, &budget)
			if err != nil {
				return AliasResult{}, err
			}
			for _, inverse := range inverses {
				business, err := restrictMappings(q.Traffic, inverse.source, true, limits.MaxRegions)
				if err != nil {
					return AliasResult{}, err
				}
				business, err = restrictMappings(business, inverse.destination, false, limits.MaxRegions)
				if err != nil {
					return AliasResult{}, err
				}
				for _, axis := range []struct {
					mappings []fm.PortMapping
					source   bool
				}{{inverse.sourcePorts, true}, {inverse.destinationPorts, false}} {
					work := packetProofBudget{limits: limits, remaining: budget}
					if err := work.mapping(ctx, business, len(axis.mappings)); err != nil {
						return AliasResult{}, err
					}
					budget = work.remaining
					business, err = restrictPortMappings(business, axis.mappings, axis.source, limits.MaxRegions)
					if err != nil {
						return AliasResult{}, err
					}
				}
				if business.Empty() {
					continue
				}
				if !forward.known || !inverse.known {
					out.Unknown, err = out.Unknown.Union(business, limits.MaxRegions)
					if err != nil {
						return AliasResult{}, err
					}
					continue
				}
				wire, _, _, err := inverse.apply(business, limits.MaxRegions)
				if err != nil {
					return AliasResult{}, err
				}
				if err := chargeVisits(ctx, &budget, fw.RecordCount(), wire.RegionCount()); err != nil {
					return AliasResult{}, err
				}
				packet := q
				packet.Traffic = wire
				result, err := e.QueryPacket(ctx, fw, packet)
				if err != nil {
					if errors.Is(err, ErrBudget) || errors.Is(err, flow.ErrBudget) || ctx.Err() != nil {
						return AliasResult{}, err
					}
					out.Unknown, err = out.Unknown.Union(business, limits.MaxRegions)
					if err != nil {
						return AliasResult{}, err
					}
					continue
				}
				// Unknown wire fractions are mapped through this candidate's reversible
				// geometry solely to report unresolved business fractions, never success.
				geometry := forward
				geometry.dynamic = nil
				if !result.Unknown.Empty() {
					uncertain, _, _, err := geometry.apply(result.Unknown, limits.MaxRegions)
					if err != nil {
						return AliasResult{}, err
					}
					uncertain, err = uncertain.Intersection(business, limits.MaxRegions)
					if err != nil {
						return AliasResult{}, err
					}
					out.Unknown, err = out.Unknown.Union(uncertain, limits.MaxRegions)
					if err != nil {
						return AliasResult{}, err
					}
				}
				for _, path := range result.Paths {
					if err := chargeVisits(ctx, &budget, 1); err != nil {
						return AliasResult{}, err
					}
					actual, known := path.View(view)
					if !known {
						uncertain, _, _, err := geometry.apply(path.Original, limits.MaxRegions)
						if err != nil {
							return AliasResult{}, err
						}
						uncertain, err = uncertain.Intersection(business, limits.MaxRegions)
						if err != nil {
							return AliasResult{}, err
						}
						out.Unknown, err = out.Unknown.Union(uncertain, limits.MaxRegions)
						if err != nil {
							return AliasResult{}, err
						}
						continue
					}
					same, err := path.Original.Equal(path.NAT.Original, limits.MaxRegions)
					if err != nil {
						return AliasResult{}, err
					}
					if !same {
						continue
					}
					wanted, err := actual.Intersection(business, limits.MaxRegions)
					if err != nil {
						return AliasResult{}, err
					}
					if wanted.Empty() {
						continue
					}
					candidateWire, _, _, err := inverse.apply(wanted, limits.MaxRegions)
					if err != nil {
						return AliasResult{}, err
					}
					contained, err := path.Original.Contains(candidateWire, limits.MaxRegions)
					if err != nil {
						return AliasResult{}, err
					}
					if !contained {
						continue
					}
					// Different native maps must not accidentally validate a projected overlap.
					observed, _, _, err := geometry.apply(candidateWire, limits.MaxRegions)
					if err != nil {
						return AliasResult{}, err
					}
					same, err = observed.Equal(wanted, limits.MaxRegions)
					if err != nil {
						return AliasResult{}, err
					}
					if !same {
						continue
					}
					// Re-query the narrowed wire candidate: projected coordinate overlap
					// alone cannot prove the correspondence when another native rule
					// shadows this catalog mapping with a different offset.
					if err := chargeVisits(ctx, &budget, fw.RecordCount(), candidateWire.RegionCount()); err != nil {
						return AliasResult{}, err
					}
					check := q
					check.Traffic = candidateWire
					valid, err := e.aliasViewMatches(ctx, fw, check, view, wanted)
					if err != nil {
						return AliasResult{}, err
					}
					if !valid {
						continue
					}
					duplicate := false
					for _, prior := range proven {
						if err := chargeVisits(ctx, &budget, 1); err != nil {
							return AliasResult{}, err
						}
						a, err := prior.candidate.Wire.Equal(candidateWire, limits.MaxRegions)
						if err != nil {
							return AliasResult{}, err
						}
						b, err := prior.candidate.Business.Equal(wanted, limits.MaxRegions)
						if err != nil {
							return AliasResult{}, err
						}
						if a && b {
							duplicate = true
							break
						}
					}
					if duplicate {
						continue
					}
					candidateRegions += wanted.RegionCount() + candidateWire.RegionCount()
					if candidateRegions > limits.MaxRegions || len(proven) >= limits.MaxCombinations {
						return AliasResult{}, ErrBudget
					}
					proven = append(proven, provenAlias{candidate: AliasCandidate{Business: wanted, Wire: candidateWire, Steps: append([]NATStep(nil), path.NAT.Steps...)}, inverse: inverse})
				}
			}
		}
	}
	// Compare all candidate business fractions before exposing any unique work.
	for i, a := range proven {
		for _, b := range proven[i+1:] {
			if err := chargeVisits(ctx, &budget, 1); err != nil {
				return AliasResult{}, err
			}
			overlap, err := a.candidate.Business.Intersection(b.candidate.Business, limits.MaxRegions)
			if err != nil {
				return AliasResult{}, err
			}
			// Equal wire aliases split by native routing are not an ownership ambiguity.
			if overlap.Empty() {
				continue
			}
			aw, _, _, err := a.inverse.apply(overlap, limits.MaxRegions)
			if err != nil {
				return AliasResult{}, err
			}
			bw, _, _, err := b.inverse.apply(overlap, limits.MaxRegions)
			if err != nil {
				return AliasResult{}, err
			}
			same, err := aw.Equal(bw, limits.MaxRegions)
			if err != nil {
				return AliasResult{}, err
			}
			if same {
				continue
			}
			out.Ambiguous, err = out.Ambiguous.Union(overlap, limits.MaxRegions)
			if err != nil {
				return AliasResult{}, err
			}
		}
	}
	excluded, err := out.Ambiguous.Union(out.Unknown, limits.MaxRegions)
	if err != nil {
		return AliasResult{}, err
	}
	accounted := excluded
	emittedRegions := 0
	for _, p := range proven {
		if err := chargeVisits(ctx, &budget, 1); err != nil {
			return AliasResult{}, err
		}
		unique, err := p.candidate.Business.Difference(excluded, limits.MaxRegions)
		if err != nil {
			return AliasResult{}, err
		}
		if unique.Empty() {
			continue
		}
		wire, _, _, err := p.inverse.apply(unique, limits.MaxRegions)
		if err != nil {
			return AliasResult{}, err
		}
		accounted, err = accounted.Union(unique, limits.MaxRegions)
		if err != nil {
			return AliasResult{}, err
		}
		emittedRegions += unique.RegionCount() + wire.RegionCount()
		if emittedRegions > limits.MaxRegions {
			return AliasResult{}, ErrBudget
		}
		out.Candidates = append(out.Candidates, AliasCandidate{Business: unique, Wire: wire, Steps: p.candidate.Steps})
	}
	out.Unmatched, err = q.Traffic.Difference(accounted, limits.MaxRegions)
	return out, err
}

// Each mapping is a separate inverse choice, even within one NAT object.
// Combining inverse axes into one Traffic would hide multiple wire aliases.
func staticInverses(ctx context.Context, n natTransform, limit int, budget *int) ([]natTransform, error) {
	sourcePorts, sourceKnown, err := aliasPortInverse(ctx, n.sourcePorts, budget)
	if err != nil {
		return nil, err
	}
	destinationPorts, destinationKnown, err := aliasPortInverse(ctx, n.destinationPorts, budget)
	if err != nil {
		return nil, err
	}
	sources, destinations := n.source, n.destination
	if len(sources) == 0 {
		sources = []fm.Mapping{{}}
	}
	if len(destinations) == 0 {
		destinations = []fm.Mapping{{}}
	}
	if len(sources) > limit/len(destinations) {
		return nil, ErrBudget
	}
	reverse := func(m fm.Mapping) ([]fm.Mapping, bool) {
		if !m.Original.Valid() {
			return nil, true
		}
		mode := m.Mode
		if mode == fm.Constant && m.Original.First == m.Original.Last && m.Translated.First == m.Translated.Last {
			mode = fm.Offset
		}
		return []fm.Mapping{{Original: m.Translated, Translated: m.Original, Mode: mode}}, mode == fm.Offset || mode == fm.Identity
	}
	var out []natTransform
	for _, source := range sources {
		for _, destination := range destinations {
			if err := chargeVisits(ctx, budget, 1); err != nil {
				return nil, err
			}
			src, s := reverse(source)
			dst, d := reverse(destination)
			out = append(out, natTransform{known: s && d && sourceKnown && destinationKnown, source: src, destination: dst, sourcePorts: sourcePorts, destinationPorts: destinationPorts})
		}
	}
	return out, nil
}

// Ports must identify one original service. A many-to-one or overlapping
// inverse cannot establish a unique wire alias without an observed session.
func aliasPortInverse(ctx context.Context, mappings []fm.PortMapping, budget *int) ([]fm.PortMapping, bool, error) {
	count := len(mappings)
	if count != 0 && count > *budget/count {
		return nil, false, ErrBudget
	}
	if err := chargeVisits(ctx, budget, count, count*count); err != nil {
		return nil, false, err
	}
	inverse, known := inversePorts(mappings)
	for i, a := range inverse {
		for _, b := range inverse[:i] {
			if max(a.Original.Low, b.Original.Low) <= min(a.Original.High, b.Original.High) {
				known = false
			}
		}
	}
	return inverse, known, nil
}

func restrictPortMappings(input flow.Traffic, mappings []fm.PortMapping, source bool, limit int) (flow.Traffic, error) {
	if len(mappings) == 0 {
		return input, nil
	}
	var out flow.Traffic
	for _, box := range input.Regions() {
		axis := box.DestinationPort
		if source {
			axis = box.SourcePort
		}
		for _, m := range mappings {
			part := flow.Interval{Low: max(axis.Low, m.Original.Low), High: min(axis.High, m.Original.High)}
			if part.Low > part.High {
				continue
			}
			piece := box
			if source {
				piece.SourcePort = part
			} else {
				piece.DestinationPort = part
			}
			t, err := flow.NewTraffic(limit, piece)
			if err != nil {
				return flow.Traffic{}, err
			}
			out, err = out.Union(t, limit)
			if err != nil {
				return flow.Traffic{}, err
			}
		}
	}
	return out, nil
}

func (e Engine) aliasViewMatches(ctx context.Context, fw *fm.Firewall, q PacketRequest, view AliasView, wanted flow.Traffic) (bool, error) {
	result, err := e.QueryPacket(ctx, fw, q)
	if err != nil {
		if errors.Is(err, ErrBudget) || errors.Is(err, flow.ErrBudget) || ctx.Err() != nil {
			return false, err
		}
		return false, nil
	}
	if !result.Unknown.Empty() {
		return false, nil
	}
	limit := e.Limits.WithDefaults().MaxRegions
	var wire, actual flow.Traffic
	for _, path := range result.Paths {
		part, known := path.View(view)
		if !known {
			return false, nil
		}
		same, err := path.Original.Equal(path.NAT.Original, limit)
		if err != nil || !same {
			return false, err
		}
		wire, err = wire.Union(path.Original, limit)
		if err != nil {
			return false, err
		}
		actual, err = actual.Union(part, limit)
		if err != nil {
			return false, err
		}
	}
	same, err := wire.Equal(q.Traffic, limit)
	if err != nil || !same {
		return false, err
	}
	return actual.Equal(wanted, limit)
}
