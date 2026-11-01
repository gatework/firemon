package policy

import (
	"context"
	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
)

// hillstonePacket is limited to the StoneOS 5.5R8 delayed-rewrite model.
// DNAT marking precedes route lookup. Policy and SNAT predicates retain original
// coordinates; the route supplies the post-DNAT destination zone and egress.
// Original policy coordinates are a documented-model inference, corroborated by
// the native Perl Searcher; this is not a claim of real-device acceptance.
func (e Engine) hillstonePacket(ctx context.Context, fw *fm.Firewall, q PacketRequest) (PacketResult, error) {
	if !stoneOS55R8(fw.Metadata().Software) {
		return PacketResult{}, ErrNAT
	}
	zone := fw.Zone(q.FromZone)
	if !fw.Complete() || zone == nil || zone.HasUnsupported() {
		return PacketResult{Unknown: q.Traffic}, nil
	}
	if q.VRF == "" {
		q.VRF = zone.Scope()
	}
	if q.Scope != zone.Scope() || q.VRF != zone.Scope() {
		return PacketResult{Unknown: q.Traffic}, nil
	}
	limits := e.Limits.WithDefaults()
	budget := limits.MaxVisits
	source, destination, err := e.hillstoneSteps(ctx, fw, q.Request)
	if err != nil {
		return PacketResult{}, err
	}
	// The routed chain retains first-match unknown consumption and tests each
	// destination candidate against its own post-translation route.
	pre, err := e.huaweiRoutedChain(ctx, fw, q.Request, q.VRF, destination, &budget)
	if err != nil {
		return PacketResult{}, err
	}
	out := PacketResult{Complete: pre.Complete, Unknown: pre.Unknown}
	unknown := func(t flow.Traffic) error {
		var err error
		out.Unknown, err = out.Unknown.Union(t, limits.MaxRegions)
		out.Complete = out.Unknown.Empty()
		return err
	}
	for _, part := range natParts(pre) {
		n := natTransform{known: true}
		if len(part.Steps) == 1 {
			n, err = transform(fw, part.Steps[0])
			if err != nil {
				return PacketResult{}, err
			}
		} else if len(part.Steps) > 1 {
			return PacketResult{}, ErrNAT
		}
		routes, err := e.routeDestinations(ctx, fw, q.VRF, part.Translated)
		if err != nil {
			return PacketResult{}, err
		}
		for _, route := range routes {
			if err := ctx.Err(); err != nil {
				return PacketResult{}, err
			}
			real, err := routedTraffic(part.Translated, route, limits.MaxRegions)
			if err != nil {
				return PacketResult{}, err
			}
			wire, err := destinationPreimage(n, part.Original, real, limits.MaxRegions)
			if err != nil {
				return PacketResult{}, err
			}
			if !route.Known || route.Interface.Scope() != q.VRF {
				if err := unknown(wire); err != nil {
					return PacketResult{}, err
				}
				continue
			}
			request := q.Request
			request.Traffic, request.ToZone, request.EgressInterface = wire, route.Zone.ID(), route.Interface.ID()
			if fw.RuleCount() > budget {
				return PacketResult{}, ErrBudget
			}
			budget -= fw.RuleCount()
			verdict, err := e.Query(ctx, fw, request)
			if err != nil {
				return PacketResult{}, err
			}
			if err := unknown(verdict.Unknown); err != nil {
				return PacketResult{}, err
			}
			rejected, err := verdict.Denied.Union(verdict.Unmatched, limits.MaxRegions)
			if err != nil {
				return PacketResult{}, err
			}
			for _, piece := range []struct {
				traffic flow.Traffic
				permit  bool
			}{{rejected, false}, {verdict.Allowed, true}} {
				if piece.traffic.Empty() {
					continue
				}
				request.Traffic = piece.traffic
				selected := NATResult{Complete: true, Unmatched: piece.traffic}
				if piece.permit {
					selected, err = e.natChain(ctx, fw, request, source, &budget)
					if err != nil {
						return PacketResult{}, err
					}
					if err := unknown(selected.Unknown); err != nil {
						return PacketResult{}, err
					}
				}
				for _, snat := range natParts(selected) {
					relation := NATRelation{Original: snat.Original, Translated: snat.Original, Exact: true}
					real, _, _, err := n.apply(snat.Original, limits.MaxRegions)
					if err != nil {
						return PacketResult{}, err
					}
					if piece.permit {
						relation.Steps = append(append([]NATStep(nil), part.Steps...), snat.Steps...)
						if len(relation.Steps) == 1 {
							relation.Kind, relation.ID = relation.Steps[0].Kind, relation.Steps[0].ID
						}
						for _, step := range relation.Steps {
							tr, err := transform(fw, step)
							if err != nil {
								return PacketResult{}, err
							}
							var exact, possible bool
							relation.Translated, exact, possible, err = tr.apply(relation.Translated, limits.MaxRegions)
							if err != nil {
								return PacketResult{}, err
							}
							relation.Exact = relation.Exact && exact
							relation.PossibleAllocation = relation.PossibleAllocation || possible
						}
					}
					request.Traffic = snat.Original
					if fw.RuleCount() > budget {
						return PacketResult{}, ErrBudget
					}
					budget -= fw.RuleCount()
					policy, err := e.Query(ctx, fw, request)
					if err != nil {
						return PacketResult{}, err
					}
					if len(out.Paths) >= limits.MaxRegions {
						return PacketResult{}, ErrBudget
					}
					out.Paths = append(out.Paths, PacketPath{Original: snat.Original, Real: real, FromZone: q.FromZone, ToZone: request.ToZone, NAT: relation, Policy: policy, NativeRequests: []Request{request}})
				}
			}
		}
	}
	out.Complete = out.Unknown.Empty()
	return out, nil
}
