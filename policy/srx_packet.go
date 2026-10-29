package policy

import (
	"context"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
)

// SRX routes and evaluates policy after DNAT, including destination service
// translation. Reverse static NAT and SNAT are only considered after permit.
func (e Engine) srxPacket(ctx context.Context, fw *fm.Firewall, q PacketRequest) (PacketResult, error) {
	zone := fw.Zone(q.FromZone)
	if !fw.Complete() || zone == nil || len(zone.Record().Unsupported) > 0 {
		return PacketResult{Unknown: q.Traffic}, nil
	}
	limits := e.Limits.WithDefaults()
	budget := limits.MaxVisits
	steps, err := e.srxSteps(ctx, fw, q.Request, false, &budget)
	if err != nil {
		return PacketResult{}, err
	}
	pre, err := e.natChain(ctx, fw, q.Request, steps, &budget)
	if err != nil {
		return PacketResult{}, err
	}
	out := PacketResult{Complete: pre.Complete, Unknown: pre.Unknown}
	markUnknown := func(t flow.Traffic) error {
		if t.Empty() {
			return nil
		}
		var err error
		out.Unknown, err = out.Unknown.Union(t, limits.MaxRegions)
		out.Complete = false
		return err
	}
	for _, part := range natParts(pre) {
		if err := ctx.Err(); err != nil {
			return PacketResult{}, err
		}
		var destinations flow.Set
		for _, b := range part.Translated.Boxes() {
			s, _ := flow.NewSet(b.Destination)
			destinations = destinations.Union(s)
		}
		routes, err := e.ResolveRoutes(ctx, fw, q.VRF, destinations)
		if err != nil {
			return PacketResult{}, err
		}
		for _, route := range routes {
			var actual flow.Traffic
			for _, b := range part.Translated.Boxes() {
				v, err := restrictDestinations(b, route.Addresses, limits.MaxRegions)
				if err != nil {
					return PacketResult{}, err
				}
				actual, err = actual.Union(v, limits.MaxRegions)
				if err != nil {
					return PacketResult{}, err
				}
			}
			original, err := srxOriginal(fw, part, actual, limits.MaxRegions)
			if err != nil {
				return PacketResult{}, err
			}
			if !route.Known {
				if err := markUnknown(original); err != nil {
					return PacketResult{}, err
				}
				continue
			}
			request := q.Request
			request.Traffic, request.ToZone = actual, route.Zone.ID()
			evaluated, err := e.Query(ctx, fw, request)
			if err != nil {
				return PacketResult{}, err
			}
			unresolved, err := srxOriginal(fw, part, evaluated.Unknown, limits.MaxRegions)
			if err != nil {
				return PacketResult{}, err
			}
			if err := markUnknown(unresolved); err != nil {
				return PacketResult{}, err
			}
			// Keep rejected/unmatched evidence, with no hypothetical post-policy rewrite.
			rejected, err := evaluated.Denied.Union(evaluated.Unmatched, limits.MaxRegions)
			if err != nil {
				return PacketResult{}, err
			}
			if !rejected.Empty() {
				rel := part
				rel.Translated = rejected
				rel.Original, err = srxOriginal(fw, part, rejected, limits.MaxRegions)
				if err != nil {
					return PacketResult{}, err
				}
				request.Traffic = rejected
				denied, err := e.Query(ctx, fw, request)
				if err != nil {
					return PacketResult{}, err
				}
				if len(out.Paths) >= limits.MaxRegions {
					return PacketResult{}, ErrBudget
				}
				out.Paths = append(out.Paths, PacketPath{Original: rel.Original, FromZone: q.FromZone, ToZone: request.ToZone, NAT: rel, Policy: denied})
			}
			if evaluated.Allowed.Empty() {
				continue
			}
			request.Traffic = evaluated.Allowed
			post, err := e.srxPostNAT(ctx, fw, request, part, &budget)
			if err != nil {
				return PacketResult{}, err
			}
			if err := markUnknown(post.Unknown); err != nil {
				return PacketResult{}, err
			}
			for _, rel := range natParts(post) {
				// natParts' identity relation is already in wire coordinates. Reconstruct
				// the policy view from that original subset, never from post-SNAT values.
				view := rel.Original
				if len(part.Steps) == 1 {
					n, err := transform(fw, part.Steps[0])
					if err != nil {
						return PacketResult{}, err
					}
					view, _, _, err = n.apply(view, limits.MaxRegions)
					if err != nil {
						return PacketResult{}, err
					}
				}
				request.Traffic = view
				allowed, err := e.Query(ctx, fw, request)
				if err != nil {
					return PacketResult{}, err
				}
				if len(out.Paths) >= limits.MaxRegions {
					return PacketResult{}, ErrBudget
				}
				out.Paths = append(out.Paths, PacketPath{Original: rel.Original, FromZone: q.FromZone, ToZone: request.ToZone, NAT: rel, Policy: allowed})
			}
		}
	}
	return out, nil
}
