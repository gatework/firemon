package policy

import (
	"context"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
)

// ScreenOS uses original addresses and ports for security policy lookup. MIP/VIP
// supply the real destination's zone; policy NAT instead requires a route for
// its public address and must retain that zone after destination translation.
func (e Engine) netscreenPacket(ctx context.Context, fw *fm.Firewall, q PacketRequest) (PacketResult, error) {
	zone := fw.Zone(q.FromZone)
	if !fw.Complete() || zone == nil || q.Scope != "" {
		return PacketResult{Unknown: q.Traffic}, nil
	}
	if q.VRF == "" {
		q.VRF = zone.Scope()
	}
	if q.VRF != zone.Scope() {
		return PacketResult{Unknown: q.Traffic}, nil
	}
	limits := e.Limits.defaults()
	budget := limits.Rules
	out := PacketResult{Complete: true}
	unknown := func(t flow.Traffic) error {
		if t.Empty() {
			return nil
		}
		var err error
		out.Unknown, err = out.Unknown.Union(t, limits.Regions)
		out.Complete = false
		return err
	}
	type part struct {
		relation NATRelation
		vrf      string
	}
	var parts []part
	covered := flow.Traffic{}
	for _, entry := range fw.NATSequence() {
		if budget <= 0 {
			return PacketResult{}, ErrBudget
		}
		budget--
		if entry.Order.Section != "mip" && entry.Order.Section != "vip" {
			continue
		}
		step := NATStep{Kind: entry.Kind, ID: entry.ID}
		n, err := transform(fw, step)
		if err != nil {
			return PacketResult{}, err
		}
		if len(n.match.ToZones) != 1 {
			return PacketResult{}, ErrNAT
		}
		request := q.Request
		request.ToZone = n.match.ToZones[0]
		pre, err := e.natChain(ctx, fw, request, []NATStep{step}, &budget)
		if err != nil {
			return PacketResult{}, err
		}
		if err = unknown(pre.Unknown); err != nil {
			return PacketResult{}, err
		}
		for _, rel := range pre.Relations {
			overlap, err := covered.Intersection(rel.Original, limits.Regions)
			if err != nil {
				return PacketResult{}, err
			}
			if err = unknown(overlap); err != nil {
				return PacketResult{}, err
			}
			covered, err = covered.Union(rel.Original, limits.Regions)
			if err != nil {
				return PacketResult{}, err
			}
			if len(parts) >= limits.Regions {
				return PacketResult{}, ErrBudget
			}
			parts = append(parts, part{rel, fw.Zone(request.ToZone).Scope()})
		}
	}
	remaining, err := q.Traffic.Difference(covered, limits.Regions)
	if err != nil {
		return PacketResult{}, err
	}
	parts = append(parts, part{NATRelation{Original: remaining, Translated: remaining, Exact: true}, q.VRF})
	for _, piece := range parts {
		if err := ctx.Err(); err != nil {
			return PacketResult{}, err
		}
		original, err := piece.relation.Original.Difference(out.Unknown, limits.Regions)
		if err != nil {
			return PacketResult{}, err
		}
		if original.Empty() {
			continue
		}
		view := original
		if len(piece.relation.Steps) == 1 {
			n, err := transform(fw, piece.relation.Steps[0])
			if err != nil {
				return PacketResult{}, err
			}
			view, _, _, err = n.apply(original, limits.Regions)
			if err != nil {
				return PacketResult{}, err
			}
		}
		var destinations flow.Set
		for _, b := range view.Boxes() {
			set, _ := flow.NewSet(b.Destination)
			destinations = destinations.Union(set)
		}
		routes, err := e.ResolveRoutes(ctx, fw, piece.vrf, destinations)
		if err != nil {
			return PacketResult{}, err
		}
		for _, route := range routes {
			var translated flow.Traffic
			for _, b := range view.Boxes() {
				t, err := restrictDestinations(b, route.Addresses, limits.Regions)
				if err != nil {
					return PacketResult{}, err
				}
				translated, err = translated.Union(t, limits.Regions)
				if err != nil {
					return PacketResult{}, err
				}
			}
			rel := piece.relation
			rel.Original = original
			rel.Translated = view
			wire, err := srxOriginal(fw, rel, translated, limits.Regions)
			if err != nil {
				return PacketResult{}, err
			}
			if !route.Known {
				if err = unknown(wire); err != nil {
					return PacketResult{}, err
				}
				continue
			}
			request := q.Request
			request.Traffic, request.ToZone, request.EgressInterface = wire, route.Zone.ID(), route.Interface.ID()
			nat, err := e.netscreenNAT(ctx, fw, request, &budget)
			if err != nil {
				return PacketResult{}, err
			}
			if err = unknown(nat.Unknown); err != nil {
				return PacketResult{}, err
			}
			for _, n := range natParts(nat) {
				request.Traffic = n.Original
				if len(fw.Rules()) > budget {
					return PacketResult{}, ErrBudget
				}
				budget -= len(fw.Rules())
				evaluated, err := e.Query(ctx, fw, request)
				if err != nil {
					return PacketResult{}, err
				}
				if err = unknown(evaluated.Unknown); err != nil {
					return PacketResult{}, err
				}
				valid, err := e.netscreenDestination(ctx, fw, n, route, limits.Regions)
				if err != nil {
					return PacketResult{}, err
				}
				if !evaluated.Allowed.Empty() && !valid {
					if err = unknown(n.Original); err != nil {
						return PacketResult{}, err
					}
					continue
				}
				if len(out.Paths) >= limits.Regions {
					return PacketResult{}, ErrBudget
				}
				out.Paths = append(out.Paths, PacketPath{Original: n.Original, FromZone: request.FromZone, ToZone: request.ToZone, NAT: n, Policy: evaluated})
			}
		}
	}
	return out, nil
}

func (e Engine) netscreenDestination(ctx context.Context, fw *fm.Firewall, n NATRelation, before RoutePath, limit int) (bool, error) {
	var destinations flow.Set
	for _, box := range n.Translated.Boxes() {
		s, _ := flow.NewSet(box.Destination)
		destinations = destinations.Union(s)
	}
	routes, err := e.ResolveRoutes(ctx, fw, before.Zone.Scope(), destinations)
	if err != nil {
		return false, err
	}
	for _, r := range routes {
		if !r.Known || r.Zone != before.Zone {
			return false, nil
		}
		for _, step := range n.Steps {
			if step.Kind != fm.DynamicNATObject {
				continue
			}
			nat := fw.DynamicNAT(step.ID)
			if pool := nat.SourcePool(); pool != nil && pool.Interface() != r.Interface {
				return false, nil
			}
			if nat.Record().SourceMode == fm.InterfaceIP && nat.Interface() != r.Interface {
				return false, nil
			}
		}
	}
	return len(routes) > 0, ctx.Err()
}
