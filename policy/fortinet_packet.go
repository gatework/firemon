package policy

import (
	"context"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
)

func (e Engine) fortinetPacket(ctx context.Context, fw *fm.Firewall, q PacketRequest) (PacketResult, error) {
	if err := ctx.Err(); err != nil {
		return PacketResult{}, err
	}
	zone := fw.Zone(q.FromZone)
	if !fw.Complete() || zone == nil || len(zone.Record().Unsupported) > 0 || zone.Scope() != q.Scope {
		return PacketResult{Unknown: q.Traffic}, nil
	}
	if q.VRF == "" {
		q.VRF = q.Scope
	}
	if q.VRF != q.Scope {
		return PacketResult{Unknown: q.Traffic}, nil
	}
	limits := e.Limits.WithDefaults()
	budget := limits.MaxVisits
	local, err := fortinetLocalAddresses(ctx, fw, q.Scope, &budget)
	if err != nil {
		return PacketResult{}, err
	}
	pre, err := e.fortinetDestinations(ctx, fw, q.Request, &budget)
	if err != nil {
		return PacketResult{}, err
	}
	out := PacketResult{Complete: pre.Complete, Unknown: pre.Unknown}
	markUnknown := func(v flow.Traffic) error {
		if v.Empty() {
			return nil
		}
		var err error
		out.Unknown, err = out.Unknown.Union(v, limits.MaxRegions)
		out.Complete = false
		return err
	}
	for _, view := range natParts(pre) {
		var localTraffic flow.Traffic
		for _, box := range view.Translated.Regions() {
			part, err := restrictDestinations(box, local, limits.MaxRegions)
			if err != nil {
				return PacketResult{}, err
			}
			localTraffic, err = localTraffic.Union(part, limits.MaxRegions)
			if err != nil {
				return PacketResult{}, err
			}
		}
		if !localTraffic.Empty() {
			unknown, err := srxOriginal(fw, view, localTraffic, limits.MaxRegions)
			if err != nil {
				return PacketResult{}, err
			}
			if err := markUnknown(unknown); err != nil {
				return PacketResult{}, err
			}
			view.Translated, err = view.Translated.Difference(localTraffic, limits.MaxRegions)
			if err != nil {
				return PacketResult{}, err
			}
			view.Original, err = view.Original.Difference(unknown, limits.MaxRegions)
			if err != nil {
				return PacketResult{}, err
			}
			if view.Original.Empty() {
				continue
			}
		}
		var destinations flow.AddressSet
		for _, box := range view.Translated.Regions() {
			set, _ := flow.NewAddressSet(box.Destination)
			destinations = destinations.Union(set)
		}
		routes, err := e.ResolveRoutes(ctx, fw, q.VRF, destinations)
		if err != nil {
			return PacketResult{}, err
		}
		for _, route := range routes {
			if err := ctx.Err(); err != nil {
				return PacketResult{}, err
			}
			if budget <= 0 {
				return PacketResult{}, ErrBudget
			}
			budget--
			var actual flow.Traffic
			for _, box := range view.Translated.Regions() {
				part, err := restrictDestinations(box, route.Addresses, limits.MaxRegions)
				if err != nil {
					return PacketResult{}, err
				}
				actual, err = actual.Union(part, limits.MaxRegions)
				if err != nil {
					return PacketResult{}, err
				}
			}
			original, err := srxOriginal(fw, view, actual, limits.MaxRegions)
			if err != nil {
				return PacketResult{}, err
			}
			if !route.Known {
				if err := markUnknown(original); err != nil {
					return PacketResult{}, err
				}
				continue
			}
			piece := view
			piece.Original, piece.Translated = original, actual
			request := q.Request
			request.Traffic = original
			request.ToZone = route.Zone.ID()
			request.EgressInterface = route.Interface.ID()
			evaluated, err := e.fortinetPolicy(ctx, fw, request, piece, &budget)
			if err != nil {
				return PacketResult{}, err
			}
			unknown, err := srxOriginal(fw, piece, evaluated.Unknown, limits.MaxRegions)
			if err != nil {
				return PacketResult{}, err
			}
			if err := markUnknown(unknown); err != nil {
				return PacketResult{}, err
			}
			for _, trace := range evaluated.Decisions {
				if !trace.Known {
					continue
				}
				post := NATResult{Complete: true, Unmatched: trace.Traffic}
				if trace.Action == fm.Permit {
					request.Traffic = trace.Traffic
					post, err = e.fortinetPost(ctx, fw, request, trace.Rule, &budget)
					if err != nil {
						return PacketResult{}, err
					}
					unknown, err = srxOriginal(fw, piece, post.Unknown, limits.MaxRegions)
					if err != nil {
						return PacketResult{}, err
					}
					if err := markUnknown(unknown); err != nil {
						return PacketResult{}, err
					}
				}
				for _, part := range natParts(post) {
					policyView := part.Original
					part, err = fortinetCompose(fw, piece, part, limits.MaxRegions)
					if err != nil {
						return PacketResult{}, err
					}
					result := Result{Complete: true, Decisions: []RuleDecision{{Rule: trace.Rule, Action: trace.Action, Traffic: policyView, Known: true}}}
					if trace.Action == fm.Permit {
						result.Allowed = policyView
					} else {
						result.Denied = policyView
					}
					if len(out.Paths) >= limits.MaxRegions {
						return PacketResult{}, ErrBudget
					}
					out.Paths = append(out.Paths, PacketPath{Original: part.Original, FromZone: q.FromZone, ToZone: request.ToZone, NAT: part, Policy: result})
				}
			}
			if !evaluated.Unmatched.Empty() {
				unknown, err = srxOriginal(fw, piece, evaluated.Unmatched, limits.MaxRegions)
				if err != nil {
					return PacketResult{}, err
				}
				if err := markUnknown(unknown); err != nil {
					return PacketResult{}, err
				}
			}
		}
	}
	return out, nil
}

// VIP and IP-pool addresses can be local destinations in FortiOS even when no
// policy references them. Version/ARP/local-in behavior is not established by a
// route alone, so an untranslated packet to these addresses stays unknown.
func fortinetLocalAddresses(ctx context.Context, fw *fm.Firewall, scope string, budget *int) (flow.AddressSet, error) {
	var ranges []flow.AddressRange
	charge := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if *budget <= 0 {
			return ErrBudget
		}
		*budget--
		return nil
	}
	for _, pool := range fw.NATPools() {
		if err := charge(); err != nil {
			return flow.AddressSet{}, err
		}
		r := pool.Record()
		if r.Scope == scope {
			ranges = append(ranges, r.Ranges...)
		}
	}
	for _, entry := range fw.NATSequence() {
		if err := charge(); err != nil {
			return flow.AddressSet{}, err
		}
		if entry.Scope != scope || entry.Order.Section != "vip" {
			continue
		}
		n, err := transform(fw, NATStep{Kind: entry.Kind, ID: entry.ID})
		if err != nil {
			return flow.AddressSet{}, err
		}
		if n.disabled {
			continue
		}
		for _, m := range n.destination {
			ranges = append(ranges, m.Original)
		}
	}
	return flow.NewAddressSet(ranges...)
}
