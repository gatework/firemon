package policy

import (
	"context"
	"strings"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
)

func destinationTransform(n natTransform) natTransform {
	n.source, n.sourcePorts, n.dynamic = nil, nil, nil
	return n
}
func routeDestinations(ctx context.Context, fw *fm.Firewall, vrf string, traffic flow.Traffic, limit int) ([]RoutePath, error) {
	var destinations flow.Set
	for _, b := range traffic.Boxes() {
		s, _ := flow.NewSet(b.Destination)
		destinations = destinations.Union(s)
	}
	return Routes(ctx, fw, vrf, destinations, limit)
}
func routedTraffic(traffic flow.Traffic, route RoutePath, limit int) (flow.Traffic, error) {
	var out flow.Traffic
	for _, b := range traffic.Boxes() {
		t, err := restrictDestinations(b, route.Addresses, limit)
		if err != nil {
			return flow.Traffic{}, err
		}
		out, err = out.Union(t, limit)
		if err != nil {
			return flow.Traffic{}, err
		}
	}
	return out, nil
}

// huaweiRoutedChain matches original packet predicates, but resolves each rule's
// destination-zone/egress against that rule's own post-DNAT destination. Unknown
// candidate routing consumes its possible match and cannot fall through.
func (e Engine) huaweiRoutedChain(ctx context.Context, fw *fm.Firewall, q Request, vrf string, steps []NATStep, budget *int) (NATResult, error) {
	limit := e.Limits.defaults().Regions
	out := NATResult{Complete: true}
	remaining := q.Traffic
	for _, step := range steps {
		if err := ctx.Err(); err != nil {
			return NATResult{}, err
		}
		if remaining.Empty() {
			break
		}
		if *budget <= 0 {
			return NATResult{}, ErrBudget
		}
		*budget--
		n, err := transform(fw, step)
		if err != nil {
			return NATResult{}, err
		}
		if n.disabled {
			continue
		}
		request := q
		request.Traffic = remaining
		request.ToZone = ""
		request.EgressInterface = ""
		var possible flow.Traffic
		if n.inverseOf != nil {
			possible, _, err = e.inverseMatch(ctx, fw, n, request, remaining)
		} else {
			possible, _, err = e.Match(ctx, fw, n.match, request, remaining)
		}
		if err != nil {
			return NATResult{}, err
		}
		possible, err = restrictMappings(possible, n.source, true, limit)
		if err != nil {
			return NATResult{}, err
		}
		possible, err = restrictMappings(possible, n.destination, false, limit)
		if err != nil {
			return NATResult{}, err
		}
		if possible.Empty() {
			continue
		}
		pre := destinationTransform(n)
		view, _, _, err := pre.apply(possible, limit)
		if err != nil {
			return NATResult{}, err
		}
		routes, err := routeDestinations(ctx, fw, vrf, view, limit)
		if err != nil {
			return NATResult{}, err
		}
		var consumed flow.Traffic
		for _, route := range routes {
			actual, err := routedTraffic(view, route, limit)
			if err != nil {
				return NATResult{}, err
			}
			original, err := destinationPreimage(pre, possible, actual, limit)
			if err != nil {
				return NATResult{}, err
			}
			if !route.Known {
				out.Unknown, err = out.Unknown.Union(original, limit)
				if err != nil {
					return NATResult{}, err
				}
				consumed, err = consumed.Union(original, limit)
				if err != nil {
					return NATResult{}, err
				}
				continue
			}
			request.Traffic, request.ToZone, request.EgressInterface = original, route.Zone.Record().ID, route.Interface.Record().ID
			part, err := e.natChain(ctx, fw, request, []NATStep{step}, budget)
			if err != nil {
				return NATResult{}, err
			}
			hit, err := original.Difference(part.Unmatched, limit)
			if err != nil {
				return NATResult{}, err
			}
			consumed, err = consumed.Union(hit, limit)
			if err != nil {
				return NATResult{}, err
			}
			out.Unknown, err = out.Unknown.Union(part.Unknown, limit)
			if err != nil {
				return NATResult{}, err
			}
			if len(out.Relations)+len(part.Relations) > limit {
				return NATResult{}, ErrBudget
			}
			out.Relations = append(out.Relations, part.Relations...)
		}
		remaining, err = remaining.Difference(consumed, limit)
		if err != nil {
			return NATResult{}, err
		}
	}
	out.Unmatched, out.Complete = remaining, out.Unknown.Empty()
	return out, nil
}

// huaweiPacket evaluates policy with the original source and translated
// destination/service. Source allocation occurs only on the permitted partition.
func (e Engine) huaweiPacket(ctx context.Context, fw *fm.Firewall, q PacketRequest) (PacketResult, error) {
	q.FromZone = fm.ID(strings.ToLower(string(q.FromZone)))
	if !fw.Complete() || q.FromZone == "" || fw.Zone(q.FromZone) == nil || q.Scope != "" {
		return PacketResult{Unknown: q.Traffic}, nil
	}
	// Native security zones may contain interfaces in several VPN instances.
	// The caller must identify ingress VRF if the zone does not determine it.
	if q.VRF == "" {
		scopes := make(map[string]bool)
		for _, i := range fw.Interfaces() {
			r := i.Record()
			if r.Zone == q.FromZone && !r.Disabled {
				scopes[r.Scope] = true
			}
		}
		if len(scopes) != 1 {
			return PacketResult{Unknown: q.Traffic}, nil
		}
		for scope := range scopes {
			q.VRF = scope
		}
	}
	if q.VRF != "" && len(fw.NATSequence()) > 0 {
		return PacketResult{Unknown: q.Traffic}, nil
	}
	budget := e.Limits.defaults().Rules
	limit := e.Limits.defaults().Regions
	queryPolicy := func(request Request) (Result, error) {
		cost := len(fw.Rules())
		if cost > budget {
			return Result{}, ErrBudget
		}
		budget -= cost
		return e.Query(ctx, fw, request)
	}
	selected, err := e.huaweiSelected(ctx, fw, q.Request, &budget, func(request Request, steps []NATStep) (NATResult, error) {
		return e.huaweiRoutedChain(ctx, fw, request, q.VRF, steps, &budget)
	})
	if err != nil {
		return PacketResult{}, err
	}
	out := PacketResult{Complete: selected.Complete, Unknown: selected.Unknown}
	markUnknown := func(t flow.Traffic) error {
		var err error
		out.Unknown, err = out.Unknown.Union(t, limit)
		out.Complete = out.Unknown.Empty()
		return err
	}
	for _, part := range natParts(selected) {
		if err := ctx.Err(); err != nil {
			return PacketResult{}, err
		}
		pre := natTransform{known: true}
		if len(part.Steps) > 0 {
			n, err := transform(fw, part.Steps[0])
			if err != nil {
				return PacketResult{}, err
			}
			pre = destinationTransform(n)
		}
		view, _, _, err := pre.apply(part.Original, limit)
		if err != nil {
			return PacketResult{}, err
		}
		routes, err := routeDestinations(ctx, fw, q.VRF, view, limit)
		if err != nil {
			return PacketResult{}, err
		}
		for _, route := range routes {
			actual, err := routedTraffic(view, route, limit)
			if err != nil {
				return PacketResult{}, err
			}
			original, err := destinationPreimage(pre, part.Original, actual, limit)
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
			request.Traffic, request.ToZone, request.EgressInterface = actual, route.Zone.Record().ID, route.Interface.Record().ID
			result, err := queryPolicy(request)
			if err != nil {
				return PacketResult{}, err
			}
			unknown, err := destinationPreimage(pre, part.Original, result.Unknown, limit)
			if err != nil {
				return PacketResult{}, err
			}
			if err := markUnknown(unknown); err != nil {
				return PacketResult{}, err
			}
			rejected, err := result.Denied.Union(result.Unmatched, limit)
			if err != nil {
				return PacketResult{}, err
			}
			for _, piece := range []struct {
				traffic flow.Traffic
				permit  bool
			}{{rejected, false}, {result.Allowed, true}} {
				if piece.traffic.Empty() {
					continue
				}
				wire, err := destinationPreimage(pre, part.Original, piece.traffic, limit)
				if err != nil {
					return PacketResult{}, err
				}
				relation := NATRelation{Original: wire, Translated: piece.traffic, Exact: true}
				if piece.permit && len(part.Steps) > 0 {
					n, err := transform(fw, part.Steps[0])
					if err != nil {
						return PacketResult{}, err
					}
					relation = part
					relation.Original = wire
					relation.Translated, relation.Exact, relation.PossibleAllocation, err = n.apply(wire, limit)
					if err != nil {
						return PacketResult{}, err
					}
				}
				request.Traffic = piece.traffic
				verdict, err := queryPolicy(request)
				if err != nil {
					return PacketResult{}, err
				}
				if len(out.Paths) >= limit {
					return PacketResult{}, ErrBudget
				}
				out.Paths = append(out.Paths, PacketPath{Original: wire, FromZone: q.FromZone, ToZone: request.ToZone, NAT: relation, Policy: verdict})
			}
		}
	}
	out.Complete = out.Unknown.Empty()
	return out, nil
}
