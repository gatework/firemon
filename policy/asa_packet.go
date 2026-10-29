package policy

import (
	"context"
	"net/netip"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
)

type asaSelection struct {
	relation NATRelation
	egress   fm.ID
}

// ASA NAT chooses an explicitly named egress before routing (except the
// unsupported route-lookup option). A route to the public address must not
// prevent a reverse static mapping from selecting its real interface.
func (e Engine) asaSelect(ctx context.Context, fw *fm.Firewall, q Request) ([]asaSelection, flow.Traffic, error) {
	steps, err := e.asaSteps(ctx, fw, q.Scope)
	if err != nil {
		return nil, flow.Traffic{}, err
	}
	limits := e.Limits.WithDefaults()
	budget := limits.MaxVisits
	remaining := q.Traffic
	var selected []asaSelection
	var unknown flow.Traffic
	for _, step := range steps {
		if err := ctx.Err(); err != nil {
			return nil, flow.Traffic{}, err
		}
		if remaining.Empty() {
			break
		}
		n, err := transform(fw, step)
		if err != nil {
			return nil, flow.Traffic{}, err
		}
		request := q
		request.Traffic, request.ToZone = remaining, ""
		if !n.match.AnyToZone {
			if len(n.match.ToZones) != 1 {
				return nil, q.Traffic, nil
			}
			request.ToZone = n.match.ToZones[0]
		}
		r, err := e.natChain(ctx, fw, request, []NATStep{step}, &budget)
		if err != nil {
			return nil, flow.Traffic{}, err
		}
		unknown, err = unknown.Union(r.Unknown, limits.MaxRegions)
		if err != nil {
			return nil, flow.Traffic{}, err
		}
		for _, relation := range r.Relations {
			if len(selected) >= limits.MaxRegions {
				return nil, flow.Traffic{}, ErrBudget
			}
			selected = append(selected, asaSelection{relation, request.ToZone})
		}
		remaining = r.Unmatched
	}
	if !remaining.Empty() {
		if len(selected) >= limits.MaxRegions {
			return nil, flow.Traffic{}, ErrBudget
		}
		selected = append(selected, asaSelection{relation: NATRelation{Original: remaining, Translated: remaining, Exact: true}})
	}
	return selected, unknown, nil
}

func zoneInterface(fw *fm.Firewall, scope string, zone fm.ID) *fm.Interface {
	var found *fm.Interface
	for _, i := range fw.Interfaces() {
		r := i.Record()
		if r.Scope != scope || r.Zone != zone {
			continue
		}
		if found != nil || r.Disabled || len(r.Unsupported) > 0 || i.Zone() == nil || len(i.Zone().Record().Unsupported) > 0 {
			return nil
		}
		found = i
	}
	return found
}

func (e Engine) asaPacket(ctx context.Context, fw *fm.Firewall, q PacketRequest) (PacketResult, error) {
	if !fw.Complete() {
		return PacketResult{Unknown: q.Traffic}, nil
	}
	ingress := zoneInterface(fw, q.Scope, q.FromZone)
	if ingress == nil {
		return PacketResult{Unknown: q.Traffic}, nil
	}
	selected, unresolved, err := e.asaSelect(ctx, fw, q.Request)
	if err != nil {
		return PacketResult{}, err
	}
	limits := e.Limits.WithDefaults()
	result := PacketResult{Unknown: unresolved, Complete: unresolved.Empty()}
	unknown := func(t flow.Traffic) error {
		var err error
		result.Complete = false
		result.Unknown, err = result.Unknown.Union(t, limits.MaxRegions)
		return err
	}
	for _, selection := range selected {
		if err := ctx.Err(); err != nil {
			return PacketResult{}, err
		}
		relation := selection.relation
		n := natTransform{known: true}
		if len(relation.Steps) == 1 {
			n, err = transform(fw, relation.Steps[0])
			if err != nil {
				return PacketResult{}, err
			}
		}
		// ACLs use real source (before SNAT) and real destination (after DNAT),
		// including destination service translation. Preserve each input pair.
		aclTransform := n
		aclTransform.source, aclTransform.sourcePorts, aclTransform.dynamic = nil, nil, nil
		traffic, _, _, err := aclTransform.apply(relation.Original, limits.MaxRegions)
		if err != nil {
			return PacketResult{}, err
		}
		var dest flow.AddressSet
		for _, b := range traffic.Regions() {
			s, _ := flow.NewAddressSet(b.Destination)
			dest = dest.Union(s)
		}
		var paths []RoutePath
		if selection.egress != "" {
			iface := zoneInterface(fw, q.Scope, selection.egress)
			path := RoutePath{Addresses: dest, Interface: iface, Known: iface != nil}
			if iface != nil {
				path.Zone = iface.Zone()
			}
			paths = []RoutePath{path}
		} else {
			paths, err = e.ResolveRoutes(ctx, fw, q.VRF, dest)
			if err != nil {
				return PacketResult{}, err
			}
		}
		for _, path := range paths {
			original, err := originalDestination(fw, relation, path.Addresses, limits.MaxRegions)
			if err != nil {
				return PacketResult{}, err
			}
			if !path.Known {
				if err := unknown(original); err != nil {
					return PacketResult{}, err
				}
				continue
			}
			actual, _, _, err := aclTransform.apply(original, limits.MaxRegions)
			if err != nil {
				return PacketResult{}, err
			}
			request := q.Request
			request.Traffic, request.ToZone = actual, path.Zone.ID()
			evaluated, err := e.asaAccess(ctx, fw, request, ingress, path.Interface)
			if err != nil {
				return PacketResult{}, err
			}
			if !evaluated.Complete {
				if err := unknown(original); err != nil {
					return PacketResult{}, err
				}
			}
			selectedRelation := relation
			selectedRelation.Original = original
			selectedRelation.Translated, _, _, err = n.apply(original, limits.MaxRegions)
			if err != nil {
				return PacketResult{}, err
			}
			if len(result.Paths) >= limits.MaxRegions {
				return PacketResult{}, ErrBudget
			}
			result.Paths = append(result.Paths, PacketPath{Original: original, FromZone: q.FromZone, ToZone: request.ToZone, NAT: selectedRelation, Policy: evaluated})
		}
	}
	return result, nil
}

// asaAccess evaluates new through-the-box flows using the bound inbound and
// outbound ACLs. Returning sessions, control-plane/VPN and same-security permit
// commands need additional native evidence and remain unsupported by parsing.
func (e Engine) asaAccess(ctx context.Context, fw *fm.Firewall, q Request, ingress, egress *fm.Interface) (Result, error) {
	// Multicast/broadcast needs native routing/relay evidence beyond an ACL.
	for _, box := range q.Traffic.Regions() {
		for _, cidr := range []string{"224.0.0.0/4", "ff00::/8", "255.255.255.255/32"} {
			network, _ := flow.PrefixRange(netip.MustParsePrefix(cidr))
			if _, overlap := box.Destination.Intersection(network); overlap {
				return Result{Unknown: q.Traffic}, nil
			}
		}
	}
	a, b := ingress.Record(), egress.Record()
	if !a.SecurityLevelKnown || !b.SecurityLevelKnown || a.SecurityLevel > 100 || b.SecurityLevel > 100 {
		return Result{Unknown: q.Traffic}, nil
	}
	if ingress == egress || a.SecurityLevel == b.SecurityLevel {
		return Result{Denied: q.Traffic, Complete: true}, nil
	}
	var incoming, outgoing []string
	for _, binding := range fw.RuleBindings() {
		r := binding.Record()
		if r.Scope != q.Scope {
			continue
		}
		if r.Direction == "in" && binding.Interface() == ingress {
			incoming = append(incoming, r.RuleSet)
		}
		if r.Direction == "out" && binding.Interface() == egress {
			outgoing = append(outgoing, r.RuleSet)
		}
	}
	if len(incoming) > 1 || len(outgoing) > 1 {
		return Result{Unknown: q.Traffic}, nil
	}
	limit := e.Limits.WithDefaults().MaxRegions
	query := func(name string, traffic flow.Traffic) (Result, error) {
		request := q
		request.RuleSet, request.Traffic = name, traffic
		r, err := e.Query(ctx, fw, request)
		if err != nil {
			return Result{}, err
		}
		r.Denied, err = r.Denied.Union(r.Unmatched, limit)
		r.Unmatched = flow.Traffic{}
		return r, err
	}
	r := Result{Complete: true}
	var err error
	if len(incoming) > 0 {
		r, err = query(incoming[0], q.Traffic)
	} else if a.SecurityLevel > b.SecurityLevel {
		r.Allowed = q.Traffic
	} else {
		r.Denied = q.Traffic
	}
	if err != nil {
		return Result{}, err
	}
	if len(outgoing) == 0 || r.Allowed.Empty() {
		return r, nil
	}
	out, err := query(outgoing[0], r.Allowed)
	if err != nil {
		return Result{}, err
	}
	r.Allowed = out.Allowed
	r.Denied, err = r.Denied.Union(out.Denied, limit)
	if err != nil {
		return Result{}, err
	}
	r.Unknown, err = r.Unknown.Union(out.Unknown, limit)
	r.Decisions = append(r.Decisions, out.Decisions...)
	r.Complete = r.Complete && out.Complete
	return r, err
}
