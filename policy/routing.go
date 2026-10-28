package policy

import (
	"context"
	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"slices"
	"strings"
)

type RoutePath struct {
	Addresses flow.Set
	Interface *fm.Interface
	Zone      *fm.Zone
	Known     bool
}

// Routes partitions addresses by native longest-prefix route evidence within one VRF.
func Routes(ctx context.Context, fw *fm.Firewall, vrf string, addresses flow.Set, limit int) ([]RoutePath, error) {
	if limit < 1 {
		return nil, ErrBudget
	}
	var routes []*fm.Route
	for _, r := range fw.Routes() {
		record := r.Record()
		if record.Scope != vrf {
			continue
		}
		if len(record.PolicyMatch) > 0 {
			return []RoutePath{{Addresses: addresses}}, nil
		}
		routes = append(routes, r)
	}
	if len(routes) > 100000 {
		return nil, ErrBudget
	}
	slices.SortStableFunc(routes, func(a, b *fm.Route) int {
		x, y := a.Record(), b.Record()
		if x.Destination.Bits() != y.Destination.Bits() {
			return y.Destination.Bits() - x.Destination.Bits()
		}
		if x.Metric < y.Metric {
			return -1
		}
		if x.Metric > y.Metric {
			return 1
		}
		return strings.Compare(x.Destination.String(), y.Destination.String())
	})
	remaining := addresses
	var result []RoutePath
	for i := 0; i < len(routes) && !remaining.Empty(); {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		r := routes[i]
		record := r.Record()
		j := i + 1
		for j < len(routes) {
			other := routes[j].Record()
			if other.Destination != record.Destination || other.Metric != record.Metric {
				break
			}
			j++
		}
		network, err := flow.PrefixRange(record.Destination)
		if err != nil {
			return nil, err
		}
		set, _ := flow.NewSet(network)
		hit := remaining.Intersection(set)
		if !hit.Empty() {
			path := RoutePath{Addresses: hit, Interface: r.Interface(), Known: true}
			if path.Interface == nil || path.Interface.Zone() == nil {
				path.Known = false
			} else {
				path.Zone = path.Interface.Zone()
				record := path.Interface.Record()
				if record.Disabled || len(record.Unsupported) > 0 || len(path.Zone.Record().Unsupported) > 0 {
					path.Known = false
				}
			}
			if len(record.Unsupported) > 0 {
				path.Known = false
			}
			for _, other := range routes[i+1 : j] {
				if other.Interface() != path.Interface || len(other.Record().Unsupported) > 0 {
					path.Known = false
					path.Interface = nil
					path.Zone = nil
				}
			}
			if len(result) >= limit {
				return nil, ErrBudget
			}
			result = append(result, path)
			remaining = remaining.Difference(hit)
		}
		i = j
	}
	if !remaining.Empty() {
		if len(result) >= limit {
			return nil, ErrBudget
		}
		result = append(result, RoutePath{Addresses: remaining})
	}
	return result, nil
}

type PacketRequest struct {
	Request
	VRF string
}
type PacketPath struct {
	Original         flow.Traffic
	FromZone, ToZone fm.ID
	NAT              NATRelation
	// Policy coverage uses the native ACL view (ASA real addresses/services,
	// PAN original addresses/services). Original retains the wire request view.
	Policy Result
}
type PacketResult struct {
	Paths    []PacketPath
	Unknown  flow.Traffic
	Complete bool
}

// QueryPacket follows vendor-specific address views: original PAN addresses and
// post-DNAT zone, or ASA real destination addresses/services and native egress.
// The ingress zone is evidence supplied by the caller; asymmetric ingress is never inferred from reverse routing.
func (e Engine) QueryPacket(ctx context.Context, fw *fm.Firewall, q PacketRequest) (PacketResult, error) {
	if err := ctx.Err(); err != nil {
		return PacketResult{}, err
	}
	if fw != nil && fw.Metadata().Vendor == "asa" {
		return e.asaPacket(ctx, fw, q)
	}
	if fw != nil && fw.Metadata().Vendor == "srx" {
		return e.srxPacket(ctx, fw, q)
	}
	if fw != nil && fw.Metadata().Vendor == "netscreen" {
		return e.netscreenPacket(ctx, fw, q)
	}
	if fw != nil && fw.Metadata().Vendor == "fortinet" {
		return e.fortinetPacket(ctx, fw, q)
	}
	if fw == nil || fw.Metadata().Vendor != "paloalto" {
		return PacketResult{}, ErrNAT
	}
	limits := e.Limits.defaults()
	result := PacketResult{Complete: true}
	if q.FromZone == "" || fw.Zone(q.FromZone) == nil {
		return PacketResult{Unknown: q.Traffic}, nil
	}
	unknown := func(t flow.Traffic) error {
		var err error
		result.Unknown, err = result.Unknown.Union(t, limits.Regions)
		result.Complete = false
		return err
	}
	for _, box := range q.Traffic.Boxes() {
		destinations, _ := flow.NewSet(box.Destination)
		pre, err := Routes(ctx, fw, q.VRF, destinations, limits.Regions)
		if err != nil {
			return PacketResult{}, err
		}
		for _, route := range pre {
			original, err := restrictDestinations(box, route.Addresses, limits.Regions)
			if err != nil {
				return PacketResult{}, err
			}
			if !route.Known {
				if err := unknown(original); err != nil {
					return PacketResult{}, err
				}
				continue
			}
			request := q.Request
			request.Traffic = original
			request.ToZone = route.Zone.Record().ID
			nat, err := e.QueryNAT(ctx, fw, request)
			if err != nil {
				return PacketResult{}, err
			}
			if !nat.Unknown.Empty() {
				if err = unknown(nat.Unknown); err != nil {
					return PacketResult{}, err
				}
			}
			relations := nat.Relations
			if !nat.Unmatched.Empty() {
				relations = append(relations, NATRelation{Original: nat.Unmatched, Translated: nat.Unmatched, Exact: true})
			}
			for _, relation := range relations {
				var dest flow.Set
				for _, translated := range relation.Translated.Boxes() {
					part, _ := flow.NewSet(translated.Destination)
					dest = dest.Union(part)
				}
				post, err := Routes(ctx, fw, q.VRF, dest, limits.Regions)
				if err != nil {
					return PacketResult{}, err
				}
				for _, path := range post {
					portion, err := originalDestination(fw, relation, path.Addresses, limits.Regions)
					if err != nil {
						if err = unknown(relation.Original); err != nil {
							return PacketResult{}, err
						}
						continue
					}
					if !path.Known {
						if err = unknown(portion); err != nil {
							return PacketResult{}, err
						}
						continue
					}
					request.Traffic = portion
					request.ToZone = path.Zone.Record().ID
					evaluated, err := e.Query(ctx, fw, request)
					if err != nil {
						return PacketResult{}, err
					}
					if !evaluated.Complete {
						result.Complete = false
					}
					if len(result.Paths) >= limits.Regions {
						return PacketResult{}, ErrBudget
					}
					result.Paths = append(result.Paths, PacketPath{Original: portion, FromZone: request.FromZone, ToZone: request.ToZone, NAT: relation, Policy: evaluated})
				}
			}
		}
	}
	return result, nil
}
func restrictDestinations(box flow.Box, addresses flow.Set, limit int) (flow.Traffic, error) {
	var out flow.Traffic
	for _, r := range addresses.Ranges() {
		if intersection, ok := box.Destination.Intersection(r); ok {
			piece := box
			piece.Destination = intersection
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
func originalDestination(fw *fm.Firewall, relation NATRelation, destinations flow.Set, limit int) (flow.Traffic, error) {
	var mappings []fm.Mapping
	if len(relation.Steps) > 1 {
		return flow.Traffic{}, ErrNAT
	}
	if relation.Kind != 0 {
		step := NATStep{Kind: relation.Kind, ID: relation.ID}
		if len(relation.Steps) == 1 {
			step = relation.Steps[0]
		}
		n, err := transform(fw, step)
		if err != nil {
			return flow.Traffic{}, err
		}
		mappings = n.destination
	}
	original := destinations
	if len(mappings) > 0 {
		original = flow.Set{}
		for _, mapping := range mappings {
			target, _ := flow.NewSet(mapping.Translated)
			overlap := target.Intersection(destinations)
			if overlap.Empty() {
				continue
			}
			switch mapping.Mode {
			case fm.Constant:
				part, _ := flow.NewSet(mapping.Original)
				original = original.Union(part)
			case fm.Identity, fm.Offset:
				reverse := fm.Mapping{Original: mapping.Translated, Translated: mapping.Original, Mode: mapping.Mode}
				for _, r := range overlap.Ranges() {
					v, err := translate(r, reverse)
					if err != nil {
						return flow.Traffic{}, err
					}
					part, _ := flow.NewSet(v)
					original = original.Union(part)
				}
			default:
				return flow.Traffic{}, ErrNAT
			}
		}
	}
	var out flow.Traffic
	for _, box := range relation.Original.Boxes() {
		part, err := restrictDestinations(box, original, limit)
		if err != nil {
			return flow.Traffic{}, err
		}
		out, err = out.Union(part, limit)
		if err != nil {
			return flow.Traffic{}, err
		}
	}
	return out, nil
}
