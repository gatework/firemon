package policy

import (
	"context"
	"net/netip"
	"slices"
	"strings"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
)

type RoutePath struct {
	Addresses flow.AddressSet
	Interface *fm.Interface
	Zone      *fm.Zone
	Known     bool
}

// ResolveRoutes partitions addresses by native longest-prefix route evidence within one VRF.
func (e Engine) ResolveRoutes(ctx context.Context, fw *fm.Firewall, vrf string, addresses flow.AddressSet) ([]RoutePath, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if fw == nil {
		return nil, ErrInvalid
	}
	limits := e.Limits.WithDefaults()
	limit := limits.MaxRegions
	var routes []routeCandidate
	for _, r := range fw.Routes() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if r.Scope() != vrf {
			continue
		}
		record := r.Record()
		if len(routes) >= limits.MaxVisits {
			return nil, ErrBudget
		}
		if len(record.PolicyMatch) > 0 {
			return []RoutePath{{Addresses: addresses}}, nil
		}
		routes = append(routes, routeCandidate{route: r, destination: record.Destination, metric: record.Metric, key: record.Destination.String()})
	}
	if err := sortRoutes(ctx, routes); err != nil {
		return nil, err
	}
	remaining := addresses
	var result []RoutePath
	for i := 0; i < len(routes) && !remaining.Empty(); {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		r := routes[i].route
		record := routes[i]
		j := i + 1
		for j < len(routes) {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			other := routes[j]
			if other.destination != record.destination || other.metric != record.metric {
				break
			}
			j++
		}
		network, err := flow.PrefixRange(record.destination)
		if err != nil {
			return nil, err
		}
		set, _ := flow.NewAddressSet(network)
		hit := remaining.Intersection(set)
		if !hit.Empty() {
			path := RoutePath{Addresses: hit, Interface: r.Interface(), Known: true}
			if path.Interface == nil || path.Interface.Zone() == nil {
				path.Known = false
			} else {
				path.Zone = path.Interface.Zone()
				if path.Interface.Disabled() || path.Interface.HasUnsupported() || path.Zone.HasUnsupported() {
					path.Known = false
				}
			}
			if r.HasUnsupported() {
				path.Known = false
			}
			for _, other := range routes[i+1 : j] {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				if other.route.Interface() != path.Interface || other.route.HasUnsupported() {
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
	return result, ctx.Err()
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
	if fw == nil {
		return PacketResult{}, ErrInvalid
	}
	query := semantics(fw.Metadata().Vendor).queryPacket
	if query == nil {
		return PacketResult{}, ErrNAT
	}
	return query(e, ctx, fw, q)
}

func (e Engine) paloaltoPacket(ctx context.Context, fw *fm.Firewall, q PacketRequest) (PacketResult, error) {
	limits := e.Limits.WithDefaults()
	result := PacketResult{Complete: true}
	if q.FromZone == "" || fw.Zone(q.FromZone) == nil {
		return PacketResult{Unknown: q.Traffic}, nil
	}
	unknown := func(t flow.Traffic) error {
		var err error
		result.Unknown, err = result.Unknown.Union(t, limits.MaxRegions)
		result.Complete = false
		return err
	}
	for _, box := range q.Traffic.Regions() {
		destinations, _ := flow.NewAddressSet(box.Destination)
		pre, err := e.ResolveRoutes(ctx, fw, q.VRF, destinations)
		if err != nil {
			return PacketResult{}, err
		}
		for _, route := range pre {
			original, err := restrictDestinations(box, route.Addresses, limits.MaxRegions)
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
			request.ToZone = route.Zone.ID()
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
				var dest flow.AddressSet
				for _, translated := range relation.Translated.Regions() {
					part, _ := flow.NewAddressSet(translated.Destination)
					dest = dest.Union(part)
				}
				post, err := e.ResolveRoutes(ctx, fw, q.VRF, dest)
				if err != nil {
					return PacketResult{}, err
				}
				for _, path := range post {
					portion, err := originalDestination(fw, relation, path.Addresses, limits.MaxRegions)
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
					request.ToZone = path.Zone.ID()
					evaluated, err := e.Query(ctx, fw, request)
					if err != nil {
						return PacketResult{}, err
					}
					if !evaluated.Complete {
						result.Complete = false
					}
					if len(result.Paths) >= limits.MaxRegions {
						return PacketResult{}, ErrBudget
					}
					result.Paths = append(result.Paths, PacketPath{Original: portion, FromZone: request.FromZone, ToZone: request.ToZone, NAT: relation, Policy: evaluated})
				}
			}
		}
	}
	return result, nil
}
func restrictDestinations(box flow.TrafficRegion, addresses flow.AddressSet, limit int) (flow.Traffic, error) {
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
func originalDestination(fw *fm.Firewall, relation NATRelation, destinations flow.AddressSet, limit int) (flow.Traffic, error) {
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
		original = flow.AddressSet{}
		for _, mapping := range mappings {
			target, _ := flow.NewAddressSet(mapping.Translated)
			overlap := target.Intersection(destinations)
			if overlap.Empty() {
				continue
			}
			switch mapping.Mode {
			case fm.Constant:
				part, _ := flow.NewAddressSet(mapping.Original)
				original = original.Union(part)
			case fm.Identity, fm.Offset:
				reverse := fm.Mapping{Original: mapping.Translated, Translated: mapping.Original, Mode: mapping.Mode}
				for _, r := range overlap.Ranges() {
					v, err := translate(r, reverse)
					if err != nil {
						return flow.Traffic{}, err
					}
					part, _ := flow.NewAddressSet(v)
					original = original.Union(part)
				}
			default:
				return flow.Traffic{}, ErrNAT
			}
		}
	}
	var out flow.Traffic
	for _, box := range relation.Original.Regions() {
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

// routeCandidate caches only ordering keys, retaining immutable object identity.
type routeCandidate struct {
	route       *fm.Route
	destination netip.Prefix
	metric      uint32
	key         string
}

func compareRoutes(a, b routeCandidate) int {
	if a.destination.Bits() != b.destination.Bits() {
		return b.destination.Bits() - a.destination.Bits()
	}
	if a.metric < b.metric {
		return -1
	}
	if a.metric > b.metric {
		return 1
	}
	return strings.Compare(a.key, b.key)
}

// sortRoutes bounds uninterrupted sorting to a small standard-library chunk.
// Larger tables are stably merged with cancellation checkpoints; equal native
// priorities retain declaration order, including ambiguous routes.
func sortRoutes(ctx context.Context, routes []routeCandidate) error {
	const chunk = 64
	for start := 0; start < len(routes); start += chunk {
		if err := ctx.Err(); err != nil {
			return err
		}
		slices.SortStableFunc(routes[start:min(start+chunk, len(routes))], compareRoutes)
	}
	if len(routes) <= chunk {
		return ctx.Err()
	}
	buffer := make([]routeCandidate, len(routes))
	source, target := routes, buffer
	original := true
	for width := chunk; width < len(routes); width *= 2 {
		for start := 0; start < len(routes); start += 2 * width {
			middle, end := min(start+width, len(routes)), min(start+2*width, len(routes))
			left, right := start, middle
			for out := start; out < end; out++ {
				if out%chunk == 0 {
					if err := ctx.Err(); err != nil {
						return err
					}
				}
				if left < middle && (right >= end || compareRoutes(source[left], source[right]) <= 0) {
					target[out] = source[left]
					left++
				} else {
					target[out] = source[right]
					right++
				}
			}
		}
		source, target = target, source
		original = !original
	}
	if !original {
		copy(routes, source)
	}
	return ctx.Err()
}
