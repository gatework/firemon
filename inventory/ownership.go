package inventory

import (
	"cmp"
	"fmt"
	"net/netip"
	"slices"

	"github.com/gatework/firemon/traffic"
)

// Ownership tells how a firewall came to own addresses.
type Ownership uint8

// Ownerships, from most to least authoritative.
const (
	OwnershipUnset Ownership = iota
	// OwnershipDeclared comes from the protected networks of the inventory.
	OwnershipDeclared
	// OwnershipDerived comes from the firewall's own non-default routes.
	OwnershipDerived
	// OwnershipTransit marks a firewall the traffic reaches through route
	// next hops without owning either end.
	OwnershipTransit
	// OwnershipZones marks the only firewall of an inventory evaluated for
	// traffic it does not route, because the request names both zones (a
	// transparent firewall bridges it).
	OwnershipZones
)

// String returns the ownership name.
func (o Ownership) String() string {
	switch o {
	case OwnershipUnset:
		return "unset"
	case OwnershipDeclared:
		return "declared"
	case OwnershipDerived:
		return "derived"
	case OwnershipTransit:
		return "transit"
	case OwnershipZones:
		return "zones"
	default:
		return "invalid"
	}
}

// MarshalText implements encoding.TextMarshaler.
func (o Ownership) MarshalText() ([]byte, error) { return []byte(o.String()), nil }

// claim is one cluster's claim on addresses.
type claim struct {
	cluster, zone string
	set           traffic.AddressSet
	bits          int
	ownership     Ownership
}

// owned is a part of an address set and its owner, with the networks of
// the claims that gave it.
type owned struct {
	cluster, zone string
	set           traffic.AddressSet
	ownership     Ownership
	networks      []string
}

// buildClaims turns declared protections into claims and, for clusters
// without declarations, derives claims from non-default routes.
func (inv *Inventory) buildClaims(protections []Protection) ([]claim, error) {
	declared := map[string]bool{}
	protectedZones := map[string][]string{} // cluster -> its protected zones
	var out []claim
	for _, p := range protections {
		m := inv.memberNamed(p.Firewall)
		if m == nil {
			return nil, fmt.Errorf("inventory: protection for unknown firewall %q", p.Firewall)
		}
		declared[m.cluster] = true
		if p.Zone != "" && !slices.Contains(protectedZones[m.cluster], p.Zone) {
			protectedZones[m.cluster] = append(protectedZones[m.cluster], p.Zone)
		}
		excluded := traffic.NewAddressSet(p.Exclude...)
		for _, n := range p.Networks {
			set := traffic.NewAddressSet(n).Subtract(excluded)
			out = append(out, claim{cluster: m.cluster, zone: p.Zone, set: set, bits: n.Bits(), ownership: OwnershipDeclared})
		}
	}
	for _, m := range inv.members {
		// A cluster that declares protected networks also owns what its
		// routes reach through its protected zones; routes into other zones
		// (management, the outside) make no claim. A cluster that declares
		// nothing owns what all its routes reach.
		zones, isDeclared := protectedZones[m.cluster], declared[m.cluster]
		if isDeclared && len(zones) == 0 {
			continue
		}
		table, ok := m.fw.RoutingTable(m.fw.Semantics().DefaultVirtualRouter)
		if !ok {
			continue
		}
		egress, _ := table.Lookup(traffic.AnyAddress())
		for _, e := range egress {
			b := e.Route.Destination.Bits()
			if b == 0 || e.Interface == "" || inv.towardOther(m.cluster, e.Route.NextHop) {
				continue
			}
			if isDeclared && !slices.Contains(zones, e.Zone) {
				continue
			}
			out = append(out, claim{cluster: m.cluster, zone: e.Zone, set: e.Addresses, bits: b, ownership: OwnershipDerived})
		}
	}
	// Declared claims win over derived ones; within each, longest prefix.
	slices.SortStableFunc(out, func(a, b claim) int {
		return cmp.Or(cmp.Compare(a.ownership, b.ownership), cmp.Compare(b.bits, a.bits))
	})
	return out, nil
}

// owners splits s by owner. Claims of equal rank and prefix length that
// belong to different clusters share the addresses; ambiguous reports them.
func (inv *Inventory) owners(s traffic.AddressSet) (parts []owned, unowned traffic.AddressSet, ambiguous []string) {
	remaining := s
	for i := 0; i < len(inv.claims) && !remaining.IsEmpty(); {
		j := i
		var taken traffic.AddressSet
		var clusters []string
		for ; j < len(inv.claims) && inv.claims[j].ownership == inv.claims[i].ownership && inv.claims[j].bits == inv.claims[i].bits; j++ {
			c := inv.claims[j]
			hit := remaining.Intersect(c.set)
			if hit.IsEmpty() {
				continue
			}
			parts = appendOwned(parts, owned{cluster: c.cluster, zone: c.zone, set: hit, ownership: c.ownership, networks: []string{c.set.String()}})
			taken = taken.Union(hit)
			if !slices.Contains(clusters, c.cluster) {
				clusters = append(clusters, c.cluster)
			}
		}
		if len(clusters) > 1 {
			ambiguous = append(ambiguous, taken.String())
		}
		remaining = remaining.Subtract(taken)
		i = j
	}
	return parts, remaining, ambiguous
}

// appendOwned merges a part into an existing part of the same owner and zone.
func appendOwned(parts []owned, o owned) []owned {
	i := slices.IndexFunc(parts, func(p owned) bool { return p.cluster == o.cluster && p.zone == o.zone && p.ownership == o.ownership })
	if i < 0 {
		return append(parts, o)
	}
	parts[i].set = parts[i].set.Union(o.set)
	for _, n := range o.networks {
		if !slices.Contains(parts[i].networks, n) {
			parts[i].networks = append(parts[i].networks, n)
		}
	}
	return parts
}

// towardOther reports whether hop is an interface address of another
// cluster of the inventory: networks behind it belong to that cluster or
// further, not to the one routing to it.
func (inv *Inventory) towardOther(cluster string, hop netip.Addr) bool {
	if !hop.IsValid() {
		return false
	}
	return slices.ContainsFunc(inv.byAddress[hop], func(c string) bool { return c != cluster })
}
