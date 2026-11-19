package inventory

import (
	"cmp"
	"fmt"
	"net/netip"
	"slices"

	"github.com/gatework/firemon/traffic"
)

// binding is one network bound to a zone of a cluster.
type binding struct {
	zone string
	set  traffic.AddressSet
	bits int
}

// buildBindings indexes the zone of every bound network per cluster,
// longest prefix first: the zone an address is in on that firewall.
func (inv *Inventory) buildBindings(protections []Protection, zones []ZoneBinding) (map[string][]binding, error) {
	out := map[string][]binding{}
	add := func(fw, zone string, nets, exclude []netip.Prefix) error {
		m := inv.memberNamed(fw)
		if m == nil {
			return fmt.Errorf("inventory: zone binding for unknown firewall %q", fw)
		}
		if zone == "" {
			return nil
		}
		excluded := traffic.NewAddressSet(exclude...)
		for _, n := range nets {
			b := binding{zone: zone, set: traffic.NewAddressSet(n).Subtract(excluded), bits: n.Bits()}
			if !slices.ContainsFunc(out[m.cluster], func(x binding) bool { return x.zone == b.zone && x.set.Equal(b.set) }) {
				out[m.cluster] = append(out[m.cluster], b)
			}
		}
		return nil
	}
	for _, p := range protections {
		if err := add(p.Firewall, p.Zone, p.Networks, p.Exclude); err != nil {
			return nil, err
		}
	}
	for _, z := range zones {
		if err := add(z.Firewall, z.Zone, z.Networks, z.Exclude); err != nil {
			return nil, err
		}
	}
	for c := range out {
		slices.SortStableFunc(out[c], func(a, b binding) int { return cmp.Compare(b.bits, a.bits) })
	}
	return out, nil
}

// zonePart is the part of an address set in one zone; zone is empty for
// addresses no binding covers.
type zonePart struct {
	zone string
	set  traffic.AddressSet
}

// zonesOf splits s by the zones a cluster binds its addresses to, longest
// prefix first; what no binding covers comes last with no zone.
func (inv *Inventory) zonesOf(cluster string, s traffic.AddressSet) []zonePart {
	var out []zonePart
	rest := s
	for _, b := range inv.bindings[cluster] {
		hit := rest.Intersect(b.set)
		if hit.IsEmpty() {
			continue
		}
		i := slices.IndexFunc(out, func(p zonePart) bool { return p.zone == b.zone })
		if i < 0 {
			out = append(out, zonePart{zone: b.zone, set: hit})
		} else {
			out[i].set = out[i].set.Union(hit)
		}
		rest = rest.Subtract(hit)
	}
	if !rest.IsEmpty() || len(out) == 0 {
		out = append(out, zonePart{set: rest})
	}
	return out
}
