package firemon

import (
	"fmt"
)

func (f *Firewall) bindVIPReferences() {
	for _, a := range f.Addresses() {
		r := a.record
		if r.VIP == (NATRef{}) {
			continue
		}
		switch r.VIP.Kind {
		case StaticNATObject:
			if n := f.staticNATs[r.VIP.ID]; n != nil && n.record.Scope == r.Scope {
				a.vipStaticNAT = n
			}
		case DynamicNATObject:
			if n := f.dynamicNATs[r.VIP.ID]; n != nil && n.record.Scope == r.Scope {
				a.vipDynamicNAT = n
			}
		}
		if a.vipStaticNAT == nil && a.vipDynamicNAT == nil {
			f.issue(r.ID, "invalid-vip-reference", "VIP destination NAT is missing, has the wrong kind, or is outside the native scope")
		}
	}
	for _, n := range f.StaticNATs() {
		r := n.record
		if r.SourceVIP == (AddressRef{}) {
			continue
		}
		if r.SourceVIP.Kind == AddressObject {
			if a := f.addresses[r.SourceVIP.ID]; a != nil && a.record.Scope == r.Scope && (a.vipStaticNAT != nil || a.vipDynamicNAT != nil) {
				n.sourceVIP = a
			}
		}
		if n.sourceVIP == nil {
			f.issue(r.ID, "invalid-source-vip-reference", "source mapping VIP address is missing, has the wrong kind, is unresolved, or is outside the native scope")
		}
	}
}

func (f *Firewall) bindRoute(r *Route, interfaces []*Interface) error {
	if !r.record.Destination.IsValid() {
		return fmt.Errorf("%w: invalid route prefix", ErrGraph)
	}
	if r.record.Interface != "" {
		i := f.interfaces[r.record.Interface]
		if i != nil && i.record.Scope == r.record.Scope {
			r.iface = i
		} else {
			f.issue(r.record.ID, "missing-interface", "route interface missing or outside VRF")
		}
	} else if r.record.NextHop.IsValid() {
		if i := uniqueNextHopInterface(r.record, interfaces); i != nil {
			r.iface = i
		} else {
			f.issue(r.record.ID, "unresolved-route", "next hop has no unique longest-prefix interface")
		}
	} else {
		f.issue(r.record.ID, "unresolved-route", "route lacks an interface or next hop")
	}
	if r.iface != nil {
		r.iface.routes = append(r.iface.routes, r)
	}
	return nil
}

// uniqueNextHopInterface returns the one enabled interface in the route's scope
// whose longest connected prefix contains the next hop, or nil when no
// interface or more than one interface has that longest prefix.
func uniqueNextHopInterface(route RouteRecord, interfaces []*Interface) *Interface {
	best, ties := -1, 0
	var match *Interface
	for _, i := range interfaces {
		if i.record.Scope != route.Scope || i.record.Disabled {
			continue
		}
		local := -1
		for _, p := range i.record.Addresses {
			if p.Contains(route.NextHop) && p.Bits() > local {
				local = p.Bits()
			}
		}
		switch {
		case local < 0:
		case local > best:
			best, ties, match = local, 1, i
		case local == best:
			ties++
		}
	}
	if ties != 1 {
		return nil
	}
	return match
}

func (f *Firewall) addressRefs(owner ID, refs []AddressRef) (as []*Address, gs []*AddressGroup) {
	for _, ref := range refs {
		switch ref.Kind {
		case AddressObject:
			if a := f.addresses[ref.ID]; a != nil {
				as = append(as, a)
			} else {
				f.issue(owner, "missing-address", string(ref.ID))
			}
		case AddressGroupObject:
			if g := f.addressGroups[ref.ID]; g != nil {
				gs = append(gs, g)
			} else {
				f.issue(owner, "missing-address-group", string(ref.ID))
			}
		default:
			f.issue(owner, "unknown-reference", "invalid address reference kind")
		}
	}
	return
}

func (f *Firewall) serviceRefs(owner ID, refs []ServiceRef) (ss []*Service, gs []*ServiceGroup) {
	for _, ref := range refs {
		switch ref.Kind {
		case ServiceObject:
			if s := f.services[ref.ID]; s != nil {
				ss = append(ss, s)
			} else {
				f.issue(owner, "missing-service", string(ref.ID))
			}
		case ServiceGroupObject:
			if g := f.serviceGroups[ref.ID]; g != nil {
				gs = append(gs, g)
			} else {
				f.issue(owner, "missing-service-group", string(ref.ID))
			}
		default:
			f.issue(owner, "unknown-reference", "invalid service reference kind")
		}
	}
	return
}

func (f *Firewall) bindGroups() {
	for _, g := range f.AddressGroups() {
		g.addresses, g.groups = f.addressRefs(g.record.ID, g.record.Members)
	}
	for _, g := range f.ServiceGroups() {
		g.services, g.groups = f.serviceRefs(g.record.ID, g.record.Members)
	}
	reportGroupCycles(f, f.AddressGroups(), func(g *AddressGroup) []*AddressGroup { return g.groups }, "cyclic address group")
	reportGroupCycles(f, f.ServiceGroups(), func(g *ServiceGroup) []*ServiceGroup { return g.groups }, "cyclic service group")
}

// reportGroupCycles reports each group reached again while its own members are
// being visited. Groups are visited in declaration order.
func reportGroupCycles[G interface{ ID() ID }](f *Firewall, groups []G, children func(G) []G, message string) {
	const (
		visiting = iota + 1
		visited
	)
	states := make(map[ID]uint8)
	var visit func(G)
	visit = func(g G) {
		switch states[g.ID()] {
		case visiting:
			f.issue(g.ID(), "group-cycle", message)
			return
		case visited:
			return
		}
		states[g.ID()] = visiting
		for _, child := range children(g) {
			visit(child)
		}
		states[g.ID()] = visited
	}
	for _, g := range groups {
		visit(g)
	}
}

func (f *Firewall) matchObjects(owner ID, m Match) MatchObjects {
	var refs MatchObjects
	refs.sources, refs.sourceGroups = f.addressRefs(owner, m.Sources)
	refs.destinations, refs.destinationGroups = f.addressRefs(owner, m.Destinations)
	refs.services, refs.serviceGroups = f.serviceRefs(owner, m.Services)
	refs.schedule = f.schedules[m.Schedule]
	for _, id := range m.FromZones {
		if zone := f.zones[id]; zone != nil {
			refs.fromZones = append(refs.fromZones, zone)
		}
	}
	for _, id := range m.ToZones {
		if zone := f.zones[id]; zone != nil {
			refs.toZones = append(refs.toZones, zone)
		}
	}
	return refs
}
