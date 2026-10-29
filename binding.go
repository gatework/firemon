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

func (f *Firewall) bindRoute(r *Route) error {
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
		best := -1
		var matches []*Interface
		for _, i := range f.Interfaces() {
			if i.record.Scope != r.record.Scope || i.record.Disabled {
				continue
			}
			local := -1
			for _, p := range i.record.Addresses {
				if p.Contains(r.record.NextHop) && p.Bits() > local {
					local = p.Bits()
				}
			}
			if local < 0 {
				continue
			}
			if local > best {
				best = local
				matches = []*Interface{i}
			} else if local == best {
				matches = append(matches, i)
			}
		}
		if len(matches) == 1 {
			r.iface = matches[0]
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
	states := make(map[ID]uint8)
	var visit func(*AddressGroup)
	visit = func(g *AddressGroup) {
		if states[g.record.ID] == 1 {
			f.issue(g.record.ID, "group-cycle", "cyclic address group")
			return
		}
		if states[g.record.ID] == 2 {
			return
		}
		states[g.record.ID] = 1
		for _, child := range g.groups {
			visit(child)
		}
		states[g.record.ID] = 2
	}
	for _, g := range f.AddressGroups() {
		visit(g)
	}
	states = make(map[ID]uint8)
	var serviceVisit func(*ServiceGroup)
	serviceVisit = func(g *ServiceGroup) {
		if states[g.record.ID] == 1 {
			f.issue(g.record.ID, "group-cycle", "cyclic service group")
			return
		}
		if states[g.record.ID] == 2 {
			return
		}
		states[g.record.ID] = 1
		for _, child := range g.groups {
			serviceVisit(child)
		}
		states[g.record.ID] = 2
	}
	for _, g := range f.ServiceGroups() {
		serviceVisit(g)
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
