package migrate

import (
	"cmp"
	"slices"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/design"
)

// network translates virtual routers, zones, interfaces and static routes.
func (tr *translator) network() {
	for _, vr := range tr.src.VirtualRouters {
		name := tr.vr(vr.Name)
		if slices.ContainsFunc(tr.out.VirtualRouters, func(v firemon.VirtualRouter) bool { return v.Name == name }) {
			continue
		}
		out := firemon.VirtualRouter{Name: name}
		tr.out.VirtualRouters = append(tr.out.VirtualRouters, out)
		if name != tr.t.Semantics.DefaultVirtualRouter {
			tr.changes.network = append(tr.changes.network, design.AddVirtualRouter{VirtualRouter: out})
		}
		tr.item(ItemKindVirtualRouter, vr.Name, FidelityExact, "", name)
	}
	members := map[string][]string{}
	for _, i := range tr.src.Interfaces {
		if i.Zone != "" {
			members[tr.zone(i.Zone)] = append(members[tr.zone(i.Zone)], tr.iface(i.Name))
		}
	}
	for _, z := range tr.src.Zones {
		out := firemon.Zone{Name: tr.zone(z.Name), Mode: z.Mode, Description: z.Description}
		if z.VirtualRouter != "" {
			out.VirtualRouter = tr.vr(z.VirtualRouter)
		}
		tr.out.Zones = append(tr.out.Zones, out)
		tr.changes.network = append(tr.changes.network, design.AddZone{Zone: out, Interfaces: members[out.Name]})
		f, reason := FidelityExact, ""
		if z.Mode == firemon.ZoneModeLayer2 || z.Mode == firemon.ZoneModeTap {
			f, reason = FidelityApproximate, "the zone is created; its bridging or tap setup (vswitch, virtual wire) is not translated"
		}
		tr.item(ItemKindZone, z.Name, f, reason, out.Name)
	}
	for _, i := range tr.src.Interfaces {
		out := firemon.Interface{Name: tr.iface(i.Name), Addresses: i.Addresses, Description: i.Description}
		if i.Zone != "" {
			out.Zone = tr.zone(i.Zone)
		}
		if i.VirtualRouter != "" {
			out.VirtualRouter = tr.vr(i.VirtualRouter)
		}
		tr.out.Interfaces = append(tr.out.Interfaces, out)
		if len(out.Addresses) > 0 || out.VirtualRouter != "" {
			tr.changes.network = append(tr.changes.network, design.AddInterface{Interface: out})
		}
		f, reason := FidelityExact, ""
		if _, ok := tr.m.Interfaces[i.Name]; !ok {
			f, reason = FidelityApproximate, "name kept: map it to the target port"
		}
		if len(i.AddressObjects) > 0 {
			f, reason = FidelityApproximate, "addresses taken from objects are written as addresses"
		}
		tr.item(ItemKindInterface, i.Name, f, reason, out.Name)
	}
	for _, r := range tr.src.Routes {
		tr.route(r)
	}
}

func (tr *translator) route(r firemon.Route) {
	id := r.VirtualRouter + " " + r.Destination.String()
	if r.Discard && !tr.caps.DiscardRoutes {
		tr.item(ItemKindRoute, id, FidelityUntranslatable, "the target cannot render a discard route")
		return
	}
	out := r
	out.VirtualRouter = tr.vr(r.VirtualRouter)
	out.Objects = nil
	if r.NextVirtualRouter != "" {
		out.NextVirtualRouter = tr.vr(r.NextVirtualRouter)
	}
	if r.Interface != "" {
		out.Interface = tr.iface(r.Interface)
	}
	if out.Distance == defaultDistance(tr.src.Vendor) {
		// The source's default stays the default on the target.
		out.Distance = defaultDistance(tr.t.Vendor)
	}
	tr.out.Routes = append(tr.out.Routes, out)
	tr.changes.network = append(tr.changes.network, design.AddRoute{Route: out})
	tr.item(ItemKindRoute, id, FidelityExact, "", out.VirtualRouter+" "+out.Destination.String())
}

// defaultDistance is the administrative distance of a static route that
// sets none.
func defaultDistance(v firemon.Vendor) uint32 {
	if v == firemon.VendorPaloAlto {
		return 10
	}
	return 1
}

func (tr *translator) zone(name string) string  { return mapped(tr.m.Zones, name) }
func (tr *translator) iface(name string) string { return mapped(tr.m.Interfaces, name) }

func (tr *translator) vr(name string) string {
	if t, ok := tr.m.VirtualRouters[name]; ok {
		return t
	}
	if name == tr.src.Semantics.DefaultVirtualRouter {
		return cmp.Or(tr.t.Semantics.DefaultVirtualRouter, name)
	}
	return name
}

func (tr *translator) zones(names []string) []string {
	out := make([]string, len(names))
	for i, z := range names {
		out[i] = tr.zone(z)
	}
	return out
}
