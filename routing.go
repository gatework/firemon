package firemon

import (
	"cmp"
	"net/netip"
	"slices"

	"github.com/gatework/firemon/traffic"
)

// Egress is the part of a destination set one route forwards, with the
// interface and zone the traffic leaves through. A route to another
// virtual router has no interface; Route.NextVirtualRouter names the
// table to continue the lookup in.
type Egress struct {
	Route     Route
	Connected bool
	Interface string
	Zone      string
	Addresses traffic.AddressSet
}

// RoutingTable is the compiled forwarding table of one virtual router:
// connected routes from interface addresses plus static routes, ordered
// for longest-prefix match.
type RoutingTable struct {
	name    string
	entries []routeEntry
}

type routeEntry struct {
	route     Route
	connected bool
	iface     string
	zone      string
	order     int
}

// Name returns the virtual router name.
func (t *RoutingTable) Name() string { return t.name }

// Lookup partitions dst by longest-prefix match. Each returned Egress holds
// the addresses one route forwards; unrouted holds the rest. Among routes
// with the same prefix the lowest distance wins, then the lowest metric,
// then declaration order; the losers forward nothing.
func (t *RoutingTable) Lookup(dst traffic.AddressSet) (egress []Egress, unrouted traffic.AddressSet) {
	remaining := dst
	for _, e := range t.entries {
		if remaining.IsEmpty() {
			break
		}
		hit := remaining.Intersect(traffic.NewAddressSet(e.route.Destination))
		if hit.IsEmpty() {
			continue
		}
		remaining = remaining.Subtract(hit)
		egress = append(egress, Egress{Route: e.route, Connected: e.connected, Interface: e.iface, Zone: e.zone, Addresses: hit})
	}
	return egress, remaining
}

// buildRoutingTables compiles one table per virtual router and reports
// routes whose egress interface cannot be determined.
func buildRoutingTables(cfg *Config, ifaces map[string]Interface) (map[string]*RoutingTable, []Issue) {
	tables := make(map[string]*RoutingTable)
	table := func(vr string) *RoutingTable {
		if t, ok := tables[vr]; ok {
			return t
		}
		t := &RoutingTable{name: vr}
		tables[vr] = t
		return t
	}
	for _, vr := range cfg.VirtualRouters {
		table(vr.Name)
	}
	order := 0
	for _, i := range cfg.Interfaces {
		for _, p := range i.Addresses {
			t := table(i.VirtualRouter)
			r := Route{VirtualRouter: i.VirtualRouter, Destination: p.Masked(), Interface: i.Name}
			t.entries = append(t.entries, routeEntry{route: r, connected: true, iface: i.Name, zone: i.Zone, order: order})
			order++
		}
	}
	var issues []Issue
	for _, r := range cfg.Routes {
		t := table(r.VirtualRouter)
		iface := r.Interface
		if iface == "" {
			iface = nextHopInterface(t, r.NextHop)
		}
		if iface == "" && r.NextVirtualRouter == "" {
			issues = append(issues, Issue{Object: "route " + r.Destination.String(), Reason: "no interface reaches next hop " + r.NextHop.String()})
		}
		t.entries = append(t.entries, routeEntry{route: r, iface: iface, zone: ifaces[iface].Zone, order: order})
		order++
	}
	for _, t := range tables {
		slices.SortStableFunc(t.entries, func(a, b routeEntry) int {
			return cmp.Or(
				cmp.Compare(b.route.Destination.Bits(), a.route.Destination.Bits()),
				cmp.Compare(a.route.Distance, b.route.Distance),
				cmp.Compare(a.route.Metric, b.route.Metric),
				cmp.Compare(a.order, b.order),
			)
		})
	}
	return tables, issues
}

// nextHopInterface finds the connected interface whose subnet holds hop.
func nextHopInterface(t *RoutingTable, hop netip.Addr) string {
	if !hop.IsValid() {
		return ""
	}
	best, bits := "", -1
	for _, e := range t.entries {
		if e.connected && e.route.Destination.Contains(hop) && e.route.Destination.Bits() > bits {
			best, bits = e.iface, e.route.Destination.Bits()
		}
	}
	return best
}
