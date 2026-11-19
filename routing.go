package firemon

import (
	"cmp"
	"net/netip"
	"slices"
	"strings"

	"github.com/gatework/firemon/traffic"
)

// Egress is the part of a destination set one route forwards, with the
// interface and zone the traffic leaves through. A route to another
// virtual router has no interface; Route.NextVirtualRouter names the table
// to continue the lookup in. A discard route has neither.
type Egress struct {
	Route     Route
	Connected bool
	Interface string
	Zone      string
	Addresses traffic.AddressSet
}

// RoutingTable is the compiled forwarding table of one virtual router:
// connected routes from interface addresses plus the static routes whose
// egress could be resolved, ordered for longest-prefix match.
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
	recursive bool // the interface was resolved through the next hop
}

// Name returns the virtual router name.
func (t *RoutingTable) Name() string { return t.name }

// Lookup partitions dst by longest-prefix match. Each returned Egress holds
// the addresses one route forwards; unrouted holds the rest. Among routes
// with the same prefix the lowest distance wins, then the lowest metric;
// routes equal in all three share the traffic (equal-cost multipath) and
// each returns the same addresses.
func (t *RoutingTable) Lookup(dst traffic.AddressSet) (egress []Egress, unrouted traffic.AddressSet) {
	remaining := dst
	for i := 0; i < len(t.entries) && !remaining.IsEmpty(); {
		best := t.entries[i]
		hit := remaining.Intersect(traffic.NewAddressSet(best.route.Destination))
		j := i
		for ; j < len(t.entries) && sameRank(t.entries[j], best); j++ {
			if hit.IsEmpty() {
				continue
			}
			e := t.entries[j]
			egress = append(egress, Egress{Route: e.route, Connected: e.connected, Interface: e.iface, Zone: e.zone, Addresses: hit})
		}
		remaining = remaining.Subtract(hit)
		i = j
	}
	return egress, remaining
}

func sameRank(a, b routeEntry) bool {
	return a.route.Destination == b.route.Destination && a.route.Distance == b.route.Distance && a.route.Metric == b.route.Metric
}

// buildRoutingTables compiles one table per virtual router. A static route
// whose next hop no connected subnet or other resolved route reaches is not
// installed, as on the device, and is reported.
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
	pending := make([]routeEntry, 0, len(cfg.Routes))
	for _, r := range cfg.Routes {
		pending = append(pending, routeEntry{route: r, iface: r.Interface, zone: ifaces[r.Interface].Zone, order: order})
		order++
	}
	// Resolve next hops recursively: a pass installs every route whose next
	// hop the installed routes reach, until nothing changes.
	for changed := true; changed; {
		changed = false
		next := pending[:0]
		for _, e := range pending {
			t := table(e.route.VirtualRouter)
			if !installable(&e, t, ifaces) {
				next = append(next, e)
				continue
			}
			t.entries = append(t.entries, e)
			changed = true
		}
		pending = next
	}
	for _, t := range tables {
		t.settle(ifaces)
	}
	var issues []Issue
	for _, e := range pending {
		// The routing context names the route: the same destination is
		// often configured in several virtual routers.
		object := strings.TrimSpace("route " + e.route.VirtualRouter + " " + e.route.Destination.String())
		issues = append(issues, Issue{Kind: IssueKindConfig, Object: object, Reason: "not installed: no route reaches next hop " + e.route.NextHop.String()})
	}
	for _, t := range tables {
		slices.SortStableFunc(t.entries, func(a, b routeEntry) int {
			return cmp.Or(
				cmp.Compare(b.route.Destination.Bits(), a.route.Destination.Bits()),
				// Same-length prefixes stay together, so equal-cost routes
				// declared apart are found as one group.
				a.route.Destination.Addr().Compare(b.route.Destination.Addr()),
				cmp.Compare(a.route.Distance, b.route.Distance),
				cmp.Compare(a.route.Metric, b.route.Metric),
				cmp.Compare(a.order, b.order),
			)
		})
	}
	return tables, issues
}

// installable resolves the egress of a static route and reports whether
// the route can be installed now.
func installable(e *routeEntry, t *RoutingTable, ifaces map[string]Interface) bool {
	switch {
	case e.route.Discard, e.route.NextVirtualRouter != "", e.iface != "":
		return true
	case !e.route.NextHop.IsValid():
		return false
	}
	iface := t.resolve(e.route.NextHop)
	if iface == "" {
		return false
	}
	e.iface, e.zone, e.recursive = iface, ifaces[iface].Zone, true
	return true
}

// settle re-resolves recursive next hops against the whole table until
// they no longer change, so the result does not depend on the order in
// which routes became installable: a more specific route installed later
// wins, as on the device.
func (t *RoutingTable) settle(ifaces map[string]Interface) {
	for range len(t.entries) + 1 {
		changed := false
		for i := range t.entries {
			e := &t.entries[i]
			if !e.recursive {
				continue
			}
			if iface := t.resolveExcept(e.route.NextHop, i); iface != "" && iface != e.iface {
				e.iface, e.zone, changed = iface, ifaces[iface].Zone, true
			}
		}
		if !changed {
			return
		}
	}
}

// resolve returns the egress interface of the most specific installed route
// containing hop.
func (t *RoutingTable) resolve(hop netip.Addr) string { return t.resolveExcept(hop, -1) }

// resolveExcept is resolve ignoring entry skip, a route that cannot
// resolve its own next hop.
func (t *RoutingTable) resolveExcept(hop netip.Addr, skip int) string {
	best, bits := "", -1
	for i, e := range t.entries {
		if i != skip && e.iface != "" && e.route.Destination.Contains(hop) && e.route.Destination.Bits() > bits {
			best, bits = e.iface, e.route.Destination.Bits()
		}
	}
	return best
}
