package firemon

import (
	"cmp"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"sync"

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
	// NextHop is the directly reachable gateway after recursive resolution.
	NextHop   netip.Addr
	Addresses traffic.AddressSet
}

// RoutingTable is the compiled forwarding table of one virtual router:
// connected routes from interface addresses plus the static routes whose
// egress could be resolved, ordered for longest-prefix match.
type RoutingTable struct {
	name    string
	entries []routeEntry
	// dests are the entries' destinations as address sets, built once.
	dests []traffic.AddressSet
	// cache keeps recent lookups: design verification looks the same
	// destinations up again for every candidate change.
	mu    sync.Mutex
	cache map[string]lookup
}

// lookup is a cached Lookup result; callers must not modify it.
type lookup struct {
	egress   []Egress
	unrouted traffic.AddressSet
}

// maxLookups bounds the lookup cache; it is emptied when full.
const maxLookups = 4096

type routeEntry struct {
	route     Route
	connected bool
	exits     []routeExit
}

type routeExit struct {
	iface, zone string
	hop         netip.Addr
}

// Name returns the virtual router name.
func (t *RoutingTable) Name() string { return t.name }

// Lookup partitions dst by longest-prefix match. Each returned Egress holds
// the addresses one route forwards; unrouted holds the rest. Among routes
// with the same prefix the lowest distance wins, then the lowest metric;
// routes equal in all three share the traffic (equal-cost multipath) and
// each returns the same addresses.
func (t *RoutingTable) Lookup(dst traffic.AddressSet) (egress []Egress, unrouted traffic.AddressSet) {
	key := dst.String()
	t.mu.Lock()
	hit, ok := t.cache[key]
	t.mu.Unlock()
	if ok {
		return slices.Clone(hit.egress), hit.unrouted
	}
	egress, unrouted = t.lookup(dst)
	t.mu.Lock()
	if t.cache == nil || len(t.cache) >= maxLookups {
		t.cache = map[string]lookup{}
	}
	t.cache[key] = lookup{egress: slices.Clone(egress), unrouted: unrouted}
	t.mu.Unlock()
	return egress, unrouted
}

func (t *RoutingTable) lookup(dst traffic.AddressSet) (egress []Egress, unrouted traffic.AddressSet) {
	remaining := dst
	for i := 0; i < len(t.entries) && !remaining.IsEmpty(); {
		best := t.entries[i]
		j := i + 1
		for j < len(t.entries) && sameRank(t.entries[j], best) {
			j++
		}
		// Most routes touch none of the addresses: test before building.
		if dest := t.dest(i); remaining.Overlaps(dest) {
			hit := remaining.Intersect(dest)
			for _, e := range t.entries[i:j] {
				for _, exit := range e.exits {
					egress = append(egress, Egress{Route: e.route, Connected: e.connected, Interface: exit.iface, Zone: exit.zone, NextHop: exit.hop, Addresses: hit})
				}
			}
			remaining = remaining.Subtract(hit)
		}
		i = j
	}
	return egress, remaining
}

// Forward resolves dst to physical egresses in vr, following next-VR routes.
// A missing table, discard or forwarding loop loses exactly its branch's addresses.
func (fw *Firewall) Forward(vr string, dst traffic.AddressSet) ([]Egress, traffic.AddressSet) {
	return fw.forward(vr, dst, make(map[string]bool))
}

func (fw *Firewall) forward(vr string, dst traffic.AddressSet, visiting map[string]bool) ([]Egress, traffic.AddressSet) {
	table, ok := fw.RoutingTable(vr)
	if !ok || visiting[vr] {
		return nil, dst
	}
	visiting[vr] = true
	defer delete(visiting, vr)
	exits, lost := table.Lookup(dst)
	var out []Egress
	for _, e := range exits {
		switch {
		case e.Route.Discard:
			lost = lost.Union(e.Addresses)
		case e.Route.NextVirtualRouter != "":
			more, dropped := fw.forward(e.Route.NextVirtualRouter, e.Addresses, visiting)
			out = append(out, more...)
			lost = lost.Union(dropped)
		case e.Interface == "":
			lost = lost.Union(e.Addresses)
		default:
			out = append(out, e)
		}
	}
	return out, lost
}

// dest is the destination of entry i as an address set.
func (t *RoutingTable) dest(i int) traffic.AddressSet {
	if i < len(t.dests) {
		return t.dests[i]
	}
	return traffic.NewAddressSet(t.entries[i].route.Destination)
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
	for _, i := range cfg.Interfaces {
		for _, p := range i.Addresses {
			t := table(i.VirtualRouter)
			r := Route{VirtualRouter: i.VirtualRouter, Destination: p.Masked(), Interface: i.Name}
			t.entries = append(t.entries, routeEntry{route: r, connected: true})
		}
	}
	for _, r := range cfg.Routes {
		t := table(r.VirtualRouter)
		t.entries = append(t.entries, routeEntry{route: r})
	}
	var issues []Issue
	for _, name := range slices.Sorted(maps.Keys(tables)) {
		t := tables[name]
		issues = append(issues, t.install(ifaces)...)
	}
	return tables, issues
}

// install resolves recursive routes in two steps. First find which routes
// have a path to an interface. Then select the best installed routes to
// each gateway and propagate all their physical exits. A cycle without
// an exit never contributes an interface to the forwarding table.
func (t *RoutingTable) install(ifaces map[string]Interface) []Issue {
	slices.SortStableFunc(t.entries, func(a, b routeEntry) int {
		return cmp.Or(cmp.Compare(b.route.Destination.Bits(), a.route.Destination.Bits()),
			a.route.Destination.Addr().Compare(b.route.Destination.Addr()),
			cmp.Compare(a.route.Distance, b.route.Distance), cmp.Compare(a.route.Metric, b.route.Metric))
	})
	reachable, via := t.directExits(ifaces)
	closeReachability(reachable, via)
	t.preferBest(reachable, via)
	t.propagateExits(via)
	issues := t.dropUnresolved()
	t.dests = make([]traffic.AddressSet, len(t.entries))
	for i, e := range t.entries {
		t.dests[i] = traffic.NewAddressSet(e.route.Destination)
	}
	return issues
}

// directExits gives routes with an interface or no forwarding their exits,
// and lists for each next-hop route the routes that contain its next hop.
func (t *RoutingTable) directExits(ifaces map[string]Interface) (reachable []bool, via [][]int) {
	reachable = make([]bool, len(t.entries))
	via = make([][]int, len(t.entries))
	for i, e := range t.entries {
		switch r := e.route; {
		case r.Discard || r.NextVirtualRouter != "":
			t.entries[i].exits = []routeExit{{}}
		case r.Interface != "":
			t.entries[i].exits = []routeExit{{iface: r.Interface, zone: ifaces[r.Interface].Zone, hop: r.NextHop}}
			reachable[i] = true
		case r.NextHop.IsValid():
			for j, candidate := range t.entries {
				if j != i && candidate.route.Destination.Contains(r.NextHop) {
					via[i] = append(via[i], j)
				}
			}
		}
	}
	return reachable, via
}

// closeReachability marks a route reachable when a route to its next hop is.
func closeReachability(reachable []bool, via [][]int) {
	for changed := true; changed; {
		changed = false
		for i, candidates := range via {
			if !reachable[i] && slices.ContainsFunc(candidates, func(j int) bool { return reachable[j] }) {
				reachable[i], changed = true, true
			}
		}
	}
}

// preferBest keeps, for each next hop, the usable routes of the best rank.
func (t *RoutingTable) preferBest(reachable []bool, via [][]int) {
	for i, candidates := range via {
		best := candidates[:0]
		for _, j := range candidates {
			if !reachable[j] && len(t.entries[j].exits) == 0 {
				continue
			}
			if len(best) > 0 && !sameRank(t.entries[best[0]], t.entries[j]) {
				break
			}
			best = append(best, j)
		}
		via[i] = best
	}
}

// propagateExits gives next-hop routes the exits of the routes that reach
// their next hop, until nothing changes.
func (t *RoutingTable) propagateExits(via [][]int) {
	for changed := true; changed; {
		changed = false
		for i, candidates := range via {
			if t.inherit(i, candidates) {
				changed = true
			}
		}
	}
}

// inherit adds the interface exits of candidates to route i.
func (t *RoutingTable) inherit(i int, candidates []int) bool {
	e := &t.entries[i]
	changed := false
	for _, j := range candidates {
		for _, exit := range t.entries[j].exits {
			if exit.iface == "" {
				continue
			}
			if !exit.hop.IsValid() {
				exit.hop = e.route.NextHop
			}
			if !slices.Contains(e.exits, exit) {
				e.exits = append(e.exits, exit)
				changed = true
			}
		}
	}
	return changed
}

// dropUnresolved removes routes whose next hop no route reaches.
func (t *RoutingTable) dropUnresolved() []Issue {
	var issues []Issue
	t.entries = slices.DeleteFunc(t.entries, func(e routeEntry) bool {
		if len(e.exits) > 0 {
			return false
		}
		object := strings.TrimSpace("route " + t.name + " " + e.route.Destination.String())
		issues = append(issues, Issue{Kind: IssueKindConfig, Object: object, Reason: "not installed: no route reaches next hop " + e.route.NextHop.String()})
		return true
	})
	return issues
}
