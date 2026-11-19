package inventory

import (
	"cmp"
	"fmt"
	"net/netip"
	"slices"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/design"
	"github.com/gatework/firemon/query"
	"github.com/gatework/firemon/traffic"
)

// Part is the piece of a request one cluster evaluates, with the zones its
// protected networks declare.
type Part struct {
	Src, Dst   traffic.AddressSet
	DstDomains []string
	FromZone   string
	ToZone     string
}

// Crossing is one cluster a request crosses.
type Crossing struct {
	Cluster string
	// Firewall is the member evaluated; Members lists the whole cluster.
	Firewall  string
	Members   []string
	Ownership Ownership
	// Basis says which ends of the request the cluster owns, and why.
	Basis []Basis
	// Parts are the parts assigned to the cluster; Crossed are those whose
	// traffic goes through the firewall, the only ones a design changes.
	Parts    []Part
	Crossed  []Part
	Paths    []query.Path
	Src, Dst traffic.AddressSet
	// Unrouted is the destination part the firewall has no route for.
	Unrouted traffic.AddressSet
	// Incomplete reports that a budget cut the evaluation short: the
	// verdict covers only part of the traffic and is indeterminate.
	Incomplete bool
	// ZonesNeeded reports layer-2 zones that routing cannot locate.
	ZonesNeeded bool
	// Inside are the parts that stay behind one interface.
	Inside  []Inside
	Verdict query.Verdict
}

// Excluded is the traffic no firewall of the inventory owns on either end.
type Excluded struct {
	Src, Dst traffic.AddressSet
}

// Trace is the evaluation of a request across the inventory.
type Trace struct {
	Crossings []Crossing
	Excluded  Excluded
	// Ambiguous lists address ranges several clusters claim equally; all of
	// them are evaluated.
	Ambiguous []string
	// ZonesNeeded lists clusters with layer-2 zones that the request did
	// not name zones for: traffic bridged through them is not located.
	ZonesNeeded []string
	// Inside lists parts whose ends are both behind one interface of a
	// cluster: the traffic does not cross it.
	Inside []Inside
	// Verdict is allowed only when every crossing allows its part.
	Verdict query.Verdict
}

// Locate finds the clusters req crosses and evaluates each on its part:
//
//   - the owners of the sources and of the destinations, declared protected
//     networks first, longest prefix across the inventory, then routing;
//   - transit clusters reached by route next hops from the source owners;
//   - traffic with neither end owned is excluded and reported.
func (inv *Inventory) Locate(req query.Request) (Trace, error) {
	var t Trace
	work, err := inv.assign(req, &t)
	if err != nil {
		return Trace{}, err
	}
	outcomes := map[query.Verdict]bool{}
	for _, cluster := range sortedKeys(work) {
		c, err := inv.evaluate(cluster, work[cluster], req)
		if err != nil {
			return Trace{}, err
		}
		t.Inside = append(t.Inside, c.Inside...)
		if c.ZonesNeeded && len(c.Paths) == 0 && !slices.Contains(t.ZonesNeeded, cluster) {
			t.ZonesNeeded = append(t.ZonesNeeded, cluster)
		}
		if len(c.Paths) == 0 && !c.Incomplete {
			continue
		}
		outcomes[c.Verdict] = true
		t.Crossings = append(t.Crossings, c)
	}
	t.Verdict = overall(outcomes)
	return t, nil
}

// assignment is the work of one cluster.
type assignment struct {
	ownership Ownership
	parts     []Part
	basis     []Basis
}

// Basis says why a request reaches a cluster: an end of it falls in
// networks the cluster owns.
type Basis struct {
	// Source is true for the source end, false for the destination.
	Source    bool
	Addresses traffic.AddressSet
	Zone      string
	// Networks are the owned networks the addresses fall in.
	Networks  []string
	Ownership Ownership
}

// basisOf is the basis an owned end gives its cluster.
func basisOf(o owned, source bool) Basis {
	return Basis{Source: source, Addresses: o.set, Zone: o.zone, Networks: o.networks, Ownership: o.ownership}
}

// works holds each cluster's assignment.
type works map[string]*assignment

// add assigns a part to a cluster, keeping its strongest ownership and
// merging the bases by end and zone.
func (w works) add(cluster string, o Ownership, p Part, basis ...Basis) {
	a := w[cluster]
	if a == nil {
		a = &assignment{ownership: o}
		w[cluster] = a
	}
	a.ownership = min(a.ownership, o)
	a.parts = append(a.parts, p)
	for _, b := range basis {
		i := slices.IndexFunc(a.basis, func(x Basis) bool { return x.Source == b.Source && x.Zone == b.Zone && x.Ownership == b.Ownership })
		if i < 0 {
			a.basis = append(a.basis, b)
			continue
		}
		a.basis[i].Addresses = a.basis[i].Addresses.Union(b.Addresses)
		for _, n := range b.Networks {
			if !slices.Contains(a.basis[i].Networks, n) {
				a.basis[i].Networks = append(a.basis[i].Networks, n)
			}
		}
	}
}

// assign splits req into parts per cluster.
func (inv *Inventory) assign(req query.Request, t *Trace) (map[string]*assignment, error) {
	srcParts, srcRest, amb1 := inv.owners(req.Src)
	dstParts, dstRest, amb2 := inv.owners(req.Dst)
	t.Ambiguous = slices.Concat(amb1, amb2)
	if !srcRest.IsEmpty() {
		srcParts = append(srcParts, owned{set: srcRest})
	}
	if !dstRest.IsEmpty() {
		dstParts = append(dstParts, owned{set: dstRest})
	}
	if len(req.DstDomains) > 0 {
		dstParts = append(dstParts, owned{}) // domains: owned by no firewall
	}
	work := works{}
	add := work.add
	for _, sp := range srcParts {
		for _, dp := range dstParts {
			p := Part{Src: sp.set, Dst: dp.set}
			if dp.set.IsEmpty() {
				p.DstDomains = req.DstDomains
			}
			if sp.cluster == "" && dp.cluster == "" {
				if only := inv.Clusters(); len(only) == 1 && req.FromZone != "" && req.ToZone != "" {
					zp := p
					zp.FromZone, zp.ToZone = req.FromZone, req.ToZone
					add(only[0], OwnershipZones, zp)
					continue
				}
				t.Excluded.Src, t.Excluded.Dst = t.Excluded.Src.Union(sp.set), t.Excluded.Dst.Union(dp.set)
				inv.bridgesMayCarry(t)
				continue
			}
			inv.assignPair(sp, dp, p, req.VirtualRouter, add)
		}
	}
	return work, nil
}

// assignPair assigns one source part and one destination part to the
// clusters that own them and to the transit clusters between. On each
// cluster an end's zone is the zone its addresses are bound to there,
// else the declared zone of its owner, else the firewall's routing
// decides; a layer-2 firewall without a binding for an end asks for one.
func (inv *Inventory) assignPair(sp, dp owned, p Part, vr string, add func(string, Ownership, Part, ...Basis)) {
	if sp.cluster != "" {
		from := ""
		if sp.ownership == OwnershipDeclared {
			from = sp.zone
		}
		if dp.cluster == sp.cluster && dp.ownership == OwnershipDeclared {
			q := p
			q.FromZone, q.ToZone = from, dp.zone
			add(sp.cluster, sp.ownership, q, basisOf(sp, true), basisOf(dp, false))
		} else {
			for _, z := range inv.zonesOf(sp.cluster, dp.set) {
				q := p
				q.Dst, q.FromZone, q.ToZone = z.set, from, z.zone
				add(sp.cluster, sp.ownership, q, basisOf(sp, true))
			}
		}
		for _, transit := range inv.chain(sp.cluster, p, vr) {
			if transit == dp.cluster {
				continue
			}
			for _, zs := range inv.zonesOf(transit, p.Src) {
				for _, zd := range inv.zonesOf(transit, p.Dst) {
					q := p
					q.Src, q.Dst, q.FromZone, q.ToZone = zs.set, zd.set, zs.zone, zd.zone
					add(transit, OwnershipTransit, q)
				}
			}
		}
	}
	if dp.cluster != "" && dp.cluster != sp.cluster {
		to := ""
		if dp.ownership == OwnershipDeclared {
			to = dp.zone
		}
		for _, z := range inv.zonesOf(dp.cluster, sp.set) {
			q := p
			q.Src, q.FromZone, q.ToZone = z.set, z.zone, to
			add(dp.cluster, dp.ownership, q, basisOf(dp, false))
		}
	}
}

// chain follows route next hops from a cluster toward the part's
// destinations and returns the clusters reached, in order.
func (inv *Inventory) chain(start string, p Part, vr string) []string {
	dst := p.Dst
	if dst.IsEmpty() {
		dst = traffic.NewAddressSet(netip.MustParsePrefix("0.0.0.0/0")) // domains leave by default
	}
	seen := map[string]bool{start: true}
	frontier := []string{start}
	var out []string
	for len(frontier) > 0 && len(out) < len(inv.members) {
		m := inv.primary(frontier[0])
		frontier = frontier[1:]
		for _, next := range inv.nextHops(m, dst, vr) {
			if !seen[next] {
				seen[next] = true
				out = append(out, next)
				frontier = append(frontier, next)
			}
		}
	}
	return out
}

// nextHops returns the clusters whose interface addresses are next hops of
// m's routes toward dst.
func (inv *Inventory) nextHops(m *member, dst traffic.AddressSet, vr string) []string {
	table, ok := m.fw.RoutingTable(vr)
	if !ok {
		// The requested routing context exists only on some members.
		table, ok = m.fw.RoutingTable(m.fw.Semantics().DefaultVirtualRouter)
	}
	if !ok {
		return nil
	}
	egress, _ := table.Lookup(dst)
	var out []string
	for _, e := range egress {
		if hop := e.Route.NextHop; hop.IsValid() {
			for _, c := range inv.byAddress[hop] {
				if c != m.cluster && !slices.Contains(out, c) {
					out = append(out, c)
				}
			}
		}
	}
	return out
}

// evaluate queries every part of one cluster on its primary member and
// keeps the paths that cross the firewall.
func (inv *Inventory) evaluate(cluster string, a *assignment, req query.Request) (Crossing, error) {
	m := inv.primary(cluster)
	c := Crossing{Cluster: cluster, Firewall: m.name, Members: inv.clusterMembers(cluster), Ownership: a.ownership, Parts: a.parts, Basis: a.basis}
	for _, p := range a.parts {
		if p.FromZone != "" && p.FromZone == p.ToZone && m.fw.ZoneInterfaces(p.FromZone) == 1 {
			// Both ends behind one interface: the traffic does not cross.
			c.Inside = append(c.Inside, Inside{Cluster: cluster, Zone: p.FromZone, Src: p.Src, Dst: p.Dst})
			continue
		}
		r := req
		r.Src, r.Dst, r.DstDomains = p.Src, p.Dst, p.DstDomains
		r.FromZone, r.ToZone = cmp.Or(p.FromZone, req.FromZone), cmp.Or(p.ToZone, req.ToZone)
		if halfBridged(m.fw, r.FromZone, r.ToZone) {
			// One end is in a layer-2 zone and nothing binds the other:
			// routing (management only) cannot tell where it is.
			c.ZonesNeeded = true
			continue
		}
		res, err := m.engine.Query(r)
		if err != nil {
			return Crossing{}, fmt.Errorf("inventory: %s: %w", m.name, err)
		}
		c.Incomplete = c.Incomplete || res.Incomplete
		c.ZonesNeeded = c.ZonesNeeded || res.ZonesNeeded
		var crossing bool
		for _, path := range res.Paths {
			// Zones named by the request count as declared too: the path
			// then has no interfaces to compare.
			if crossesFirewall(path, Part{FromZone: r.FromZone, ToZone: r.ToZone}) {
				crossing = true
				c.Paths = append(c.Paths, path)
				c.Src, c.Dst = c.Src.Union(path.Original.Src), c.Dst.Union(path.Original.Dst)
			}
		}
		if crossing {
			c.Crossed = append(c.Crossed, p)
			c.Unrouted = c.Unrouted.Union(res.Unrouted)
		}
	}
	c.Verdict = combine(c.Paths)
	switch {
	case c.Incomplete:
		c.Verdict = query.VerdictIndeterminate
	case !c.Unrouted.IsEmpty() && c.Verdict == query.VerdictAllowed:
		c.Verdict = query.VerdictPartial // the unrouted part is dropped
	case !c.Unrouted.IsEmpty() && c.Verdict == query.VerdictUnset:
		c.Verdict = query.VerdictDenied
	}
	return c, nil
}

// crossesFirewall reports whether a path goes through the firewall: it
// enters and leaves through different interfaces, or its zones were
// declared.
func crossesFirewall(p query.Path, part Part) bool {
	if part.FromZone != "" || part.ToZone != "" {
		return true
	}
	return p.Ingress != "" && p.Egress != "" && p.Ingress != p.Egress
}

// Plan designs, per crossed cluster and part, the change that permits the
// part of intent crossing it.
func (inv *Inventory) Plan(intent design.Intent) ([]ClusterPlan, error) {
	t, err := inv.Locate(query.Request{
		Src: intent.Src, Dst: intent.Dst, Service: intent.Service, VirtualRouter: intent.VirtualRouter,
		FromZone: intent.FromZone, ToZone: intent.ToZone,
	})
	if err != nil {
		return nil, err
	}
	return inv.PlanTrace(t, intent)
}

// PlanTrace is Plan on a trace Locate already computed for intent: only
// the parts that cross a firewall are designed, so traffic that stays
// behind one interface or is not routed through the firewall gets no rule.
func (inv *Inventory) PlanTrace(t Trace, intent design.Intent) ([]ClusterPlan, error) {
	var out []ClusterPlan
	for _, c := range t.Crossings {
		m := inv.primary(c.Cluster)
		for _, p := range c.Crossed {
			part := intent
			part.Src, part.Dst = p.Src, p.Dst
			part.FromZone, part.ToZone = cmp.Or(p.FromZone, intent.FromZone), cmp.Or(p.ToZone, intent.ToZone)
			plan, err := m.planner.Plan(part)
			if err != nil {
				return nil, fmt.Errorf("inventory: %s: %w", c.Cluster, err)
			}
			out = append(out, ClusterPlan{Cluster: c.Cluster, Firewall: m.name, Part: p, Plan: plan})
		}
	}
	return out, nil
}

// ClusterPlan is the plan of one part on one cluster.
type ClusterPlan struct {
	Cluster  string
	Firewall string
	Part     Part
	Plan     *design.Plan
}

func combine(paths []query.Path) query.Verdict {
	outcomes := map[query.Verdict]bool{}
	for _, p := range paths {
		outcomes[p.Verdict] = true
	}
	return overall(outcomes)
}

func overall(v map[query.Verdict]bool) query.Verdict {
	switch {
	case len(v) == 0:
		return query.VerdictUnset
	case v[query.VerdictIndeterminate]:
		return query.VerdictIndeterminate
	case len(v) == 1 && v[query.VerdictAllowed]:
		return query.VerdictAllowed
	case len(v) == 1 && v[query.VerdictDenied]:
		return query.VerdictDenied
	default:
		return query.VerdictPartial
	}
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, cmp.Compare)
	return keys
}

// bridgesMayCarry notes the clusters with layer-2 interfaces: excluded
// traffic may still cross them, bridged rather than routed.
func (inv *Inventory) bridgesMayCarry(t *Trace) {
	for _, m := range inv.members {
		if m.fw.Bridges() && !inv.declared(m.cluster) && !slices.Contains(t.ZonesNeeded, m.cluster) {
			t.ZonesNeeded = append(t.ZonesNeeded, m.cluster)
		}
	}
}

// Inside is traffic both of whose ends are behind one interface of a
// cluster's zone.
type Inside struct {
	Cluster  string
	Zone     string
	Src, Dst traffic.AddressSet
}

// declared reports whether a cluster declares protected networks, which
// locate it without routing.
func (inv *Inventory) declared(cluster string) bool {
	return slices.ContainsFunc(inv.claims, func(c claim) bool { return c.cluster == cluster && c.ownership == OwnershipDeclared })
}

// halfBridged reports a part with one end in a layer-2 zone and the other
// end's zone unknown.
func halfBridged(fw *firemon.Firewall, from, to string) bool {
	if (from == "") == (to == "") {
		return false
	}
	z, ok := fw.Zone(cmp.Or(from, to))
	return ok && z.Mode == firemon.ZoneModeLayer2
}
