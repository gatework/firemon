package inventory

import (
	"cmp"
	"fmt"
	"net/netip"
	"slices"

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
	Parts     []Part
	Paths     []query.Path
	Src, Dst  traffic.AddressSet
	// Unrouted is the destination part the firewall has no route for.
	Unrouted traffic.AddressSet
	// Incomplete reports that a budget cut the evaluation short: the
	// verdict covers only part of the traffic and is indeterminate.
	Incomplete bool
	// ZonesNeeded reports layer-2 zones that routing cannot locate.
	ZonesNeeded bool
	Verdict     query.Verdict
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
		if c.ZonesNeeded && !slices.Contains(t.ZonesNeeded, cluster) {
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
	work := map[string]*assignment{}
	add := func(cluster string, o Ownership, p Part) {
		a := work[cluster]
		if a == nil {
			a = &assignment{ownership: o}
			work[cluster] = a
		}
		a.ownership = min(a.ownership, o)
		a.parts = append(a.parts, p)
	}
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
			inv.assignPair(sp, dp, p, add)
		}
	}
	return work, nil
}

func (inv *Inventory) assignPair(sp, dp owned, p Part, add func(string, Ownership, Part)) {
	if sp.cluster != "" {
		sp1 := p
		if sp.ownership == OwnershipDeclared {
			sp1.FromZone = sp.zone
		}
		if dp.cluster == sp.cluster && dp.ownership == OwnershipDeclared {
			sp1.ToZone = dp.zone
		}
		add(sp.cluster, sp.ownership, sp1)
		for _, transit := range inv.chain(sp.cluster, p) {
			if transit != dp.cluster {
				add(transit, OwnershipTransit, p)
			}
		}
	}
	if dp.cluster != "" && dp.cluster != sp.cluster {
		dp1 := p
		if dp.ownership == OwnershipDeclared {
			dp1.ToZone = dp.zone
		}
		add(dp.cluster, dp.ownership, dp1)
	}
}

// chain follows route next hops from a cluster toward the part's
// destinations and returns the clusters reached, in order.
func (inv *Inventory) chain(start string, p Part) []string {
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
		for _, next := range inv.nextHops(m, dst) {
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
func (inv *Inventory) nextHops(m *member, dst traffic.AddressSet) []string {
	table, ok := m.fw.RoutingTable(m.fw.Semantics().DefaultVirtualRouter)
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
	c := Crossing{Cluster: cluster, Firewall: m.name, Members: inv.clusterMembers(cluster), Ownership: a.ownership, Parts: a.parts}
	for _, p := range a.parts {
		r := req
		r.Src, r.Dst, r.DstDomains = p.Src, p.Dst, p.DstDomains
		r.FromZone, r.ToZone = cmp.Or(p.FromZone, req.FromZone), cmp.Or(p.ToZone, req.ToZone)
		res, err := m.engine.Query(r)
		if err != nil {
			return Crossing{}, fmt.Errorf("inventory: %s: %w", m.name, err)
		}
		c.Incomplete = c.Incomplete || res.Incomplete
		c.ZonesNeeded = c.ZonesNeeded || res.ZonesNeeded
		var crossing bool
		for _, path := range res.Paths {
			if crossesFirewall(path, p) {
				crossing = true
				c.Paths = append(c.Paths, path)
				c.Src, c.Dst = c.Src.Union(path.Original.Src), c.Dst.Union(path.Original.Dst)
			}
		}
		if crossing {
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
	var out []ClusterPlan
	for _, c := range t.Crossings {
		m := inv.primary(c.Cluster)
		for _, p := range c.Parts {
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
		if m.fw.Bridges() && !slices.Contains(t.ZonesNeeded, m.cluster) {
			t.ZonesNeeded = append(t.ZonesNeeded, m.cluster)
		}
	}
}
