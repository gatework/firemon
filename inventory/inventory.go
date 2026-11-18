package inventory

import (
	"cmp"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/design"
	"github.com/gatework/firemon/query"
	"github.com/gatework/firemon/traffic"
)

// ErrDuplicate reports two members with the same name.
var ErrDuplicate = errors.New("inventory: duplicate firewall name")

// Member is one firewall of the inventory.
type Member struct {
	Name     string
	Firewall *firemon.Firewall
}

// Options configures an Inventory. The zero value evaluates at time.Now.
type Options struct {
	Now func() time.Time
}

// Inventory is an immutable set of firewalls, safe for concurrent use.
type Inventory struct {
	members   []member
	byAddress map[netip.Addr][]string // interface address -> member names (HA pairs share)
	now       func() time.Time
}

type member struct {
	name    string
	fw      *firemon.Firewall
	engine  *query.Engine
	planner *design.Planner
}

// New returns an inventory of members, ordered by name.
func New(members []Member, opts Options) (*Inventory, error) {
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	inv := &Inventory{now: now, byAddress: map[netip.Addr][]string{}}
	for _, m := range members {
		if slices.ContainsFunc(inv.members, func(x member) bool { return x.name == m.Name }) {
			return nil, fmt.Errorf("%w: %q", ErrDuplicate, m.Name)
		}
		inv.members = append(inv.members, member{
			name: m.Name, fw: m.Firewall,
			engine:  query.New(m.Firewall, query.Options{Now: now}),
			planner: design.New(m.Firewall, design.Options{Now: now}),
		})
	}
	slices.SortFunc(inv.members, func(a, b member) int { return cmp.Compare(a.name, b.name) })
	for _, m := range inv.members {
		for _, ifc := range m.fw.Config().Interfaces {
			for _, p := range ifc.Addresses {
				if !slices.Contains(inv.byAddress[p.Addr()], m.name) {
					inv.byAddress[p.Addr()] = append(inv.byAddress[p.Addr()], m.name)
				}
			}
		}
	}
	return inv, nil
}

// Crossing is one firewall a request crosses and the part of the request
// that crosses it.
type Crossing struct {
	Firewall string
	// Paths are the crossing paths with their decisions.
	Paths []query.Path
	// Src and Dst bound the crossing part of the request.
	Src, Dst traffic.AddressSet
	Verdict  query.Verdict
}

// Trace is the evaluation of a request across the inventory.
type Trace struct {
	Crossings []Crossing
	// Verdict is allowed only when every crossed firewall allows its part.
	Verdict query.Verdict
}

// Locate evaluates req on every firewall and keeps those it crosses.
func (inv *Inventory) Locate(req query.Request) (Trace, error) {
	candidates, err := inv.candidates(req)
	if err != nil {
		return Trace{}, err
	}
	crossed := inv.crossed(req, candidates)
	var t Trace
	outcomes := map[query.Verdict]bool{}
	for _, c := range candidates {
		if !crossed[c.Firewall] {
			continue
		}
		for _, p := range c.Paths {
			c.Src, c.Dst = c.Src.Union(p.Original.Src), c.Dst.Union(p.Original.Dst)
		}
		c.Verdict = combine(c.Paths)
		outcomes[c.Verdict] = true
		t.Crossings = append(t.Crossings, c)
	}
	t.Verdict = overall(outcomes)
	return t, nil
}

// Plan designs, per crossed firewall, the change that permits the part of
// intent crossing it.
func (inv *Inventory) Plan(intent design.Intent) (map[string]*design.Plan, error) {
	t, err := inv.Locate(query.Request{Src: intent.Src, Dst: intent.Dst, Service: intent.Service, VirtualRouter: intent.VirtualRouter})
	if err != nil {
		return nil, err
	}
	plans := make(map[string]*design.Plan, len(t.Crossings))
	for _, c := range t.Crossings {
		m := inv.member(c.Firewall)
		part := intent
		part.Src, part.Dst = c.Src, c.Dst
		p, err := m.planner.Plan(part)
		if err != nil {
			return nil, fmt.Errorf("inventory: %s: %w", c.Firewall, err)
		}
		plans[c.Firewall] = p
	}
	return plans, nil
}

// crossed selects the firewalls on the path: the owners of the sources
// and of the destinations (most specific non-default route across the
// inventory), plus every firewall reached by following route next hops
// from the source owners toward the destinations.
func (inv *Inventory) crossed(req query.Request, candidates []Crossing) map[string]bool {
	bestSrc, bestDst := 0, 0
	for _, c := range candidates {
		for _, p := range c.Paths {
			bestSrc, bestDst = max(bestSrc, p.IngressPrefixLen), max(bestDst, p.EgressPrefixLen)
		}
	}
	out := map[string]bool{}
	var frontier []string
	for _, c := range candidates {
		for _, p := range c.Paths {
			if bestSrc > 0 && p.IngressPrefixLen == bestSrc && !out[c.Firewall] {
				out[c.Firewall] = true
				frontier = append(frontier, c.Firewall)
			}
			if bestDst > 0 && p.EgressPrefixLen == bestDst {
				out[c.Firewall] = true
			}
		}
	}
	isCandidate := func(name string) bool {
		return slices.ContainsFunc(candidates, func(c Crossing) bool { return c.Firewall == name })
	}
	for len(frontier) > 0 {
		m := inv.member(frontier[0])
		frontier = frontier[1:]
		for _, next := range inv.nextHops(m, req) {
			if !out[next] && isCandidate(next) {
				out[next] = true
				frontier = append(frontier, next)
			}
		}
	}
	return out
}

// nextHops returns the members whose interface addresses are next hops of
// m's routes toward the request destinations.
func (inv *Inventory) nextHops(m *member, req query.Request) []string {
	vr := cmp.Or(req.VirtualRouter, m.fw.Semantics().DefaultVirtualRouter)
	table, ok := m.fw.RoutingTable(vr)
	if !ok {
		return nil
	}
	egress, _ := table.Lookup(req.Dst)
	var out []string
	for _, e := range egress {
		if hop := e.Route.NextHop; hop.IsValid() {
			for _, owner := range inv.byAddress[hop] {
				if owner != m.name {
					out = append(out, owner)
				}
			}
		}
	}
	return out
}

// candidates returns, per firewall, the paths that enter and leave through
// different interfaces.
func (inv *Inventory) candidates(req query.Request) ([]Crossing, error) {
	var out []Crossing
	for _, m := range inv.members {
		if req.VirtualRouter == "" {
			if _, ok := m.fw.RoutingTable(m.fw.Semantics().DefaultVirtualRouter); !ok {
				continue // no routing context to locate with
			}
		}
		res, err := m.engine.Query(req)
		if err != nil {
			return nil, fmt.Errorf("inventory: %s: %w", m.name, err)
		}
		c := Crossing{Firewall: m.name}
		for _, p := range res.Paths {
			if p.Ingress != "" && p.Egress != "" && p.Ingress != p.Egress {
				c.Paths = append(c.Paths, p)
			}
		}
		if len(c.Paths) > 0 {
			out = append(out, c)
		}
	}
	return out, nil
}

func (inv *Inventory) member(name string) *member {
	i := slices.IndexFunc(inv.members, func(m member) bool { return m.name == name })
	return &inv.members[i]
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
