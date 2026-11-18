package query

import (
	"net/netip"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/traffic"
)

// discoverTargets expands a request into its targets, the plain
// destination addresses and each destination domain, times each
// application, and discovers the paths of every target.
func (e *Engine) discoverTargets(req Request, table *firemon.RoutingTable) (paths []Path, unrouted traffic.AddressSet, incomplete bool) {
	apps := req.Applications
	if len(apps) == 0 {
		apps = []string{""}
	}
	for _, app := range apps {
		base := req
		base.Service = e.applicationService(req.Service, app)
		if !base.Dst.IsEmpty() {
			ps, lost, inc := e.discover(base, table)
			paths, unrouted, incomplete = append(paths, tag(ps, "", false, app)...), unrouted.Union(lost), incomplete || inc
		}
		for _, d := range req.DstDomains {
			ps, inc := e.discoverDomain(base, table, d)
			paths, incomplete = append(paths, tag(ps, d, len(req.Resolved[d]) > 0, app)...), incomplete || inc
		}
	}
	return paths, unrouted, incomplete
}

// applicationService is the service evaluated for an application target:
// the requested service, or the application's default ports when the
// request leaves the service open.
func (e *Engine) applicationService(s traffic.ServiceSet, app string) traffic.ServiceSet {
	if app == "" || !s.IsAny() {
		return s
	}
	if ports, ok := e.fw.ApplicationPorts(app); ok && !ports.IsEmpty() {
		return ports
	}
	return s
}

// discoverDomain routes a domain target by its resolved addresses, or
// through the default route when they are unknown.
func (e *Engine) discoverDomain(req Request, table *firemon.RoutingTable, domain string) ([]Path, bool) {
	if addrs := req.Resolved[domain]; len(addrs) > 0 {
		var dst traffic.AddressSet
		for _, a := range addrs {
			dst = dst.Union(traffic.NewAddressSet(netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen())))
		}
		r := req
		r.Dst = dst
		ps, _, inc := e.discover(r, table)
		return ps, inc
	}
	var paths []Path
	for _, fam := range []traffic.AddressSet{traffic.AnyIPv4()} {
		r := req
		r.Src, r.Dst = req.Src.Intersect(fam), fam
		if r.Src.IsEmpty() {
			continue
		}
		for _, in := range e.ingress(r, table) {
			inTable := e.tableOf(in.vr, table)
			out, ok := e.defaultEgress(r, inTable)
			if !ok {
				continue
			}
			pc := natPiece{original: traffic.Space{Src: in.addrs, Dst: fam, Service: r.Service}}
			pc.translated = pc.original
			if len(paths) >= e.maxPaths {
				return paths, true
			}
			paths = append(paths, e.path(in, out, pc))
		}
	}
	return paths, false
}

// defaultEgress is where traffic to an unknown Internet address leaves: the
// interface of the default route, or the requested zone.
func (e *Engine) defaultEgress(req Request, table *firemon.RoutingTable) (hop, bool) {
	if req.ToZone != "" {
		return hop{vr: tableName(table), zone: req.ToZone, prefixLen: -1, addrs: req.Dst}, true
	}
	hops, _ := e.route(table, traffic.NewAddressSet(netip.PrefixFrom(netip.IPv4Unspecified(), 0)), 0)
	for _, h := range hops {
		if h.prefixLen == 0 {
			h.addrs = req.Dst
			return h, true
		}
	}
	return hop{}, false
}

func tag(paths []Path, domain string, resolved bool, app string) []Path {
	for i := range paths {
		paths[i].Domain, paths[i].DomainResolved, paths[i].Application = domain, resolved, app
	}
	return paths
}

// view is how one rule matches one path's target.
type view struct {
	match, bound traffic.Space
	decidable    bool
	skip         bool // the rule certainly does not match this target
}

// ruleView adapts a rule to the target of path p: an application target
// skips rules for other applications and uses application default ports
// for application-default services; a domain target matches the rule's
// domain patterns by name and its addresses through the resolution.
func (e *Engine) ruleView(r *firemon.Rule, p *Path) view {
	v := view{match: r.Match(), bound: r.Bound(), decidable: r.DecidableFor(p.Domain != "", p.Application != "")}
	if p.Application != "" {
		if !r.MatchesApplication(p.Application) {
			return view{skip: true}
		}
		if r.Spec().ApplicationDefault {
			if ports, ok := e.fw.ApplicationPorts(p.Application); ok {
				v.match.Service, v.bound.Service = ports, ports
			} else {
				v.decidable = false
			}
		}
	}
	if p.Domain == "" {
		return v
	}
	switch {
	case r.DstDomains().Match(p.Domain):
		v.match.Dst, v.bound.Dst = traffic.AnyAddress(), traffic.AnyAddress()
	case p.DomainResolved:
		// The rule's addresses decide; its other domain patterns do not
		// cover this name.
	case v.match.Dst.ContainsSet(traffic.AnyIPv4()):
	case v.match.Dst.IsEmpty() && !r.DstDomains().IsEmpty():
		return view{skip: true} // domain-only rule for other names
	default:
		// Addresses only: the unresolved name may or may not be one of them.
		v.bound.Dst, v.decidable = traffic.AnyAddress(), false
	}
	return v
}
