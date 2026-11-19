package query

import (
	"net/netip"
	"slices"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/traffic"
)

// discoverTargets expands a request into its targets, the plain
// destination addresses and each destination domain, times each
// application, and discovers the paths of every target.
func (e *search) discoverTargets(req Request, table *firemon.RoutingTable) (paths []Path, unrouted traffic.AddressSet, incomplete bool) {
	apps := req.Applications
	if len(apps) == 0 {
		apps = []string{""}
	}
	for _, app := range apps {
		base := req
		base.Service = e.applicationService(req.Service, app)
		if !base.Dst.IsEmpty() {
			e.domain, e.resolved = "", false
			ps, lost, inc := e.discover(base, table)
			paths, unrouted, incomplete = append(paths, tag(ps, "", false, app)...), unrouted.Union(lost), incomplete || inc
		}
		for _, d := range req.DstDomains {
			e.domain, e.resolved = d, len(req.Resolved[d]) > 0
			ps, lost, inc := e.discoverDomain(base, table, d)
			paths, unrouted, incomplete = append(paths, tag(ps, d, len(req.Resolved[d]) > 0, app)...), unrouted.Union(lost), incomplete || inc
		}
	}
	return paths, unrouted, incomplete || e.incomplete
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
func (e *search) discoverDomain(req Request, table *firemon.RoutingTable, domain string) ([]Path, traffic.AddressSet, bool) {
	if addrs := req.Resolved[domain]; len(addrs) > 0 {
		var dst traffic.AddressSet
		for _, a := range addrs {
			dst = dst.Union(traffic.NewAddressSet(netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen())))
		}
		r := req
		r.Dst = dst
		return e.discover(r, table)
	}
	var paths []Path
	for _, fam := range []traffic.AddressSet{traffic.AnyIPv4(), traffic.AnyIPv6()} {
		r := req
		r.Src, r.Dst = req.Src.Intersect(fam), fam
		if r.Src.IsEmpty() {
			continue
		}
		for _, in := range e.ingress(r, table) {
			inTable := e.tableOf(in.vr, table)
			def, ok := e.defaultEgress(r, inTable, fam)
			if !ok {
				continue
			}
			// An unresolved name leaves by the default route, so its address
			// is one the default route forwards: not in any more specific route.
			pc := natPiece{original: traffic.Space{Src: in.addrs, Dst: def.addrs, Service: r.Service}}
			pc.translated = pc.original
			for _, rt := range e.policyRoute(pc, in) {
				out := def
				if rt.out != nil {
					if rt.out.iface == "" {
						continue
					}
					out = *rt.out
				}
				out.addrs = rt.piece.translated.Dst
				if !e.admit() {
					return paths, traffic.AddressSet{}, true
				}
				paths = append(paths, e.routedPath(in, out, rt))
			}
		}
	}
	return paths, traffic.AddressSet{}, false
}

// defaultEgress is where traffic to an unknown Internet address leaves: the
// interface of the default route, or the requested zone.
func (e *Engine) defaultEgress(req Request, table *firemon.RoutingTable, family traffic.AddressSet) (hop, bool) {
	if req.ToZone != "" {
		return hop{vr: tableName(table), zone: req.ToZone, prefixLen: -1, addrs: req.Dst}, true
	}
	if table == nil {
		return hop{}, false
	}
	egress, _ := table.Lookup(family)
	for _, g := range egress {
		if g.Route.Destination.Bits() == 0 && g.Interface != "" {
			return hop{vr: table.Name(), zone: g.Zone, iface: g.Interface, prefixLen: 0, addrs: g.Addresses}, true
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
	// certain is matched for sure when the rule is not decidable; empty
	// when nothing is.
	certain   traffic.Space
	decidable bool
	skip      bool // the rule certainly does not match this target
}

// ruleView adapts a rule to the target of path p: an application target
// skips rules for other applications and uses application default ports
// for application-default services; a domain target matches the rule's
// domain patterns by name and its addresses through the resolution.
func (e *Engine) ruleView(r *firemon.Rule, p *Path) view {
	v := view{match: r.Match(), bound: r.Bound(), decidable: r.DecidableFor(p.Domain != "", p.Application != "")}
	v.certain, _ = r.Certain()
	if p.Application != "" {
		if !r.MatchesApplication(p.Application) {
			return view{skip: true}
		}
		if r.DefaultPorts() {
			if ports, ok := e.fw.ApplicationPorts(p.Application); ok {
				v.match.Service, v.bound.Service = ports, ports
			} else {
				v.decidable = false
			}
		}
	}
	if p.Application == "" {
		if ports, ok := e.appPorts[r]; ok {
			v = appPortsView(v, r, ports, p)
			if v.skip {
				return v
			}
		}
	}
	if p.Domain == "" {
		return v
	}
	return domainView(v, r.DstDomains(), r.DecidableFor(true, p.Application != ""), p.Domain, p.DomainResolved, p.Policy.Dst)
}

// appPortsView narrows a rule that matches any service but only some
// applications to those applications' standard ports, for a target that
// names no application: traffic on other ports is taken not to be the
// application. Within the ports the rule stays a possible match, since a
// port alone does not identify an application. The path records the
// rule when the narrowing changed what it might match.
func appPortsView(v view, r *firemon.Rule, ports traffic.ServiceSet, p *Path) view {
	if v.bound.Overlaps(p.Policy) && !p.Policy.Service.Intersect(v.bound.Service).Subtract(ports).IsEmpty() &&
		!slices.ContainsFunc(p.AppPorts, func(a AppPorts) bool { return a.Rule == r }) {
		p.AppPorts = append(p.AppPorts, AppPorts{Rule: r, Ports: ports})
	}
	v.bound.Service = v.bound.Service.Intersect(ports)
	v.match.Service = v.match.Service.Intersect(ports)
	if v.bound.IsEmpty() {
		return view{skip: true}
	}
	return v
}

// domainView adapts the view of a rule or policy route to a domain target:
// its domain patterns match the name, its addresses match through the
// resolution, and an unresolved name, which leaves by the default route,
// may be any address that route forwards (dst).
func domainView(v view, patterns traffic.DomainSet, decidableByName bool, domain string, resolved bool, dst traffic.AddressSet) view {
	switch {
	case patterns.Match(domain):
		v.match.Dst, v.bound.Dst = traffic.AnyAddress(), traffic.AnyAddress()
		if !v.certain.IsEmpty() {
			v.certain.Dst = traffic.AnyAddress()
		}
	case resolved:
		// The addresses decide; other domain patterns do not cover this name.
	case v.match.Dst.ContainsSet(traffic.AnyIPv4()):
	case v.match.Dst.IsEmpty() && !patterns.IsEmpty():
		return view{skip: true} // domain-only entry for other names
	case !v.match.Dst.Overlaps(dst) && decidableByName:
		// The addresses are all routed elsewhere: the name cannot be one.
		return view{skip: true}
	default:
		// Addresses only: the unresolved name may or may not be one of them.
		v.bound.Dst, v.decidable, v.certain = traffic.AnyAddress(), false, traffic.Space{}
	}
	return v
}
