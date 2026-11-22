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
	for _, t := range e.appTargets(req) {
		base := req
		base.Service = t.service
		if !base.Dst.IsEmpty() {
			e.domain, e.resolved = "", false
			ps, lost, inc := e.discover(base, table)
			paths, unrouted, incomplete = append(paths, t.tag(ps, "", false)...), unrouted.Union(lost), incomplete || inc
		}
		for _, d := range req.DstDomains {
			e.domain, e.resolved = d, len(req.Resolved[d]) > 0
			ps, lost, inc := e.discoverDomain(base, table, d)
			paths, unrouted, incomplete = append(paths, t.tag(ps, d, len(req.Resolved[d]) > 0)...), unrouted.Union(lost), incomplete || inc
		}
	}
	return paths, unrouted, incomplete || e.incomplete
}

// appTarget is the application a part of the request is evaluated as.
type appTarget struct {
	service      traffic.ServiceSet
	app          string   // named or inferred application; empty when several or none
	family       []string // applications matched against rules
	inferred     bool
	unidentified bool
}

func (t appTarget) tag(paths []Path, domain string, resolved bool) []Path {
	for i := range paths {
		p := &paths[i]
		p.Domain, p.DomainResolved, p.Application = domain, resolved, t.app
		p.AppFamily, p.AppInferred, p.AppUnidentified = slices.Clone(t.family), t.inferred, t.unidentified
	}
	return paths
}

// appTargets splits a request by application. Named applications are
// targets of their own. Otherwise, unless the request is strict, the
// service is split by the standard application of its ports; parts that
// every application rule of the firewall treats alike are evaluated
// together, so a wide service costs one path per distinct treatment.
func (e *Engine) appTargets(req Request) []appTarget {
	if len(req.Applications) > 0 {
		out := make([]appTarget, len(req.Applications))
		for i, app := range req.Applications {
			out[i] = appTarget{service: e.applicationService(req.Service, app), app: app}
		}
		return out
	}
	if req.Strict || (len(e.appRules) == 0 && !e.urlRules) {
		return []appTarget{{service: req.Service}}
	}
	var out []appTarget
	var keys []string
	for _, g := range e.fw.IdentifyApplications(req.Service) {
		key := e.appSignature(g.Apps)
		if g.Unidentified() {
			key += "?" // unknown applications may match only here
		} else if e.urlRules && !e.webApps(g.Apps) {
			key += "-" // URL categories cannot match
		}
		i := slices.Index(keys, key)
		if i < 0 {
			keys = append(keys, key)
			out = append(out, appTarget{inferred: true})
			i = len(out) - 1
		}
		t := &out[i]
		t.service = t.service.Union(g.Service)
		t.family = append(t.family, g.Apps...)
		t.unidentified = t.unidentified || g.Unidentified()
		if t.app == "" && len(g.Apps) > 0 && !t.unidentified && len(t.family) == len(g.Apps) {
			t.app = g.Apps[0]
		} else if len(t.family) != len(g.Apps) || t.unidentified {
			t.app = ""
		}
	}
	return out
}

// appSignature names the application rules that admit one of apps: parts
// of a request with the same signature are decided alike.
func (e *Engine) appSignature(apps []string) string {
	b := make([]byte, (len(e.appRules)+7)/8)
	for i, r := range e.appRules {
		if r.MatchesAnyApplication(apps) {
			b[i/8] |= 1 << (i % 8)
		}
	}
	return string(b)
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

// view is how one rule matches one path's target.
type view struct {
	match, bound traffic.Space
	// certain is matched for sure when the rule is not decidable; empty
	// when nothing is.
	certain   traffic.Space
	decidable bool
	skip      bool // the rule certainly does not match this target
	// assumed: the rule is skipped because a criterion the request did not
	// give is taken not to hold (a premise of the result).
	assumed bool
	// domainPremise: the rule is undecidable only by domain names it may
	// resolve to; its certain part decides, and the rest is taken not to
	// match an address target (a premise).
	domainPremise bool
}

// ruleView adapts a rule to the target of path p: an application target
// skips rules for other applications and uses application default ports
// for application-default services; a domain target matches the rule's
// domain patterns by name and its addresses through the resolution.
func (e *Engine) ruleView(r *firemon.Rule, p *Path) view {
	apps := p.matchApps()
	named := len(apps) > 0 || p.AppUnidentified
	v := view{match: r.Match(), bound: r.Bound(), decidable: r.DecidableFor(p.Domain != "", named)}
	v.certain, _ = r.Certain()
	unknownApp := false
	if named {
		if !r.MatchesAnyApplication(apps) {
			if !p.AppUnidentified || !e.unknownApps[r] {
				return view{skip: true}
			}
			// An application the book does not know may use any port the
			// book leaves unclaimed.
			v.decidable, v.certain, unknownApp = false, traffic.Space{}, true
		}
		if r.DefaultPorts() && v.decidable {
			if ports, ok := e.admittedPorts(r, apps); ok {
				v.match.Service, v.bound.Service = ports, ports
			} else {
				v.decidable = false
			}
		}
	} else if ports, ok := e.appPorts[r]; ok {
		v = appPortsView(v, r, ports, p)
		if v.skip {
			return v
		}
	}
	if v = e.conditionView(r, p, v, named); v.skip {
		return v
	}
	if p.Domain == "" {
		if !v.decidable && !p.strict && !unknownApp && byDomain(r) && r.DecidableWithout(e.settledKinds(named)...) {
			v.domainPremise = true
		}
		return v
	}
	return domainView(v, r.DstDomains(), r.DecidableFor(true, named), p.Domain, p.DomainResolved, p.Policy.Dst)
}

// matchApps are the applications a path is matched as: the family of an
// inferred target, the named application, or none.
func (p *Path) matchApps() []string {
	if len(p.AppFamily) > 0 {
		return p.AppFamily
	}
	if p.Application != "" {
		return []string{p.Application}
	}
	return nil
}

// admittedPorts are the standard ports of the applications of apps that
// an application-default rule admits; false when one is unknown.
func (e *Engine) admittedPorts(r *firemon.Rule, apps []string) (traffic.ServiceSet, bool) {
	var out traffic.ServiceSet
	for _, a := range apps {
		if !r.MatchesApplication(a) {
			continue
		}
		ports, ok := e.fw.ApplicationPorts(a)
		if !ok || ports.IsEmpty() {
			return traffic.ServiceSet{}, false
		}
		out = out.Union(ports)
	}
	return out, !out.IsEmpty()
}

// appPortsView applies a rule's application-default service to a port-only
// request. Inside that service, application identification remains unknown.
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
