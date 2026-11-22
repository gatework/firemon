package query

import (
	"slices"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/traffic"
)

// hop is the part of an address set one interface reaches.
type hop struct {
	vr          string // routing context of the interface
	zone, iface string
	prefixLen   int // shortest route prefix reaching the addresses; -1 when unknown or given
	addrs       traffic.AddressSet
}

// discover splits req into paths: by address family, by the interface
// that routes back to the sources, by NAT, and by the egress interface of
// the (translated) destinations. It stops adding paths at the budget.
func (e *search) discover(req Request, table *firemon.RoutingTable) (paths []Path, unrouted traffic.AddressSet, incomplete bool) {
	for _, fam := range families(req) {
		for _, in := range e.ingress(fam, table) {
			inTable := e.tableOf(in.vr, table)
			base := traffic.Space{Src: in.addrs, Dst: fam.Dst, Service: fam.Service}
			for _, pc := range e.translate(base, in, inTable, fam) {
				for _, rt := range e.policyRoute(pc, in) {
					outs, lost := e.routedEgress(fam, inTable, rt)
					unrouted = unrouted.Union(lost)
					for _, out := range outs {
						if !e.admit() {
							return paths, unrouted, true
						}
						paths = append(paths, e.routedPath(in, out, rt))
					}
				}
			}
		}
	}
	return paths, unrouted, false
}

// families splits a request into its IPv4 and IPv6 parts. Traffic always
// keeps its family, so an IPv4 source never reaches an IPv6 destination.
func families(req Request) []Request {
	var out []Request
	for _, all := range []traffic.AddressSet{traffic.AnyIPv4(), traffic.AnyIPv6()} {
		f := req
		f.Src, f.Dst = req.Src.Intersect(all), req.Dst.Intersect(all)
		if !f.Src.IsEmpty() && !f.Dst.IsEmpty() {
			out = append(out, f)
		}
	}
	return out
}

func (e *Engine) tableOf(vr string, fallback *firemon.RoutingTable) *firemon.RoutingTable {
	if t, ok := e.fw.RoutingTable(vr); ok {
		return t
	}
	return fallback
}

func (e *Engine) path(in, out hop, pc natPiece) Path {
	translated := pc.translated
	translated.Dst = out.addrs
	original := pc.original
	original.Dst = pc.originalDst(out.addrs)
	policy := translated
	if e.fw.Semantics().PolicyDestination == firemon.AddressStageOriginal {
		policy.Dst, policy.Service = original.Dst, original.Service
	}
	p := Path{
		From: in.zone, To: out.zone, Ingress: in.iface, Egress: out.iface,
		VirtualRouter: in.vr, EgressVirtualRouter: out.vr,
		IngressPrefixLen: in.prefixLen, EgressPrefixLen: out.prefixLen,
		Original: original, Policy: policy, Translated: translated, DestinationNAT: pc.dstHit, NATUncertain: slices.Clone(pc.uncertain),
		NATSkipped: slices.Clone(pc.skipped),
	}
	if pc.srcHit != nil {
		hit := *pc.srcHit
		if hit.Translated.IsEmpty() && hit.Rule != nil {
			hit.Translated = e.interfaceAddresses(out.iface)
		}
		p.SourceNAT = []NATHit{hit}
	}
	if e.fw.Semantics().NATOrder != firemon.NATOrderSingle {
		e.sourceNAT(&p, translated, in, out)
	}
	return p
}

// routedEgress is the egress of a routed part: the policy route's, or the
// routing table's.
func (e *Engine) routedEgress(req Request, table *firemon.RoutingTable, rt routed) ([]hop, traffic.AddressSet) {
	if rt.out == nil {
		return e.egress(req, table, rt.piece.translated.Dst)
	}
	if rt.out.iface == "" {
		return nil, rt.piece.translated.Dst // next hop unreachable: dropped
	}
	h := *rt.out
	h.addrs = rt.piece.translated.Dst
	return []hop{h}, traffic.AddressSet{}
}

// routedPath builds the path of a routed part.
func (e *Engine) routedPath(in, out hop, rt routed) Path {
	p := e.path(in, out, rt.piece)
	p.Conditions = rt.conditions
	if rt.out != nil {
		p.PolicyRoute = rt.policy
	}
	return p
}

// ingress partitions the sources by the interface that routes back to them.
func (e *Engine) ingress(req Request, table *firemon.RoutingTable) []hop {
	if req.FromZone != "" {
		return []hop{{vr: tableName(table), zone: req.FromZone, prefixLen: -1, addrs: req.Src}}
	}
	hops, lost := e.route(table, req.Src)
	if !lost.IsEmpty() {
		hops = append(hops, hop{vr: tableName(table), prefixLen: -1, addrs: lost}) // unknown zone
	}
	return hops
}

// egress partitions translated destinations by outgoing interface.
func (e *Engine) egress(req Request, table *firemon.RoutingTable, dst traffic.AddressSet) ([]hop, traffic.AddressSet) {
	if req.ToZone != "" {
		return []hop{{vr: tableName(table), zone: req.ToZone, prefixLen: -1, addrs: dst}}, traffic.AddressSet{}
	}
	return e.route(table, dst)
}

// route looks dst up in table, following next-vr hops. Discarded and
// unrouted addresses are returned as lost.
func (e *Engine) route(table *firemon.RoutingTable, dst traffic.AddressSet) ([]hop, traffic.AddressSet) {
	if table == nil {
		return nil, dst
	}
	exits, lost := e.fw.Forward(table.Name(), dst)
	hops := make([]hop, 0, len(exits))
	for _, g := range exits {
		hops = append(hops, hop{vr: g.Route.VirtualRouter, zone: g.Zone, iface: g.Interface, prefixLen: g.Route.Destination.Bits(), addrs: g.Addresses})
	}
	return mergeHops(hops), lost
}

// mergeHops joins hops through the same interface.
func mergeHops(hops []hop) []hop {
	var out []hop
	for _, h := range hops {
		i := slices.IndexFunc(out, func(o hop) bool { return o.iface == h.iface && o.zone == h.zone && o.vr == h.vr })
		if i < 0 {
			out = append(out, h)
			continue
		}
		out[i].addrs = out[i].addrs.Union(h.addrs)
		out[i].prefixLen = min(out[i].prefixLen, h.prefixLen)
	}
	return out
}

func tableName(t *firemon.RoutingTable) string {
	if t == nil {
		return ""
	}
	return t.Name()
}
