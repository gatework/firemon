package query

import (
	"net/netip"
	"slices"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/traffic"
)

// maxNextVR bounds next-vr recursion between routing tables.
const maxNextVR = 4

// hop is the part of an address set one interface reaches.
type hop struct {
	zone, iface string
	prefixLen   int // shortest route prefix reaching the addresses; -1 for a given zone
	addrs       traffic.AddressSet
}

// natPiece is part of a request with its destination translation.
type natPiece struct {
	original   traffic.Space
	translated traffic.Space
	hit        *NATHit
}

// discover splits req into paths by ingress route, destination NAT and
// egress route.
func (e *Engine) discover(req Request, table *firemon.RoutingTable) (paths []Path, unrouted traffic.AddressSet) {
	for _, in := range e.ingress(req, table) {
		base := traffic.Space{Src: in.addrs, Dst: req.Dst, Service: req.Service}
		for _, piece := range e.destinationNAT(base, in.zone, table) {
			outs, lost := e.egress(req, table, piece.translated.Dst)
			unrouted = unrouted.Union(lost)
			for _, out := range outs {
				paths = append(paths, e.path(in, out, piece))
			}
		}
	}
	return paths, unrouted
}

func (e *Engine) path(in, out hop, piece natPiece) Path {
	original := piece.original
	translated := piece.translated
	translated.Dst = out.addrs
	if piece.hit == nil {
		original.Dst = out.addrs
	}
	policy := translated
	if e.fw.Semantics().PolicyDestination == firemon.AddressStageOriginal {
		policy.Dst, policy.Service = original.Dst, original.Service
	}
	p := Path{
		From: in.zone, To: out.zone, Ingress: in.iface, Egress: out.iface, IngressPrefixLen: in.prefixLen, EgressPrefixLen: out.prefixLen,
		Original: original, Policy: policy, DestinationNAT: piece.hit,
	}
	p.SourceNAT = e.sourceNAT(translated, in.zone, out)
	return p
}

// ingress partitions the sources by the interface that routes back to them.
func (e *Engine) ingress(req Request, table *firemon.RoutingTable) []hop {
	if req.FromZone != "" {
		return []hop{{zone: req.FromZone, prefixLen: -1, addrs: req.Src}}
	}
	hops, lost := e.route(table, req.Src, 0)
	if !lost.IsEmpty() {
		hops = append(hops, hop{prefixLen: -1, addrs: lost}) // unknown zone
	}
	return hops
}

// egress partitions translated destinations by outgoing interface.
func (e *Engine) egress(req Request, table *firemon.RoutingTable, dst traffic.AddressSet) ([]hop, traffic.AddressSet) {
	if req.ToZone != "" {
		return []hop{{zone: req.ToZone, prefixLen: -1, addrs: dst}}, traffic.AddressSet{}
	}
	return e.route(table, dst, 0)
}

// route looks dst up in table, following next-vr hops.
func (e *Engine) route(table *firemon.RoutingTable, dst traffic.AddressSet, depth int) ([]hop, traffic.AddressSet) {
	if table == nil {
		return nil, dst
	}
	egress, lost := table.Lookup(dst)
	var hops []hop
	for _, g := range egress {
		next := g.Route.NextVirtualRouter
		if next == "" {
			if g.Interface == "" {
				lost = lost.Union(g.Addresses)
				continue
			}
			hops = append(hops, hop{zone: g.Zone, iface: g.Interface, prefixLen: g.Route.Destination.Bits(), addrs: g.Addresses})
			continue
		}
		nextTable, ok := e.fw.RoutingTable(next)
		if !ok || depth >= maxNextVR {
			lost = lost.Union(g.Addresses)
			continue
		}
		more, moreLost := e.route(nextTable, g.Addresses, depth+1)
		hops = append(hops, more...)
		lost = lost.Union(moreLost)
	}
	return mergeHops(hops), lost
}

// mergeHops joins hops through the same interface.
func mergeHops(hops []hop) []hop {
	var out []hop
	for _, h := range hops {
		i := slices.IndexFunc(out, func(o hop) bool { return o.iface == h.iface && o.zone == h.zone })
		if i < 0 {
			out = append(out, h)
			continue
		}
		out[i].addrs = out[i].addrs.Union(h.addrs)
		out[i].prefixLen = min(out[i].prefixLen, h.prefixLen)
	}
	return out
}

// destinationNAT applies the first matching destination NAT rule, then
// inbound static NAT, to each part of base.
func (e *Engine) destinationNAT(base traffic.Space, from string, table *firemon.RoutingTable) []natPiece {
	remaining := traffic.NewRegion(base)
	var out []natPiece
	for _, n := range e.fw.NATRules(firemon.NATKindDestination) {
		if !n.Decidable() || n.Translated().IsEmpty() || !e.natZoneMatches(n, from, table, n.Match().Dst) {
			continue
		}
		for _, s := range remaining.Intersect(n.Match()).Spaces() {
			translated := s
			translated.Dst = n.Translated()
			if port := n.Spec().Translated.Port; port != 0 {
				translated.Service = withPort(s.Service, port)
			}
			out = append(out, natPiece{original: s, translated: translated, hit: &NATHit{Rule: n, Translated: n.Translated()}})
		}
		remaining = remaining.Subtract(n.Match())
	}
	for _, m := range e.fw.StaticNATs() {
		if !m.Enabled() {
			continue
		}
		box := traffic.Space{Src: traffic.AnyAddress(), Dst: m.Mapped(), Service: traffic.AnyService()}
		for _, s := range remaining.Intersect(box).Spaces() {
			translated := s
			translated.Dst = m.ToReal(s.Dst)
			out = append(out, natPiece{original: s, translated: translated, hit: &NATHit{Static: m, Translated: translated.Dst}})
		}
		remaining = remaining.Subtract(box)
	}
	for _, s := range remaining.Spaces() {
		out = append(out, natPiece{original: s, translated: s})
	}
	return out
}

// natZoneMatches checks a NAT rule's zones: the ingress zone against From,
// and the zones the untranslated destination routes to against To.
func (e *Engine) natZoneMatches(n *firemon.NATRule, from string, table *firemon.RoutingTable, dst traffic.AddressSet) bool {
	spec := n.Spec()
	if spec.Disabled || (len(spec.From) > 0 && !slices.Contains(spec.From, from)) {
		return false
	}
	if len(spec.To) == 0 {
		return true
	}
	hops, _ := e.route(table, dst, 0)
	return slices.ContainsFunc(hops, func(h hop) bool { return slices.Contains(spec.To, h.zone) })
}

// sourceNAT reports the source translations of the translated traffic.
func (e *Engine) sourceNAT(s traffic.Space, from string, out hop) []NATHit {
	remaining := traffic.NewRegion(s)
	var hits []NATHit
	for _, n := range e.fw.NATRules(firemon.NATKindSource) {
		if remaining.IsEmpty() {
			break
		}
		if !n.Decidable() || !n.Applies(from, out.zone) || (n.Spec().Egress != "" && n.Spec().Egress != out.iface) {
			continue
		}
		if remaining.Intersect(n.Match()).IsEmpty() {
			continue
		}
		hits = append(hits, NATHit{Rule: n, Translated: e.snatAddresses(n, out.iface)})
		remaining = remaining.Subtract(n.Match())
	}
	for _, m := range e.fw.StaticNATs() {
		if m.Enabled() && !remaining.Intersect(traffic.Space{Src: m.Real(), Dst: traffic.AnyAddress(), Service: traffic.AnyService()}).IsEmpty() {
			hits = append(hits, NATHit{Static: m, Translated: m.ToMapped(s.Src)})
		}
	}
	return hits
}

func (e *Engine) snatAddresses(n *firemon.NATRule, egress string) traffic.AddressSet {
	if t := n.Translated(); !t.IsEmpty() || n.Spec().Translated.Mode != firemon.TranslationModeInterface {
		return t
	}
	ifc, _ := e.fw.Interface(egress)
	var out traffic.AddressSet
	for _, p := range ifc.Addresses {
		out = out.Union(traffic.NewAddressSet(netip.PrefixFrom(p.Addr(), p.Addr().BitLen())))
	}
	return out
}

// withPort rewrites every port-carrying destination range of s to port.
func withPort(s traffic.ServiceSet, port uint16) traffic.ServiceSet {
	var out traffic.ServiceSet
	for r := range s.All() {
		for p := int(r.ProtocolLow); p <= int(r.ProtocolHigh); p++ {
			proto := traffic.Protocol(p)
			if proto.HasPorts() {
				out = out.Union(traffic.NewService(proto, r.Src, traffic.Port(port)))
			} else {
				out = out.Union(traffic.NewService(proto, r.Src, r.Dst))
			}
		}
	}
	return out
}
