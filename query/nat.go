package query

import (
	"cmp"
	"net/netip"
	"slices"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/traffic"
)

// natPiece is part of a request with the translations decided for it.
type natPiece struct {
	original   traffic.Space
	translated traffic.Space
	dstHit     *NATHit
	srcHit     *NATHit
	mapped     *firemon.StaticMapping // inbound static mapping, for narrowing
	uncertain  []string               // NAT rules that may have matched
	skipped    []string               // disabled NAT rules that would have matched
	decided    bool
}

// originalDst returns the pre-NAT destinations of the translated part dst.
// One-to-one mappings narrow exactly; many-to-one translations keep every
// original destination.
func (pc natPiece) originalDst(dst traffic.AddressSet) traffic.AddressSet {
	switch {
	case pc.mapped != nil:
		return pc.mapped.ToMapped(dst)
	case pc.dstHit == nil:
		return dst
	default:
		return pc.original.Dst
	}
}

// natEntry is one position of a NAT rule list.
type natEntry struct {
	rule     *firemon.NATRule
	static   *firemon.StaticMapping
	inbound  bool // static mapping applied to the destination
	priority int
}

func (n natEntry) id() string {
	if n.rule != nil {
		return "nat " + n.rule.Spec().ID
	}
	return "static nat " + n.static.Spec().ID
}

// preEntries lists the NAT entries applied before routing: on single-order
// vendors every rule and both directions of every static mapping, by
// precedence; otherwise the destination-deciding rules and the inbound
// static mappings, statics first when the vendor says so.
func (e *Engine) preEntries() []natEntry {
	sem := e.fw.Semantics()
	var dyn, static []natEntry
	for _, n := range e.fw.NATRules() {
		if sem.NATOrder == firemon.NATOrderSingle || n.Translates(firemon.NATKindDestination) {
			dyn = append(dyn, natEntry{rule: n, priority: n.Spec().Precedence})
		}
	}
	for _, m := range e.fw.StaticNATs() {
		static = append(static, natEntry{static: m, inbound: true, priority: m.Spec().Precedence})
		if sem.NATOrder == firemon.NATOrderSingle && !m.Spec().InboundOnly {
			static = append(static, natEntry{static: m, priority: m.Spec().Precedence})
		}
	}
	if sem.NATOrder == firemon.NATOrderSingle {
		all := slices.Concat(dyn, static)
		slices.SortStableFunc(all, func(a, b natEntry) int { return cmp.Compare(a.priority, b.priority) })
		return all
	}
	if sem.StaticNATFirst {
		return slices.Concat(static, dyn)
	}
	return slices.Concat(dyn, static)
}

// translate applies the pre-routing NAT entries to base, first match per
// packet, and returns the resulting pieces.
func (e *Engine) translate(base traffic.Space, in hop, table *firemon.RoutingTable, req Request) []natPiece {
	work := []natPiece{{original: base, translated: base}}
	for _, en := range e.preEntries() {
		var next []natPiece
		for _, pc := range work {
			if pc.decided {
				next = append(next, pc)
				continue
			}
			next = append(next, e.matchEntry(en, pc, in, table, req)...)
		}
		work = next
	}
	return work
}

// matchEntry splits an undecided piece by one entry: matched parts are
// translated and decided, possibly matched parts carry the entry as
// uncertain, and the rest stays undecided.
func (e *Engine) matchEntry(en natEntry, pc natPiece, in hop, table *firemon.RoutingTable, req Request) []natPiece {
	if en.rule != nil && en.rule.Spec().Disabled && en.rule.AppliesFromIgnoringState(in.zone) && pc.original.Overlaps(en.rule.Match()) {
		pc.skipped = append(clip(pc.skipped), "nat "+en.rule.Spec().ID)
	}
	hit, maybe, miss := e.classify(en, pc.original, in, table, req)
	var out []natPiece
	for _, s := range hit {
		out = append(out, e.applyEntry(en, s, pc))
	}
	for _, s := range maybe {
		p := pc
		p.original, p.translated = s, s
		p.uncertain = append(slices.Clip(pc.uncertain), en.id())
		out = append(out, p)
	}
	for _, s := range miss {
		p := pc
		p.original, p.translated = s, s
		out = append(out, p)
	}
	return out
}

// classify partitions s into the packets the entry certainly matches, may
// match, and certainly does not match.
func (e *Engine) classify(en natEntry, s traffic.Space, in hop, table *firemon.RoutingTable, req Request) (hit, maybe, miss []traffic.Space) {
	var match, bound traffic.Space
	var from []string
	switch {
	case en.rule != nil:
		n := en.rule
		if !n.InVirtualRouter(in.vr) || n.Spec().Disabled {
			return nil, nil, []traffic.Space{s}
		}
		match, bound, from = n.Match(), n.Bound(), n.Spec().From
	case en.inbound:
		m := en.static
		if !m.Enabled() || !m.InVirtualRouter(in.vr) {
			return nil, nil, []traffic.Space{s}
		}
		match = traffic.Space{Src: traffic.AnyAddress(), Dst: m.Mapped(), Service: traffic.AnyService()}
		bound, from = match, m.Spec().Zones
	default:
		m := en.static
		if !m.Enabled() || !m.InVirtualRouter(in.vr) {
			return nil, nil, []traffic.Space{s}
		}
		match = traffic.Space{Src: m.Real(), Dst: traffic.AnyAddress(), Service: traffic.AnyService()}
		bound, from = match, m.Spec().From
	}
	fromYes, fromMaybe := zoneFits(from, in.zone)
	if !fromYes && !fromMaybe {
		return nil, nil, []traffic.Space{s}
	}
	miss = s.Subtract(bound)
	if en.rule != nil && !en.rule.Decidable() || fromMaybe {
		if c := s.Intersect(bound); !c.IsEmpty() {
			maybe = append(maybe, c)
		}
		return nil, maybe, miss
	}
	miss = append(miss, s.Intersect(bound).Subtract(match)...)
	cand := s.Intersect(match)
	if cand.IsEmpty() {
		return nil, nil, miss
	}
	h, m, x := e.toZoneCheck(en, cand, table, req)
	return h, m, append(miss, x...)
}

// toZoneCheck splits matched packets by the zone and interface their
// original destination routes to, against the entry's To zones and egress.
func (e *Engine) toZoneCheck(en natEntry, cand traffic.Space, table *firemon.RoutingTable, req Request) (hit, maybe, miss []traffic.Space) {
	var to []string
	egress := ""
	switch {
	case en.rule != nil:
		to, egress = en.rule.Spec().To, en.rule.Spec().Egress
	case !en.inbound:
		to = en.static.Spec().Zones
	}
	if len(to) == 0 && egress == "" {
		return []traffic.Space{cand}, nil, nil
	}
	for _, part := range e.splitDst(req, table, cand) {
		yes, unknown := zoneFits(to, part.zone)
		ifaceOK := egress == "" || part.iface == egress
		switch {
		case part.zone == "" && (len(to) > 0 || egress != ""):
			maybe = append(maybe, part.space)
		case yes && ifaceOK:
			hit = append(hit, part.space)
		case unknown:
			maybe = append(maybe, part.space)
		default:
			miss = append(miss, part.space)
		}
	}
	return hit, maybe, miss
}

// dstPart is part of a space with the zone its destination routes to.
type dstPart struct {
	zone, iface string
	space       traffic.Space
}

func (e *Engine) splitDst(req Request, table *firemon.RoutingTable, s traffic.Space) []dstPart {
	if req.ToZone != "" {
		return []dstPart{{zone: req.ToZone, space: s}}
	}
	hops, lost := e.route(table, s.Dst, 0)
	out := make([]dstPart, 0, len(hops)+1)
	for _, h := range hops {
		part := s
		part.Dst = h.addrs
		out = append(out, dstPart{zone: h.zone, iface: h.iface, space: part})
	}
	if !lost.IsEmpty() {
		part := s
		part.Dst = lost
		out = append(out, dstPart{space: part})
	}
	return out
}

// applyEntry translates a matched piece and marks it decided.
func (e *Engine) applyEntry(en natEntry, s traffic.Space, pc natPiece) natPiece {
	out := pc
	out.original, out.translated, out.decided = s, s, true
	switch {
	case en.rule != nil:
		n := en.rule
		if t := n.Translation(firemon.NATKindDestination); t.Mode != firemon.TranslationModeUnset && t.Mode != firemon.TranslationModeNone {
			d := n.Translated(firemon.NATKindDestination)
			if !d.IsEmpty() {
				out.translated.Dst = d
			}
			if t.Port != 0 {
				out.translated.Service = withPort(s.Service, t.Port)
			}
			out.dstHit = &NATHit{Rule: n, Side: firemon.NATKindDestination, Translated: out.translated.Dst, Position: n.Position(), Space: traffic.NewRegion(s)}
		}
		if t := n.Translation(firemon.NATKindSource); t.Mode != firemon.TranslationModeUnset && t.Mode != firemon.TranslationModeNone {
			out.srcHit = &NATHit{Rule: n, Side: firemon.NATKindSource, Translated: n.Translated(firemon.NATKindSource), Position: n.Position(), Space: traffic.NewRegion(s)}
		}
	case en.inbound:
		out.translated.Dst = en.static.ToReal(s.Dst)
		out.mapped = en.static
		out.dstHit = &NATHit{Static: en.static, Side: firemon.NATKindDestination, Translated: out.translated.Dst, Position: -1, Space: traffic.NewRegion(s)}
	default:
		out.srcHit = &NATHit{Static: en.static, Side: firemon.NATKindSource, Translated: en.static.ToMapped(s.Src), Position: -1, Space: traffic.NewRegion(s)}
	}
	return out
}

// sourceNAT applies the post-policy source NAT of separate-order vendors
// to one path: the first matching rule per packet, after routing.
func (e *Engine) sourceNAT(p *Path, s traffic.Space, in, out hop) {
	remaining := traffic.NewRegion(s)
	for _, n := range e.fw.NATRulesFor(firemon.NATKindSource) {
		if remaining.IsEmpty() {
			return
		}
		remaining = e.sourceNATRule(p, n, remaining, in, out)
	}
	for _, m := range e.fw.StaticNATs() {
		if !m.Spec().InboundOnly && m.InVirtualRouter(in.vr) && m.AppliesOutbound(in.zone, out.zone) {
			part := remaining.Intersect(traffic.Space{Src: m.Real(), Dst: traffic.AnyAddress(), Service: traffic.AnyService()})
			if !part.IsEmpty() {
				p.SourceNAT = append(p.SourceNAT, NATHit{Static: m, Side: firemon.NATKindSource, Translated: m.ToMapped(s.Src), Position: -1, Space: part})
			}
		}
	}
}

// sourceNATRule applies one source NAT rule to the untranslated rest of a
// path and returns what is left for later rules.
func (e *Engine) sourceNATRule(p *Path, n *firemon.NATRule, remaining traffic.Region, in, out hop) traffic.Region {
	spec := n.Spec()
	if !n.InVirtualRouter(in.vr) || (spec.Egress != "" && spec.Egress != out.iface) {
		return remaining
	}
	applies := zoneApplies(spec.From, spec.To, in.zone, out.zone)
	switch {
	case applies == appliesNo:
		return remaining
	case spec.Disabled:
		if applies == appliesYes && !remaining.Intersect(n.Match()).IsEmpty() {
			p.NATSkipped = append(p.NATSkipped, "nat "+spec.ID)
		}
		return remaining
	case applies == appliesMaybe || !n.Decidable():
		if !remaining.Intersect(n.Bound()).IsEmpty() {
			p.NATUncertain = append(p.NATUncertain, "nat "+spec.ID)
		}
		return remaining
	}
	hit := remaining.Intersect(n.Match())
	if hit.IsEmpty() {
		return remaining
	}
	if !n.Exempts() {
		t := n.Translated(firemon.NATKindSource)
		if t.IsEmpty() {
			t = e.interfaceAddresses(out.iface)
		}
		p.SourceNAT = append(p.SourceNAT, NATHit{Rule: n, Side: firemon.NATKindSource, Translated: t, Position: n.Position(), Space: hit})
	}
	return remaining.Subtract(n.Match())
}

func (e *Engine) interfaceAddresses(name string) traffic.AddressSet {
	ifc, _ := e.fw.Interface(name)
	var out traffic.AddressSet
	for _, p := range ifc.Addresses {
		out = out.Union(traffic.NewAddressSet(netip.PrefixFrom(p.Addr(), p.Addr().BitLen())))
	}
	return out
}

// withPort rewrites every port-carrying destination range of s to port;
// other protocols keep their destination.
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
