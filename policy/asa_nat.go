package policy

import (
	"context"
	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"net/netip"
	"strconv"
	"strings"
)

// asaNAT's sections are priority groups, not successive rewrites. The first
// selected manual, object or after-auto object terminates NAT selection.
func (e Engine) asaNAT(ctx context.Context, fw *fm.Firewall, q Request, budget *int) (NATResult, error) {
	steps, err := e.asaSteps(ctx, fw, q.Scope)
	if err != nil {
		return NATResult{}, err
	}
	return e.natChain(ctx, fw, q, steps, budget)
}

func (e Engine) asaSteps(ctx context.Context, fw *fm.Firewall, scope string) ([]NATStep, error) {
	if !modernASA(fw.Metadata().Software) {
		return nil, ErrNAT
	}
	entries := fw.NATSequence()
	if len(entries) > e.Limits.defaults().Rules {
		return nil, ErrBudget
	}
	var steps []NATStep
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if entry.Scope != scope {
			continue
		}
		if entry.Order.Stage < 1 || entry.Order.Stage > 3 || entry.Order.Section == "legacy" {
			return nil, ErrNAT
		}
		steps = append(steps, NATStep{Kind: entry.Kind, ID: entry.ID})
		if entry.Kind == fm.StaticNATObject && fw.StaticNAT(entry.ID).Record().Bidirectional {
			steps = append(steps, NATStep{Kind: entry.Kind, ID: entry.ID, Reverse: true})
		}
	}
	return steps, nil
}
func modernASA(version string) bool {
	version = strings.TrimPrefix(strings.TrimSpace(version), "ASA Version ")
	major, rest, ok := strings.Cut(version, ".")
	if !ok {
		return false
	}
	ma, err := strconv.Atoi(major)
	if err != nil {
		return false
	}
	end := 0
	for end < len(rest) && rest[end] >= '0' && rest[end] <= '9' {
		end++
	}
	mi, err := strconv.Atoi(rest[:end])
	if err != nil {
		return false
	}
	return ma == 9 || ma == 8 && mi >= 3
}
func inverseMappings(in []fm.Mapping) ([]fm.Mapping, bool) {
	out := make([]fm.Mapping, 0, len(in))
	known := true
	for _, m := range in {
		if m.Mode != fm.Identity && m.Mode != fm.Offset && !(m.Mode == fm.Constant && m.Original.First == m.Original.Last) {
			known = false
		}
		r := fm.Mapping{Original: m.Translated, Translated: m.Original, Mode: m.Mode}
		for _, prior := range out {
			if overlap, ok := prior.Original.Intersection(r.Original); ok {
				a, e := translate(overlap, prior)
				b, e2 := translate(overlap, r)
				if e != nil || e2 != nil || a != b {
					known = false
				}
			}
		}
		out = append(out, r)
	}
	return out, known
}
func inversePorts(in []fm.PortMapping) ([]fm.PortMapping, bool) {
	out := make([]fm.PortMapping, 0, len(in))
	known := true
	for _, m := range in {
		if m.Mode != fm.Identity && m.Mode != fm.Offset && !(m.Mode == fm.Constant && m.Original.Low == m.Original.High) {
			known = false
		}
		out = append(out, fm.PortMapping{Original: m.Translated, Translated: m.Original, Mode: m.Mode})
	}
	return out, known
}
func reverseStatic(n natTransform, r fm.StaticNATRecord) natTransform {
	forward := n
	n.inverseOf = &forward
	n.match = r.Match
	n.match.Sources, n.match.Destinations = r.Match.Destinations, r.Match.Sources
	n.match.AnySource, n.match.AnyDestination = r.Match.AnyDestination, r.Match.AnySource
	n.match.FromZones, n.match.ToZones = r.Match.ToZones, r.Match.FromZones
	n.match.AnyFromZone, n.match.AnyToZone = r.Match.AnyToZone, r.Match.AnyFromZone
	var known bool
	n.source, known = inverseMappings(r.Destination)
	n.known = n.known && known
	n.destination, known = inverseMappings(r.Source)
	n.known = n.known && known
	n.sourcePorts, known = inversePorts(r.DestinationPorts)
	n.known = n.known && known
	n.destinationPorts, known = inversePorts(r.SourcePorts)
	n.known = n.known && known
	return n
}
func allTraffic(limit int) (flow.Traffic, error) {
	var boxes []flow.Box
	for _, cidr := range []string{"0.0.0.0/0", "::/0"} {
		r, err := flow.PrefixRange(netip.MustParsePrefix(cidr))
		if err != nil {
			return flow.Traffic{}, err
		}
		boxes = append(boxes, flow.Box{Source: r, Destination: r, Protocol: flow.Interval{High: 255}, SourcePort: flow.Interval{High: 65535}, DestinationPort: flow.Interval{High: 65535}, ICMPType: flow.Interval{High: 255}, ICMPCode: flow.Interval{High: 255}})
	}
	return flow.NewTraffic(limit, boxes...)
}

// inverseMatch constructs the inverse domain from the complete forward match,
// including paired ports and both address axes. Swapping untransformed selectors
// alone would incorrectly discard public-address matches.
func (e Engine) inverseMatch(ctx context.Context, fw *fm.Firewall, n natTransform, q Request, input flow.Traffic) (flow.Traffic, bool, error) {
	limit := e.Limits.defaults().Regions
	all, err := allTraffic(limit)
	if err != nil {
		return flow.Traffic{}, false, err
	}
	forward := q
	forward.FromZone, forward.ToZone = q.ToZone, q.FromZone
	hit, known, err := e.Match(ctx, fw, n.inverseOf.match, forward, all)
	if err != nil {
		return flow.Traffic{}, false, err
	}
	hit, err = restrictMappings(hit, n.inverseOf.source, true, limit)
	if err != nil {
		return flow.Traffic{}, false, err
	}
	hit, err = restrictMappings(hit, n.inverseOf.destination, false, limit)
	if err != nil {
		return flow.Traffic{}, false, err
	}
	if hit.Empty() {
		return hit, known, nil
	}
	translated, _, _, err := n.inverseOf.apply(hit, limit)
	if err != nil {
		return flow.Traffic{}, false, err
	}
	boxes := translated.Boxes()
	for i := range boxes {
		boxes[i].Source, boxes[i].Destination = boxes[i].Destination, boxes[i].Source
		boxes[i].SourcePort, boxes[i].DestinationPort = boxes[i].DestinationPort, boxes[i].SourcePort
	}
	reversed, err := flow.NewTraffic(limit, boxes...)
	if err != nil {
		return flow.Traffic{}, false, err
	}
	hit, err = input.Intersection(reversed, limit)
	return hit, known, err
}
