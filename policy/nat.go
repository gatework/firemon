package policy

import (
	"context"
	"errors"
	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"math/big"
	"net/netip"
)

var ErrNAT = errors.New("NAT semantics are not established for this operation")

// NATStep identifies one selected object in a native pipeline. Reverse is the
// implicit destination mapping of a bidirectional StaticNAT, never a session lookup.
type NATStep struct {
	Kind    fm.Kind
	ID      fm.ID
	Reverse bool
}
type NATRelation struct {
	Kind                      fm.Kind
	ID                        fm.ID
	Steps                     []NATStep
	Original, Translated      flow.Traffic
	Exact, PossibleAllocation bool
}
type NATResult struct {
	Relations          []NATRelation
	Unmatched, Unknown flow.Traffic
	Complete           bool
}

// QueryNAT evaluates new-session translation using the vendor's selection order.
// Dynamic allocation describes possibilities, not an observed session binding.
func (e Engine) QueryNAT(ctx context.Context, fw *fm.Firewall, q Request) (NATResult, error) {
	if err := ctx.Err(); err != nil {
		return NATResult{}, err
	}
	if fw == nil {
		return NATResult{}, ErrNAT
	}
	for _, d := range fw.Diagnostics() {
		if d.Object == "" {
			return NATResult{Unknown: q.Traffic}, nil
		}
	}
	budget := e.Limits.defaults().Rules
	switch fw.Metadata().Vendor {
	case "hillstone":
		return e.hillstoneNAT(ctx, fw, q, &budget)
	case "asa":
		return e.asaNAT(ctx, fw, q, &budget)
	case "srx":
		return e.srxNAT(ctx, fw, q, &budget)
	case "netscreen":
		return e.netscreenNAT(ctx, fw, q, &budget)
	case "fortinet":
		return e.fortinetNAT(ctx, fw, q, &budget)
	case "huawei":
		return e.huaweiNAT(ctx, fw, q, &budget)
	case "paloalto":
		entries := fw.NATSequence()
		if len(entries) > e.Limits.defaults().Rules {
			return NATResult{}, ErrBudget
		}
		steps := make([]NATStep, 0, len(entries))
		var stage int
		haveStage := false
		for _, entry := range entries {
			if entry.Scope != q.Scope {
				continue
			}
			if haveStage && entry.Order.Stage != stage {
				return NATResult{}, ErrNAT
			}
			stage, haveStage = entry.Order.Stage, true
			if entry.Kind == fm.StaticNATObject {
				r := fw.StaticNAT(entry.ID).Record()
				if r.Bidirectional && !r.Disabled && reverseDomainIntersects(q.Traffic, r) {
					return NATResult{}, ErrNAT
				}
			}
			steps = append(steps, NATStep{Kind: entry.Kind, ID: entry.ID})
		}
		return e.natChain(ctx, fw, q, steps, &budget)
	default:
		return NATResult{}, ErrNAT
	}
}

// natTransform is an ephemeral execution view of the separate typed catalogs.
// It is not a domain object and is never persisted or exposed by Firewall.
type natTransform struct {
	match                         fm.Match
	source, destination           []fm.Mapping
	sourcePorts, destinationPorts []fm.PortMapping
	dynamic                       *fm.DynamicNAT
	disabled, known               bool
	egress                        fm.ID
	inverseOf                     *natTransform
}

func transform(fw *fm.Firewall, step NATStep) (natTransform, error) {
	n := natTransform{known: true}
	objectKnown := true
	for _, d := range fw.Diagnostics() {
		if d.Object == step.ID {
			objectKnown = false
			break
		}
	}
	switch step.Kind {
	case fm.StaticNATObject:
		object := fw.StaticNAT(step.ID)
		if object == nil {
			return n, ErrNAT
		}
		r := object.Record()
		n.match, n.source, n.destination = r.Match, r.Source, r.Destination
		n.sourcePorts, n.destinationPorts = r.SourcePorts, r.DestinationPorts
		n.disabled, n.known = r.Disabled, len(r.Unsupported) == 0 && objectKnown
		if fw.Metadata().Vendor == "hillstone" && !r.Bidirectional {
			n.egress = r.Interface
		}
		if step.Reverse {
			if fw.Metadata().Vendor == "asa" || fw.Metadata().Vendor == "srx" || fw.Metadata().Vendor == "netscreen" || fw.Metadata().Vendor == "huawei" {
				return reverseStatic(n, r), nil
			}
			// StoneOS BNAT is unconditional one-to-one source mapping, with an implicit
			// inverse destination mapping. Extra selectors have no established inverse.
			n.known = n.known && r.Bidirectional && len(r.Source) > 0 && len(r.Destination) == 0 &&
				len(r.SourcePorts) == 0 && len(r.DestinationPorts) == 0 && r.Interface == "" &&
				r.Match.AnyDestination && r.Match.AnyService && r.Match.AnyFromZone && r.Match.AnyToZone &&
				r.Match.Schedule == "" && len(r.Match.Applications) == 0 && len(r.Match.Users) == 0 && len(r.Match.Unsupported) == 0
			n.match = fm.Match{AnySource: true, AnyDestination: true, AnyService: true, AnyFromZone: true, AnyToZone: true}
			n.source, n.destination, n.sourcePorts, n.destinationPorts = nil, nil, nil, nil
			for _, m := range r.Source {
				if m.Mode != fm.Offset && m.Mode != fm.Identity {
					n.known = false
				}
				n.destination = append(n.destination, fm.Mapping{Original: m.Translated, Translated: m.Original, Mode: m.Mode})
			}
		}
	case fm.DynamicNATObject:
		n.dynamic = fw.DynamicNAT(step.ID)
		if n.dynamic == nil || step.Reverse {
			return n, ErrNAT
		}
		r := n.dynamic.Record()
		n.match, n.destination = r.Match, r.Destination
		n.sourcePorts, n.destinationPorts = r.SourcePorts, r.DestinationPorts
		n.disabled = r.Disabled
		n.known = len(r.Unsupported) == 0 && objectKnown && r.SourceMode != fm.UnknownTranslation && r.DestinationMode != fm.UnknownTranslation
		// Hillstone eif constrains selection. PAN interface-address is an allocation
		// target and is intentionally not treated as a match predicate here.
		if fw.Metadata().Vendor == "hillstone" {
			n.egress = r.Interface
		}
		if fw.Metadata().Vendor == "huawei" {
			if r.Order.Section == "nat-policy" {
				n.egress = r.Interface
			}
			for _, pool := range []*fm.NATPool{n.dynamic.SourcePool(), n.dynamic.DestinationPool()} {
				if pool != nil {
					n.known = n.known && len(pool.Record().Unsupported) == 0
				}
			}
			if r.SourceMode == fm.InterfaceIP {
				iface := n.dynamic.Interface()
				n.known = n.known && iface != nil
				if iface != nil {
					n.known = n.known && !iface.Record().Disabled && len(iface.Record().Unsupported) == 0 && len(iface.Record().Addresses) == 1
				}
			}
		}
		if fw.Metadata().Vendor == "netscreen" && r.SourceMode == fm.InterfaceIP && len(n.sourcePorts) == 0 {
			// ScreenOS reserves the well-known ports for both DIP and interface PAT.
			// Allocation remains possible, not an exact observed session binding.
			n.sourcePorts = []fm.PortMapping{{Original: flow.Interval{High: 65535}, Translated: flow.Interval{Low: 1024, High: 65535}, Mode: fm.Constant}}
		}
	default:
		return n, ErrNAT
	}
	return n, nil
}
func (n natTransform) apply(input flow.Traffic, limit int) (flow.Traffic, bool, bool, error) {
	out, err := mapTraffic(input, n.source, true, limit)
	if err != nil {
		return flow.Traffic{}, false, false, err
	}
	out, err = mapTraffic(out, n.destination, false, limit)
	if err != nil {
		return flow.Traffic{}, false, false, err
	}
	exact, possible := true, false
	if n.dynamic != nil {
		out, exact, possible, err = allocate(out, n.dynamic, limit)
		if err != nil {
			return flow.Traffic{}, false, false, err
		}
	}
	out, err = mapPorts(out, n.sourcePorts, true, limit)
	if err != nil {
		return flow.Traffic{}, false, false, err
	}
	out, err = mapPorts(out, n.destinationPorts, false, limit)
	return out, exact, possible, err
}
func (e Engine) natChain(ctx context.Context, fw *fm.Firewall, q Request, steps []NATStep, budget *int) (NATResult, error) {
	limit := e.Limits.defaults().Regions
	out := NATResult{Complete: true}
	remaining := q.Traffic
	for _, step := range steps {
		if err := ctx.Err(); err != nil {
			return NATResult{}, err
		}
		if remaining.Empty() {
			break
		}
		if *budget <= 0 {
			return NATResult{}, ErrBudget
		}
		*budget--
		n, err := transform(fw, step)
		if err != nil {
			return NATResult{}, err
		}
		if n.disabled {
			continue
		}
		var hit flow.Traffic
		var certain bool
		if n.inverseOf != nil {
			hit, certain, err = e.inverseMatch(ctx, fw, n, q, remaining)
		} else {
			hit, certain, err = e.Match(ctx, fw, n.match, q, remaining)
		}
		if err != nil {
			return NATResult{}, err
		}
		hit, err = restrictMappings(hit, n.source, true, limit)
		if err != nil {
			return NATResult{}, err
		}
		hit, err = restrictMappings(hit, n.destination, false, limit)
		if err != nil {
			return NATResult{}, err
		}
		if hit.Empty() {
			continue
		}
		if n.egress != "" {
			if q.EgressInterface != "" && q.EgressInterface != n.egress {
				continue
			}
			iface := fw.Interface(n.egress)
			certain = certain && q.EgressInterface != "" && iface != nil
			if iface != nil {
				certain = certain && !iface.Record().Disabled && len(iface.Record().Unsupported) == 0
			}
		}
		active, timeKnown := schedule(fw, n.match.Schedule, q.At)
		if timeKnown && !active {
			continue
		}
		known := n.known && certain && timeKnown
		var translated flow.Traffic
		exact, possible := false, false
		if known {
			translated, exact, possible, err = n.apply(hit, limit)
			if errors.Is(err, flow.ErrBudget) {
				return NATResult{}, err
			}
			if err != nil {
				known = false
			}
		}
		if !known {
			out.Unknown, err = out.Unknown.Union(hit, limit)
			out.Complete = false
		} else {
			if len(out.Relations) >= limit {
				return NATResult{}, ErrBudget
			}
			out.Relations = append(out.Relations, NATRelation{Kind: step.Kind, ID: step.ID, Steps: []NATStep{step}, Original: hit, Translated: translated, Exact: exact, PossibleAllocation: possible})
		}
		if err != nil {
			return NATResult{}, err
		}
		remaining, err = remaining.Difference(hit, limit)
		if err != nil {
			return NATResult{}, err
		}
	}
	out.Unmatched = remaining
	return out, nil
}
func translate(r flow.Range, m fm.Mapping) (flow.Range, error) {
	overlap, ok := r.Intersection(m.Original)
	if !ok || overlap != r {
		return flow.Range{}, ErrNAT
	}
	switch m.Mode {
	case fm.Identity:
		return r, nil
	case fm.Constant:
		return m.Translated, nil
	case fm.Offset:
		first, err := offset(r.First, m.Original.First, m.Translated.First)
		if err != nil {
			return flow.Range{}, err
		}
		last, err := offset(r.Last, m.Original.First, m.Translated.First)
		if err != nil {
			return flow.Range{}, err
		}
		return flow.Range{First: first, Last: last}, nil
	default:
		return flow.Range{}, ErrNAT
	}
}
func offset(a, base, target netip.Addr) (netip.Addr, error) {
	av, bv, tv := a.As16(), base.As16(), target.As16()
	n := new(big.Int).Sub(new(big.Int).SetBytes(av[:]), new(big.Int).SetBytes(bv[:]))
	n.Add(n, new(big.Int).SetBytes(tv[:]))
	if n.Sign() < 0 || n.BitLen() > 128 {
		return netip.Addr{}, ErrNAT
	}
	var bytes [16]byte
	n.FillBytes(bytes[:])
	result := netip.AddrFrom16(bytes)
	if a.Is4() {
		result = result.Unmap()
		if !result.Is4() {
			return netip.Addr{}, ErrNAT
		}
	}
	return result, nil
}
func mapTraffic(input flow.Traffic, mappings []fm.Mapping, source bool, limit int) (flow.Traffic, error) {
	if len(mappings) == 0 {
		return input, nil
	}
	var result flow.Traffic
	for _, box := range input.Boxes() {
		original := box.Destination
		if source {
			original = box.Source
		}
		set, _ := flow.NewSet(original)
		var covered flow.Set
		for _, m := range mappings {
			part, ok := original.Intersection(m.Original)
			if !ok {
				continue
			}
			translated, err := translate(part, m)
			if err != nil {
				return flow.Traffic{}, err
			}
			piece := box
			if source {
				piece.Source = translated
			} else {
				piece.Destination = translated
			}
			traffic, err := flow.NewTraffic(limit, piece)
			if err != nil {
				return flow.Traffic{}, err
			}
			result, err = result.Union(traffic, limit)
			if err != nil {
				return flow.Traffic{}, err
			}
			r, _ := flow.NewSet(part)
			covered = covered.Union(r)
		}
		if !covered.Contains(set) {
			return flow.Traffic{}, ErrNAT
		}
	}
	return result, nil
}
func allocate(input flow.Traffic, n *fm.DynamicNAT, limit int) (flow.Traffic, bool, bool, error) {
	r := n.Record()
	if r.SourceMode == fm.NoTranslation && r.DestinationMode == fm.NoTranslation {
		return input, true, false, nil
	}
	if r.DestinationMode != fm.NoTranslation && len(r.Destination) == 0 {
		return flow.Traffic{}, false, false, ErrNAT
	}
	if r.SourceMode == fm.NoTranslation {
		return input, true, false, nil
	}
	var targets []flow.Range
	if pool := n.SourcePool(); pool != nil {
		targets = pool.Record().Ranges
	}
	if r.SourceMode == fm.InterfaceIP {
		if n.Interface() == nil {
			return flow.Traffic{}, false, false, ErrNAT
		}
		if r.InterfaceAddress.IsValid() {
			targets = []flow.Range{{First: r.InterfaceAddress, Last: r.InterfaceAddress}}
		} else {
			for _, p := range n.Interface().Record().Addresses {
				targets = append(targets, flow.Range{First: p.Addr(), Last: p.Addr()})
			}
		}
	}
	if len(targets) == 0 {
		return flow.Traffic{}, false, false, ErrNAT
	}
	if r.SourceMode == fm.StaticIP {
		return flow.Traffic{}, false, false, ErrNAT
	} // Equal pool size does not establish an offset relation.
	var out flow.Traffic
	for _, box := range input.Boxes() {
		for _, target := range targets {
			if box.Source.First.BitLen() != target.First.BitLen() {
				continue
			}
			piece := box
			piece.Source = target
			if r.SourceMode == fm.DynamicIPPort || r.SourceMode == fm.InterfaceIP {
				piece.SourcePort = flow.Interval{Low: 0, High: 65535}
				if pool := n.SourcePool(); pool != nil && pool.Record().Ports != (flow.Interval{}) {
					piece.SourcePort = pool.Record().Ports
				}
			}
			t, err := flow.NewTraffic(limit, piece)
			if err != nil {
				return flow.Traffic{}, false, false, err
			}
			out, err = out.Union(t, limit)
			if err != nil {
				return flow.Traffic{}, false, false, err
			}
		}
	}
	if out.Empty() {
		return flow.Traffic{}, false, false, ErrNAT
	}
	return out, false, true, nil
}
func mapPorts(input flow.Traffic, mappings []fm.PortMapping, source bool, limit int) (flow.Traffic, error) {
	if len(mappings) == 0 {
		return input, nil
	}
	var out flow.Traffic
	for _, box := range input.Boxes() {
		origin := box.DestinationPort
		if source {
			origin = box.SourcePort
		}
		covered := uint64(0)
		var intervals []flow.Interval
		for _, m := range mappings {
			lo, hi := max(origin.Low, m.Original.Low), min(origin.High, m.Original.High)
			if lo > hi {
				continue
			}
			for _, other := range intervals {
				if max(other.Low, lo) <= min(other.High, hi) {
					return flow.Traffic{}, ErrNAT
				}
			}
			intervals = append(intervals, flow.Interval{Low: lo, High: hi})
			covered += uint64(hi) - uint64(lo) + 1
			var target flow.Interval
			switch m.Mode {
			case fm.Identity:
				target = flow.Interval{Low: lo, High: hi}
			case fm.Constant:
				target = m.Translated
			case fm.Offset:
				target = flow.Interval{Low: m.Translated.Low + (lo - m.Original.Low), High: m.Translated.Low + (hi - m.Original.Low)}
			default:
				return flow.Traffic{}, ErrNAT
			}
			piece := box
			if source {
				piece.SourcePort = target
			} else {
				piece.DestinationPort = target
			}
			t, err := flow.NewTraffic(limit, piece)
			if err != nil {
				return flow.Traffic{}, err
			}
			out, err = out.Union(t, limit)
			if err != nil {
				return flow.Traffic{}, err
			}
		}
		if covered != uint64(origin.High)-uint64(origin.Low)+1 {
			return flow.Traffic{}, ErrNAT
		}
	}
	return out, nil
}

func restrictMappings(input flow.Traffic, mappings []fm.Mapping, source bool, limit int) (flow.Traffic, error) {
	if len(mappings) == 0 {
		return input, nil
	}
	var out flow.Traffic
	for _, box := range input.Boxes() {
		for _, m := range mappings {
			axis := box.Destination
			if source {
				axis = box.Source
			}
			part, ok := axis.Intersection(m.Original)
			if !ok {
				continue
			}
			piece := box
			if source {
				piece.Source = part
			} else {
				piece.Destination = part
			}
			traffic, err := flow.NewTraffic(limit, piece)
			if err != nil {
				return flow.Traffic{}, err
			}
			out, err = out.Union(traffic, limit)
			if err != nil {
				return flow.Traffic{}, err
			}
		}
	}
	return out, nil
}

// Reverse packet selection depends on native direction and zone semantics. Until that
// pipeline is established, a possible reverse match cannot be reported as definite no-NAT.
func reverseDomainIntersects(input flow.Traffic, record fm.StaticNATRecord) bool {
	for _, box := range input.Boxes() {
		for _, mapping := range record.Source {
			if _, ok := box.Destination.Intersection(mapping.Translated); ok {
				return true
			}
		}
		for _, mapping := range record.Destination {
			if _, ok := box.Source.Intersection(mapping.Translated); ok {
				return true
			}
		}
	}
	return false
}
