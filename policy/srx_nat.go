package policy

import (
	"context"
	"slices"
	"strings"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
)

// srxSteps selects the zone-based native rule sets before considering any rule
// address/port predicates. Interface/instance contexts remain unsupported in the
// parser; they cannot be flattened into zone matches with a different priority.
func (e Engine) srxSteps(ctx context.Context, fw *fm.Firewall, q Request, post bool, budget *int) ([]NATStep, error) {
	if q.Scope != "" {
		return nil, ErrNAT
	}
	entries := fw.NATSequence()
	if len(entries) > e.Limits.defaults().Rules {
		return nil, ErrBudget
	}
	type group struct {
		from, to []fm.ID
		steps    []NATStep
		stage    int
	}
	var groups []group
	index := make(map[string]int)
	for _, entry := range entries {
		if *budget <= 0 {
			return nil, ErrBudget
		}
		*budget--
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		stage := entry.Order.Stage
		if stage < 0 || stage > 2 || entry.Scope != "" {
			return nil, ErrNAT
		}
		if post && stage == 1 || !post && stage == 2 {
			continue
		}
		n, err := transform(fw, NATStep{Kind: entry.Kind, ID: entry.ID})
		if err != nil {
			return nil, err
		}
		if n.disabled {
			continue
		}
		section := entry.Order.Section
		prefix := []string{"static:", "destination:", "source:"}[stage]
		if !strings.HasPrefix(section, prefix) || len(n.match.FromZones) != 1 || n.match.AnyFromZone || stage != 2 && (!n.match.AnyToZone || len(n.match.ToZones) != 0) || stage == 2 && (len(n.match.ToZones) != 1 || n.match.AnyToZone) {
			return nil, ErrNAT
		}
		if stage == 0 && (entry.Kind != fm.StaticNATObject || !fw.StaticNAT(entry.ID).Record().Bidirectional) || stage != 0 && entry.Kind != fm.DynamicNATObject {
			return nil, ErrNAT
		}
		step := NATStep{Kind: entry.Kind, ID: entry.ID, Reverse: post && stage == 0}
		i, ok := index[section]
		if !ok {
			i = len(groups)
			index[section] = i
			groups = append(groups, group{from: n.match.FromZones, to: n.match.ToZones, stage: stage})
		}
		g := &groups[i]
		if !slices.Equal(g.from, n.match.FromZones) || !slices.Equal(g.to, n.match.ToZones) {
			return nil, ErrNAT
		}
		g.steps = append(g.steps, step)
	}
	var selected []NATStep
	have := make(map[int]bool)
	for _, g := range groups {
		from := q.FromZone
		if post && g.stage == 0 {
			from = q.ToZone
		}
		if from == "" {
			return nil, ErrNAT
		}
		if g.from[0] != from {
			continue
		}
		if g.stage == 2 {
			if q.ToZone == "" {
				return nil, ErrNAT
			}
			if g.to[0] != q.ToZone {
				continue
			}
		}
		if have[g.stage] {
			return nil, ErrNAT
		}
		have[g.stage] = true
		selected = append(selected, g.steps...)
	}
	return selected, nil
}

func natParts(r NATResult) []NATRelation {
	parts := slices.Clone(r.Relations)
	if !r.Unmatched.Empty() {
		parts = append(parts, NATRelation{Original: r.Unmatched, Translated: r.Unmatched, Exact: true})
	}
	return parts
}

// QueryNAT's ToZone denotes the post-DNAT destination zone. QueryPacket derives
// that zone from independent routing and uses the intermediate policy view.
func (e Engine) srxNAT(ctx context.Context, fw *fm.Firewall, q Request, budget *int) (NATResult, error) {
	steps, err := e.srxSteps(ctx, fw, q, false, budget)
	if err != nil {
		return NATResult{}, err
	}
	pre, err := e.natChain(ctx, fw, q, steps, budget)
	if err != nil {
		return NATResult{}, err
	}
	out := NATResult{Complete: pre.Complete, Unknown: pre.Unknown}
	for _, part := range natParts(pre) {
		request := q
		request.Traffic = part.Translated
		post, err := e.srxPostNAT(ctx, fw, request, part, budget)
		if err != nil {
			return NATResult{}, err
		}
		out.Relations = append(out.Relations, post.Relations...)
		if len(out.Relations) > e.Limits.defaults().Regions {
			return NATResult{}, ErrBudget
		}
		out.Unknown, err = out.Unknown.Union(post.Unknown, e.Limits.defaults().Regions)
		if err != nil {
			return NATResult{}, err
		}
		out.Unmatched, err = out.Unmatched.Union(post.Unmatched, e.Limits.defaults().Regions)
		if err != nil {
			return NATResult{}, err
		}
		out.Complete = out.Complete && post.Complete
	}
	return out, nil
}

func (e Engine) srxPostNAT(ctx context.Context, fw *fm.Firewall, q Request, pre NATRelation, budget *int) (NATResult, error) {
	limit := e.Limits.defaults().Regions
	steps, err := e.srxSteps(ctx, fw, q, true, budget)
	if err != nil {
		return NATResult{}, err
	}
	post, err := e.natChain(ctx, fw, q, steps, budget)
	if err != nil {
		return NATResult{}, err
	}
	out := NATResult{Complete: post.Complete}
	out.Unknown, err = srxOriginal(fw, pre, post.Unknown, limit)
	if err != nil {
		return NATResult{}, err
	}
	for _, piece := range natParts(post) {
		original, err := srxOriginal(fw, pre, piece.Original, limit)
		if err != nil {
			return NATResult{}, err
		}
		steps := append(slices.Clone(pre.Steps), piece.Steps...)
		if len(steps) == 0 {
			out.Unmatched, err = out.Unmatched.Union(original, limit)
			if err != nil {
				return NATResult{}, err
			}
			continue
		}
		rel := NATRelation{Original: original, Translated: piece.Translated, Steps: steps, Exact: pre.Exact && piece.Exact, PossibleAllocation: pre.PossibleAllocation || piece.PossibleAllocation}
		if len(steps) == 1 {
			rel.Kind, rel.ID = steps[0].Kind, steps[0].ID
		}
		if len(out.Relations) >= limit {
			return NATResult{}, ErrBudget
		}
		out.Relations = append(out.Relations, rel)
	}
	return out, nil
}

// srxOriginal takes a preimage of a partition of the post-DNAT traffic. Constant
// translations can have multiple original addresses; they are not inverted as
// an arbitrary one-to-one mapping. Intersecting the retained original traffic
// preserves source/destination/port pairs through subsequent SNAT partitioning.
func srxOriginal(fw *fm.Firewall, pre NATRelation, subset flow.Traffic, limit int) (flow.Traffic, error) {
	if subset.Empty() {
		return flow.Traffic{}, nil
	}
	if len(pre.Steps) == 0 {
		return subset.Intersection(pre.Original, limit)
	}
	if len(pre.Steps) != 1 || pre.Steps[0].Reverse {
		return flow.Traffic{}, ErrNAT
	}
	n, err := transform(fw, pre.Steps[0])
	if err != nil {
		return flow.Traffic{}, err
	}
	if len(n.source) > 0 || len(n.sourcePorts) > 0 {
		return flow.Traffic{}, ErrNAT
	}
	var out flow.Traffic
	for _, b := range subset.Boxes() {
		addresses := []flow.Range{b.Destination}
		if len(n.destination) > 0 {
			addresses = nil
			for _, m := range n.destination {
				part, ok := m.Translated.Intersection(b.Destination)
				if !ok {
					continue
				}
				value := m.Original
				if m.Mode == fm.Identity || m.Mode == fm.Offset {
					value, err = translate(part, fm.Mapping{Original: m.Translated, Translated: m.Original, Mode: m.Mode})
					if err != nil {
						return flow.Traffic{}, err
					}
				} else if m.Mode != fm.Constant {
					return flow.Traffic{}, ErrNAT
				}
				addresses = append(addresses, value)
			}
		}
		ports := []flow.Interval{b.DestinationPort}
		if len(n.destinationPorts) > 0 {
			ports = nil
			for _, m := range n.destinationPorts {
				lo, hi := max(b.DestinationPort.Low, m.Translated.Low), min(b.DestinationPort.High, m.Translated.High)
				if lo > hi {
					continue
				}
				value := m.Original
				if m.Mode == fm.Identity || m.Mode == fm.Offset {
					value = flow.Interval{Low: m.Original.Low + (lo - m.Translated.Low), High: m.Original.Low + (hi - m.Translated.Low)}
				} else if m.Mode != fm.Constant {
					return flow.Traffic{}, ErrNAT
				}
				ports = append(ports, value)
			}
		}
		if len(addresses) > limit || len(ports) > limit || len(addresses)*len(ports) > limit {
			return flow.Traffic{}, ErrBudget
		}
		for _, address := range addresses {
			for _, port := range ports {
				box := b
				box.Destination, box.DestinationPort = address, port
				piece, err := flow.NewTraffic(limit, box)
				if err != nil {
					return flow.Traffic{}, err
				}
				out, err = out.Union(piece, limit)
				if err != nil {
					return flow.Traffic{}, err
				}
			}
		}
	}
	return out.Intersection(pre.Original, limit)
}
