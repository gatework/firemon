package policy

import (
	"context"
	"errors"
	"slices"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
)

func (e Engine) fortinetNAT(ctx context.Context, fw *fm.Firewall, q Request, budget *int) (NATResult, error) {
	pre, err := e.fortinetDestinations(ctx, fw, q, budget)
	if err != nil {
		return NATResult{}, err
	}
	out := NATResult{Complete: pre.Complete, Unknown: pre.Unknown}
	limit := e.Limits.defaults().Regions
	for _, view := range natParts(pre) {
		evaluated, err := e.fortinetPolicy(ctx, fw, q, view, budget)
		if err != nil {
			return NATResult{}, err
		}
		unknown, err := srxOriginal(fw, view, evaluated.Unknown, limit)
		if err != nil {
			return NATResult{}, err
		}
		out.Unknown, err = out.Unknown.Union(unknown, limit)
		if err != nil {
			return NATResult{}, err
		}
		rejected, err := evaluated.Denied.Union(evaluated.Unmatched, limit)
		if err != nil {
			return NATResult{}, err
		}
		rejected, err = srxOriginal(fw, view, rejected, limit)
		if err != nil {
			return NATResult{}, err
		}
		out.Unmatched, err = out.Unmatched.Union(rejected, limit)
		if err != nil {
			return NATResult{}, err
		}
		for _, trace := range evaluated.Trace {
			if !trace.Certain || trace.Action != fm.Permit {
				continue
			}
			request := q
			request.Traffic = trace.Traffic
			post, err := e.fortinetPost(ctx, fw, request, trace.Rule, budget)
			if err != nil {
				return NATResult{}, err
			}
			unknown, err := srxOriginal(fw, view, post.Unknown, limit)
			if err != nil {
				return NATResult{}, err
			}
			out.Unknown, err = out.Unknown.Union(unknown, limit)
			if err != nil {
				return NATResult{}, err
			}
			for _, part := range natParts(post) {
				part, err = fortinetCompose(fw, view, part, limit)
				if err != nil {
					return NATResult{}, err
				}
				if len(part.Steps) == 0 {
					out.Unmatched, err = out.Unmatched.Union(part.Original, limit)
					if err != nil {
						return NATResult{}, err
					}
				} else {
					if len(out.Relations) >= limit {
						return NATResult{}, ErrBudget
					}
					out.Relations = append(out.Relations, part)
				}
			}
		}
	}
	out.Complete = out.Unknown.Empty()
	return out, nil
}

func fortinetCompose(fw *fm.Firewall, pre, post NATRelation, limit int) (NATRelation, error) {
	original, err := srxOriginal(fw, pre, post.Original, limit)
	if err != nil {
		return NATRelation{}, err
	}
	if post.ID == "" {
		post.Kind, post.ID = pre.Kind, pre.ID
	}
	post.Original = original
	post.Steps = append(slices.Clone(pre.Steps), post.Steps...)
	post.Exact = pre.Exact && post.Exact
	post.PossibleAllocation = pre.PossibleAllocation || post.PossibleAllocation
	return post, nil
}

func (e Engine) fortinetPost(ctx context.Context, fw *fm.Firewall, q Request, rule fm.ID, budget *int) (NATResult, error) {
	var owner *fm.DynamicNAT
	for _, n := range fw.DynamicNATs() {
		if *budget <= 0 {
			return NATResult{}, ErrBudget
		}
		*budget--
		if err := ctx.Err(); err != nil {
			return NATResult{}, err
		}
		if n.Record().Rule == rule && !n.Record().Disabled {
			if owner != nil || n.Rule() == nil {
				return NATResult{}, ErrNAT
			}
			owner = n
		}
	}
	if owner == nil {
		return NATResult{Complete: true, Unmatched: q.Traffic}, nil
	}
	step := NATStep{Kind: fm.DynamicNATObject, ID: owner.Record().ID}
	n, err := transform(fw, step)
	if err != nil {
		return NATResult{}, err
	}
	known := n.known
	if iface := owner.Interface(); iface != nil {
		known = known && fortinetEgressKnown(fw, iface, q)
	}
	if pool := owner.SourcePool(); pool != nil {
		known = known && len(pool.Record().Unsupported) == 0
		if iface := pool.Interface(); iface != nil {
			known = known && fortinetEgressKnown(fw, iface, q)
		}
	}
	if !known {
		return NATResult{Unknown: q.Traffic}, nil
	}
	active, err := e.fortinetActiveVIPs(ctx, fw, budget)
	if errors.Is(err, ErrNAT) {
		return NATResult{Unknown: q.Traffic}, nil
	}
	if err != nil {
		return NATResult{}, err
	}
	out := NATResult{Complete: true}
	remaining := q.Traffic
	limit := e.Limits.defaults().Regions
	for _, section := range []string{"vip-source-forced", "vip-source-interface"} {
		if section == "vip-source-interface" && owner.SourcePool() != nil {
			continue
		}
		part, err := e.fortinetSourceTier(ctx, fw, Request{Traffic: remaining, Scope: q.Scope, FromZone: q.FromZone, ToZone: q.ToZone, EgressInterface: q.EgressInterface, At: q.At}, section, active, owner.Record().SourceMode == fm.DynamicIP, budget)
		if err != nil {
			return NATResult{}, err
		}
		if len(out.Relations)+len(part.Relations) > limit {
			return NATResult{}, ErrBudget
		}
		out.Relations = append(out.Relations, part.Relations...)
		out.Unknown, err = out.Unknown.Union(part.Unknown, limit)
		if err != nil {
			return NATResult{}, err
		}
		remaining = part.Unmatched
	}
	if !remaining.Empty() {
		translated, exact, possible, err := n.apply(remaining, limit)
		if errors.Is(err, flow.ErrBudget) {
			return NATResult{}, err
		}
		if err != nil {
			out.Unknown, err = out.Unknown.Union(remaining, limit)
			if err != nil {
				return NATResult{}, err
			}
		} else {
			if len(out.Relations) >= limit {
				return NATResult{}, ErrBudget
			}
			out.Relations = append(out.Relations, NATRelation{Kind: step.Kind, ID: step.ID, Steps: []NATStep{step}, Original: remaining, Translated: translated, Exact: exact, PossibleAllocation: possible})
		}
	}
	out.Complete = out.Unknown.Empty()
	return out, nil
}

func fortinetEgressKnown(fw *fm.Firewall, iface *fm.Interface, q Request) bool {
	r := iface.Record()
	if r.Disabled || len(r.Unsupported) > 0 || r.Scope != q.Scope || r.Zone != q.ToZone {
		return false
	}
	if q.EgressInterface != "" {
		return q.EgressInterface == r.ID
	}
	// A zone names an interface only when that ownership is unique.
	for _, other := range fw.Interfaces() {
		if other.Record().Zone == r.Zone && other.Record().ID != r.ID {
			return false
		}
	}
	return true
}

func (e Engine) fortinetSourceTier(ctx context.Context, fw *fm.Firewall, q Request, section string, active map[fm.ID]bool, preservePorts bool, budget *int) (NATResult, error) {
	out := NATResult{Complete: true}
	limit := e.Limits.defaults().Regions
	var covered flow.Traffic
	for _, nat := range fw.StaticNATs() {
		if err := ctx.Err(); err != nil {
			return NATResult{}, err
		}
		if *budget <= 0 {
			return NATResult{}, ErrBudget
		}
		*budget--
		r := nat.Record()
		if r.Scope != q.Scope || r.Order.Section != section || !active[fm.ID("vip:"+r.Name)] {
			continue
		}
		part, err := e.natChain(ctx, fw, q, []NATStep{{Kind: fm.StaticNATObject, ID: r.ID}}, budget)
		if err != nil {
			return NATResult{}, err
		}
		hit, err := q.Traffic.Difference(part.Unmatched, limit)
		if err != nil {
			return NATResult{}, err
		}
		overlap, err := hit.Intersection(covered, limit)
		if err != nil {
			return NATResult{}, err
		}
		out.Unknown, err = out.Unknown.Union(part.Unknown, limit)
		if err != nil {
			return NATResult{}, err
		}
		out.Unknown, err = out.Unknown.Union(overlap, limit)
		if err != nil {
			return NATResult{}, err
		}
		covered, err = covered.Union(hit, limit)
		if err != nil {
			return NATResult{}, err
		}
		if len(out.Relations)+len(part.Relations) > limit {
			return NATResult{}, ErrBudget
		}
		out.Relations = append(out.Relations, part.Relations...)
	}
	var selected []NATRelation
	for _, part := range out.Relations {
		var err error
		part.Original, err = part.Original.Difference(out.Unknown, limit)
		if err != nil {
			return NATResult{}, err
		}
		if part.Original.Empty() {
			continue
		}
		n, err := transform(fw, part.Steps[0])
		if err != nil {
			return NATResult{}, err
		}
		part.Translated, _, _, err = n.apply(part.Original, limit)
		if err != nil {
			return NATResult{}, err
		}
		if !preservePorts {
			part.Translated, err = mapPorts(part.Translated, []fm.PortMapping{{Original: flow.Interval{High: 65535}, Translated: flow.Interval{High: 65535}, Mode: fm.Constant}}, true, limit)
			if err != nil {
				return NATResult{}, err
			}
			part.Exact = false
			part.PossibleAllocation = true
		}
		selected = append(selected, part)
	}
	out.Relations = selected
	var err error
	out.Unmatched, err = q.Traffic.Difference(covered, limit)
	if err != nil {
		return NATResult{}, err
	}
	out.Complete = out.Unknown.Empty()
	return out, nil
}

func (e Engine) fortinetActiveVIPs(ctx context.Context, fw *fm.Firewall, budget *int) (map[fm.ID]bool, error) {
	active := make(map[fm.ID]bool)
	resolver := &resolutionBudget{ctx: ctx, limit: e.Limits.defaults().Combinations}
	for _, rule := range fw.Rules() {
		if *budget <= 0 {
			return nil, ErrBudget
		}
		*budget--
		r := rule.Record()
		if r.Disabled {
			continue
		}
		_, vips, known, err := fortinetDestRefs(fw, r.Match.Destinations, resolver)
		if err != nil {
			return nil, err
		}
		if !known {
			return nil, ErrNAT
		}
		for id := range vips {
			active[id] = true
		}
	}
	return active, nil
}
