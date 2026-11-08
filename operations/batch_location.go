package operations

import (
	"context"

	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/inventory"
	"github.com/gatework/firemon/policy"
)

func (r *targetBatch) locate(ctx context.Context, input int, a AccessRequest, topology inventory.Topology) error {
	view := a.View
	if view == "" {
		view = inventory.Original
	}

	limit := r.designer.options.Engine.Limits.WithDefaults().MaxRegions
	count := 0
	for _, box := range a.Traffic.Regions() {
		src, _ := flow.NewAddressSet(box.Source)
		dst, _ := flow.NewAddressSet(box.Destination)
		selection := inventory.Selection{Role: inventory.Protection, View: view, Scope: a.Scope, VRF: a.VRF}
		sources, err := topology.Locate(ctx, src, selection, limit)
		if err != nil {
			return err
		}
		destinations, err := topology.Locate(ctx, dst, selection, limit)
		if err != nil {
			return err
		}
		for _, source := range sources {
			for _, destination := range destinations {
				for _, s := range source.Addresses.Ranges() {
					for _, d := range destination.Addresses.Ranges() {
						count++
						if count > limit {
							return policy.ErrBudget
						}
						if err := r.charge(ctx); err != nil {
							return err
						}
						region := box
						region.Source, region.Destination = s, d
						traffic, err := flow.NewTraffic(limit, region)
						if err != nil {
							return err
						}
						var owners []inventory.Binding
						for _, side := range []struct {
							name     string
							bindings []inventory.Binding
						}{{"source", source.Bindings}, {"destination", destination.Bindings}} {
							if len(side.bindings) != 1 {
								code := "unlocated_" + side.name
								var refs []string
								if len(side.bindings) > 1 {
									code = "ambiguous_" + side.name
									for _, b := range side.bindings {
										refs = append(refs, b.Sources...)
									}
								}
								r.issue(input, "", "location", code, traffic, string(view), refs, "")
								continue
							}
							b := side.bindings[0]
							graph, err := r.load(ctx, input, traffic, string(view), AccessTarget{Device: b.Device, Revision: b.Revision}, b.Sources)
							if err != nil {
								return err
							}
							if graph == nil {
								continue
							}
							if graph.Zone(b.Zone) == nil {
								r.issue(input, b.Device, "location", "topology_zone_missing", traffic, string(view), b.Sources, "")
								continue
							}
							duplicate := false
							for _, other := range owners {
								if other.Device == b.Device && other.Scope == b.Scope && other.VRF == b.VRF {
									duplicate = true
								}
							}
							if !duplicate {
								owners = append(owners, b)
							}
						}
						for _, owner := range owners {
							addresses, _ := flow.NewAddressSet(s)
							ingress, err := topology.Locate(ctx, addresses, inventory.Selection{Device: owner.Device, Scope: &owner.Scope, VRF: &owner.VRF, Role: inventory.Ingress, View: view}, limit)
							if err != nil {
								return err
							}
							for _, part := range ingress {
								var regions []flow.TrafficRegion
								for _, network := range part.Addresses.Ranges() {
									piece := region
									piece.Source = network
									regions = append(regions, piece)
								}
								sub, err := flow.NewTraffic(limit, regions...)
								if err != nil {
									return err
								}
								if len(part.Bindings) != 1 {
									code := "ingress_missing"
									if len(part.Bindings) > 1 {
										code = "ingress_ambiguous"
									}
									r.issue(input, owner.Device, "ingress", code, sub, string(view), owner.Sources, "")
									continue
								}
								binding := part.Bindings[0]
								refs := append(append([]string(nil), owner.Sources...), binding.Sources...)
								if binding.Revision != owner.Revision {
									r.issue(input, owner.Device, "snapshot", "stale_topology", sub, string(view), refs, "")
									continue
								}
								h, exists := r.manifest.Devices[owner.Device]
								if exists && h.Revision != owner.Revision {
									r.issue(input, owner.Device, "snapshot", "stale_topology", sub, string(view), refs, "")
									continue
								}
								target := AccessTarget{Device: owner.Device, Revision: owner.Revision, VRF: owner.VRF, Packet: true, Request: policy.Request{Scope: owner.Scope, FromZone: binding.Zone, At: a.At}}
								fw, err := r.load(ctx, input, sub, string(view), target, refs)
								if err != nil {
									return err
								}
								if fw == nil {
									continue
								}
								if fw.Zone(owner.Zone) == nil || fw.Zone(binding.Zone) == nil {
									r.issue(input, owner.Device, "location", "topology_zone_missing", sub, string(view), refs, "")
									continue
								}
								if view != inventory.Original {
									if err := r.aliases(ctx, input, sub, target, refs, view); err != nil {
										return err
									}
									continue
								}
								if _, err := r.evaluate(ctx, input, targetProposal{traffic: sub, target: target, sources: refs}); err != nil {
									return err
								}
							}
						}
					}
				}
			}
		}
	}
	return nil
}

func (r *targetBatch) candidates(ctx context.Context, input int, a AccessRequest) error {
	limit := r.designer.options.Engine.Limits.WithDefaults().MaxRegions
	var validated flow.Traffic
	for _, candidate := range a.WireCandidates {
		target := candidate.Target
		target.Packet = true
		entries, err := r.evaluate(ctx, input, targetProposal{
			traffic: candidate.Traffic, target: target, sources: a.Sources,
			expected: &targetView{view: policy.AliasView(a.View), traffic: a.Traffic},
		})
		if err != nil {
			return err
		}
		for _, entry := range entries {
			var err error
			validated, err = validated.Union(aliasOutcomeTraffic(entry.outcome, a.View), limit)
			if err != nil {
				return err
			}
		}
	}
	missing, err := a.Traffic.Difference(validated, limit)
	if err != nil {
		return err
	}
	if !missing.Empty() {
		r.issue(input, "", "nat", "unvalidated_"+string(a.View), missing, string(a.View), nil, "")
	}
	return nil
}

func aliasOutcomeTraffic(outcome TargetOutcome, view inventory.View) flow.Traffic {
	if view == inventory.Real {
		return outcome.Real
	}
	return outcome.NAT.Translated
}
func (r *targetBatch) aliases(ctx context.Context, input int, business flow.Traffic, target AccessTarget, sources []string, view inventory.View) error {
	fw, err := r.load(ctx, input, business, string(view), target, sources)
	if err != nil || fw == nil {
		return err
	}
	q := target.Request
	q.Traffic = business
	if q.Scope == "" {
		q.Scope = fw.Metadata().Context
	}
	if q.RuleSet == "" {
		q.RuleSet = "security"
	}
	result, err := r.designer.options.Engine.DiscoverStaticAliases(ctx, fw, policy.PacketRequest{Request: q, VRF: target.VRF}, policy.AliasView(view))
	if err != nil {
		if fatalBatch(err) {
			return err
		}
		r.issue(input, target.Device, "alias", "unsupported_alias", business, string(view), sources, err.Error())
		return nil
	}
	for _, part := range []struct {
		code    string
		traffic flow.Traffic
	}{{"ambiguous_alias", result.Ambiguous}, {"unknown_alias", result.Unknown}, {"unlocated_alias", result.Unmatched}} {
		if !part.traffic.Empty() {
			r.issue(input, target.Device, "alias", part.code, part.traffic, string(view), sources, "")
		}
	}
	for _, candidate := range result.Candidates {
		if err := r.charge(ctx); err != nil {
			return err
		}
		if _, err := r.evaluate(ctx, input, targetProposal{
			traffic: candidate.Wire, target: target, sources: sources,
			expected: &targetView{view: policy.AliasView(view), traffic: candidate.Business},
		}); err != nil {
			return err
		}
	}
	return nil
}
