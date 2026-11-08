package operations

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/inventory"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/policy"
)

type relatedTraffic struct {
	traffic flow.Traffic
	sources []string
	window  *fm.TimeWindow
	derived bool
}

// discovery walks configuration associations. It never asserts that different
// devices lie on one physical path, or feeds a dynamic pool back as exact traffic.
type discovery struct {
	batch    *targetBatch
	input    int
	request  AccessRequest
	cache    *inventory.Cache
	variants []relatedTraffic
	pending  []int
	queued   []bool
	probes   map[probeContext][]discoveryProbe
}
type probeContext struct {
	device, revision, scope, ruleset, vrf string
	from, to                              fm.ID
	at, end                               time.Time
	packet, conditional                   bool
	view                                  policy.AliasView
}
type discoveryProbe struct {
	traffic flow.Traffic
	entries []*targetEntry
}
type policyIngress struct {
	scope string
	zone  fm.ID
}

func (r *targetBatch) discover(ctx context.Context, input int, a AccessRequest) error {
	cache, ok := r.store.(*inventory.Cache)
	if !ok {
		return ErrInvalid
	}
	d := discovery{batch: r, input: input, request: a, cache: cache,
		variants: []relatedTraffic{{traffic: a.Traffic, window: a.Window}},
		probes:   make(map[probeContext][]discoveryProbe), pending: []int{0}, queued: []bool{true}}
	devices := make([]string, 0, len(r.manifest.Devices))
	for device := range r.manifest.Devices {
		devices = append(devices, device)
	}
	sort.Strings(devices)
	for next := 0; next < len(d.pending); next++ {
		index := d.pending[next]
		d.queued[index] = false
		for _, device := range devices {
			if err := d.scan(ctx, device, d.variants[index]); err != nil {
				return err
			}
		}
	}
	if len(r.inputs[input].entries) == 0 {
		view := a.View
		if view == "" {
			view = inventory.Original
		}
		r.issue(input, "", "location", "unlocated", a.Traffic, string(view), nil, "")
	}
	return r.budgetErr
}

func (d *discovery) scan(ctx context.Context, device string, variant relatedTraffic) error {
	r := d.batch
	target := AccessTarget{Device: device, Revision: r.manifest.Devices[device].Revision, Packet: true}
	view := d.request.View
	if view == "" {
		view = inventory.Original
	}
	fw, err := r.load(ctx, d.input, variant.traffic, string(view), target, variant.sources)
	if err != nil || fw == nil {
		return err
	}
	if err := r.chargeGraph(ctx, fw); err != nil {
		return err
	}
	index := r.indexes[target.Revision]
	if index == nil {
		index, err = d.cache.Index(ctx, target.Revision, fw)
		if err != nil {
			return err
		}
		if r.indexes == nil {
			r.indexes = make(map[string]*inventory.Index)
		}
		r.indexes[target.Revision] = index
	}
	traffic, sources, err := d.related(ctx, index, device, variant)
	if err != nil || traffic.Empty() {
		return err
	}
	a := d.request
	a.Window = variant.window
	windows, err := r.times(ctx, fw, a)
	if err != nil {
		return err
	}
	ingresses := make(map[policyIngress]bool)
	for _, ingress := range index.Ingress() {
		if a.Scope != nil && *a.Scope != ingress.Scope || a.VRF != nil && *a.VRF != ingress.VRF {
			continue
		}
		ingresses[policyIngress{scope: ingress.Scope, zone: ingress.Zone}] = true
		target.Request = policy.Request{Scope: ingress.Scope, FromZone: ingress.Zone}
		target.VRF = ingress.VRF
		var established flow.Traffic
		if view == inventory.Original && !variant.derived {
			established, err = r.establishedIngress(ctx, target, traffic)
			if err != nil {
				return err
			}
		}
		remaining, err := traffic.Difference(established, r.engine.Limits.WithDefaults().MaxRegions)
		if err != nil {
			return err
		}
		for _, when := range windows {
			target.Request.At = when.Start
			for _, part := range []struct {
				traffic     flow.Traffic
				conditional bool
			}{{established, false}, {remaining, true}} {
				if part.traffic.Empty() {
					continue
				}
				proposal := targetProposal{traffic: part.traffic, target: target, sources: sources, scopeSet: true, conditional: part.conditional}
				if variant.window != nil {
					proposal.window = &when
				}
				var err error
				if view == inventory.Original {
					err = d.query(ctx, fw, proposal)
				} else {
					err = d.aliases(ctx, fw, proposal)
				}
				if err != nil {
					return err
				}
			}
		}
	}
	if view != inventory.Original {
		if len(ingresses) == 0 {
			r.issue(d.input, device, "alias", "unknown_alias", traffic, string(view), sources, "native packet context is unavailable")
		}
		return r.budgetErr
	}
	proposal := targetProposal{traffic: traffic, target: target, sources: sources, scopeSet: true, conditional: true}
	return d.unboundDeclarations(ctx, fw, proposal, windows, ingresses)
}

// Native declarations remain queryable without an interface-backed packet
// context. These zone references come from the graph; they do not establish
// arrival, routing or VRF membership and cannot authorize a change.
func (d *discovery) unboundDeclarations(ctx context.Context, fw *fm.Firewall, p targetProposal, windows []fm.TimeWindow, ingresses map[policyIngress]bool) error {
	type contextKey struct {
		chain fm.PolicyChain
		from  fm.ID
	}
	seen := make(map[contextKey]bool)
	var zones []fm.ID
	for _, zone := range fw.Zones() {
		if err := d.batch.charge(ctx); err != nil {
			return err
		}
		zones = append(zones, zone.ID())
	}
	for rule := range fw.OrderedRules() {
		if err := d.batch.charge(ctx); err != nil {
			return err
		}
		chain := rule.Chain()
		if d.request.Scope != nil && chain.Scope != *d.request.Scope {
			continue
		}
		match := rule.Record().Match
		from := declarationZones(zones, match.FromZones, match.AnyFromZone)
		unboundTo := !match.AnyToZone && len(match.ToZones) == 0
		for _, zone := range match.ToZones {
			unboundTo = unboundTo || fw.Zone(zone) == nil
		}
		for _, zone := range from {
			if err := d.batch.charge(ctx); err != nil {
				return err
			}
			key := contextKey{chain: chain, from: zone}
			if seen[key] || !unboundTo && ingresses[policyIngress{scope: chain.Scope, zone: zone}] {
				continue
			}
			seen[key] = true
			for _, when := range windows {
				proposal := p
				proposal.target = AccessTarget{Device: p.target.Device, Revision: p.target.Revision,
					Request: policy.Request{Scope: chain.Scope, RuleSet: chain.RuleSet, FromZone: zone, At: when.Start}}
				if !when.End.IsZero() {
					proposal.window = &when
				}
				if err := d.declarations(ctx, fw, proposal, p.traffic); err != nil {
					return err
				}
			}
		}
	}
	return d.batch.budgetErr
}

func (d *discovery) related(ctx context.Context, index *inventory.Index, device string, variant relatedTraffic) (flow.Traffic, []string, error) {
	r := d.batch
	limit := r.engine.Limits.WithDefaults().MaxRegions
	src, dst := trafficAddresses(variant.traffic)
	sources := slices.Clone(variant.sources)
	sets := [2]flow.AddressSet{}
	for side, addresses := range []flow.AddressSet{src, dst} {
		hits, err := index.Candidates(ctx, addresses, limit)
		if err != nil {
			return flow.Traffic{}, nil, err
		}
		for _, h := range hits {
			if err := r.charge(ctx); err != nil {
				return flow.Traffic{}, nil, err
			}
			sets[side] = sets[side].Union(h.Addresses)
			sources = append(sources, fmt.Sprintf("%s:%s:%s", device, h.Source, h.ID))
		}
	}
	slices.Sort(sources)
	sources = slices.Compact(sources)
	traffic, err := relatedDomain(variant.traffic, sets[0], sets[1], limit)
	return traffic, sources, err
}

func (d *discovery) query(ctx context.Context, fw *fm.Firewall, p targetProposal) error {
	r := d.batch
	entries, err := d.probe(ctx, fw, p)
	if err != nil {
		return err
	}
	var covered flow.Traffic
	for _, entry := range entries {
		covered, err = covered.Union(entry.outcome.Wire, r.engine.Limits.WithDefaults().MaxRegions)
		if err != nil {
			return err
		}
		nat := entry.outcome.NAT
		if nat.Exact && !nat.PossibleAllocation {
			if err := d.append(ctx, nat.Translated, p.sources, p.window); err != nil {
				return err
			}
		}
	}
	missing, err := p.traffic.Difference(covered, r.engine.Limits.WithDefaults().MaxRegions)
	if err != nil {
		return err
	}
	// Missing routes do not hide declarations on the unresolved fraction.
	if !missing.Empty() {
		if err := d.declarations(ctx, fw, p, missing); err != nil {
			return err
		}
	}
	return d.aliases(ctx, fw, p)
}

func (d *discovery) declarations(ctx context.Context, fw *fm.Firewall, p targetProposal, traffic flow.Traffic) error {
	type contextKey struct {
		chain fm.PolicyChain
		to    fm.ID
	}
	seen := make(map[contextKey]bool)
	var zones []fm.ID
	for _, zone := range fw.Zones() {
		if err := d.batch.charge(ctx); err != nil {
			return err
		}
		zones = append(zones, zone.ID())
	}
	probe := func(chain fm.PolicyChain, zone fm.ID) error {
		if err := d.batch.charge(ctx); err != nil {
			return err
		}
		key := contextKey{chain: chain, to: zone}
		if seen[key] {
			return nil
		}
		seen[key] = true
		direct := p
		direct.traffic = traffic
		direct.target.Packet = false
		direct.target.Request.RuleSet = chain.RuleSet
		direct.target.Request.ToZone = zone
		direct.conditional = true
		_, err := d.probe(ctx, fw, direct)
		return err
	}
	for rule := range fw.OrderedRules() {
		if err := d.batch.charge(ctx); err != nil {
			return err
		}
		chain := rule.Chain()
		if chain.Scope != p.target.Request.Scope || p.target.Request.RuleSet != "" && chain.RuleSet != p.target.Request.RuleSet {
			continue
		}
		match := rule.Record().Match
		for _, zone := range declarationZones(zones, match.ToZones, match.AnyToZone) {
			if err := probe(chain, zone); err != nil {
				return err
			}
		}
	}
	if len(seen) == 0 {
		for _, zone := range declarationZones(zones, nil, true) {
			if err := probe(p.target.Request.Chain(), zone); err != nil {
				return err
			}
		}
	}
	return ctx.Err()
}

// Empty denotes an unknown native context, never a synthesized zone or ingress.
func declarationZones(zones, refs []fm.ID, any bool) []fm.ID {
	if !any && len(refs) != 0 {
		return refs
	}
	if any && len(zones) != 0 {
		return zones
	}
	return []fm.ID{""}
}

func (d *discovery) aliases(ctx context.Context, fw *fm.Firewall, p targetProposal) error {
	r := d.batch
	views := []policy.AliasView{policy.RealView, policy.TranslatedView}
	explicit := d.request.View == inventory.Real || d.request.View == inventory.Translated
	if explicit {
		views = []policy.AliasView{policy.AliasView(d.request.View)}
	}
	for _, view := range views {
		q := policy.PacketRequest{Request: p.target.Request, VRF: p.target.VRF}
		q.Traffic = p.traffic
		if err := r.chargeGraph(ctx, fw); err != nil {
			return err
		}
		aliases, err := r.engine.DiscoverStaticAliases(ctx, fw, q, view)
		if err != nil {
			if fatalBatch(err) {
				return err
			}
			r.issue(d.input, p.target.Device, "alias", "unsupported_alias", p.traffic, string(view), p.sources, err.Error())
			continue
		}
		for _, uncertain := range []struct {
			code    string
			traffic flow.Traffic
		}{
			{"ambiguous_alias", aliases.Ambiguous}, {"unknown_alias", aliases.Unknown},
		} {
			if !uncertain.traffic.Empty() {
				r.issue(d.input, p.target.Device, "alias", uncertain.code, uncertain.traffic, string(view), p.sources, "")
			}
		}
		if explicit && !aliases.Unmatched.Empty() {
			r.issue(d.input, p.target.Device, "alias", "unlocated_alias", aliases.Unmatched, string(view), p.sources, "")
		}
		for _, alias := range aliases.Candidates {
			proof := p
			proof.traffic = alias.Wire
			proof.expected = &targetView{view: view, traffic: alias.Business}
			// An inferred address view cannot authorize a configuration change.
			proof.conditional = true
			if _, err := d.probe(ctx, fw, proof); err != nil {
				return err
			}
			if !explicit {
				if err := d.append(ctx, alias.Wire, p.sources, p.window); err != nil {
					return err
				}
			}
		}
	}
	return r.budgetErr
}

func (d *discovery) probe(ctx context.Context, fw *fm.Firewall, p targetProposal) ([]*targetEntry, error) {
	q := p.target.Request
	key := probeContext{device: p.target.Device, revision: p.target.Revision, scope: q.Scope, ruleset: q.RuleSet,
		vrf: p.target.VRF, from: q.FromZone, to: q.ToZone, at: q.At.Round(0).UTC(), packet: p.target.Packet, conditional: p.conditional}
	if p.window != nil {
		key.end = p.window.End.Round(0).UTC()
	}
	if p.expected != nil {
		key.view = p.expected.view
	}
	for _, previous := range d.probes[key] {
		if err := d.batch.charge(ctx); err != nil {
			return nil, err
		}
		same, err := previous.traffic.Equal(p.traffic, d.batch.engine.Limits.WithDefaults().MaxRegions)
		if err != nil {
			return nil, err
		}
		if same {
			for _, entry := range previous.entries {
				refs, err := d.mergeSources(ctx, entry.outcome.Sources, p.sources)
				if err != nil {
					return nil, err
				}
				if err := d.batch.retainRefs(refs); err != nil {
					return nil, err
				}
				entry.outcome.Sources = refs
			}
			return previous.entries, nil
		}
	}
	if err := d.batch.chargeGraph(ctx, fw); err != nil {
		return nil, err
	}
	var entries []*targetEntry
	var err error
	if !p.target.Packet && p.conditional && (fw.Zone(q.FromZone) == nil || fw.Zone(q.ToZone) == nil) {
		q.Traffic = p.traffic
		if q.RuleSet == "" {
			q.RuleSet = "security"
		}
		outcome := TargetOutcome{At: q.At, Window: p.window, Conditional: true,
			Device: p.target.Device, Revision: p.target.Revision, Wire: p.traffic,
			NativeRequests: []policy.Request{q}, Sources: slices.Clone(p.sources),
			Policy: policy.Result{Unknown: p.traffic}, Disposition: plan.BatchPending}
		var entry *targetEntry
		entry, err = d.batch.record(d.input, outcome, "policy")
		if err == nil {
			entries = append(entries, entry)
			d.batch.issue(d.input, p.target.Device, "query", "zone_missing", p.traffic, "policy", p.sources, "native zone context is unavailable")
			err = d.batch.budgetErr
		}
	} else {
		entries, err = d.batch.evaluate(ctx, d.input, p)
	}
	if err != nil {
		return nil, err
	}
	d.probes[key] = append(d.probes[key], discoveryProbe{traffic: p.traffic, entries: entries})
	return entries, nil
}

func (d *discovery) append(ctx context.Context, t flow.Traffic, sources []string, window *fm.TimeWindow) error {
	if t.Empty() {
		return nil
	}
	limit := d.batch.engine.Limits.WithDefaults().MaxRegions
	for i, previous := range d.variants {
		if err := d.batch.charge(ctx); err != nil {
			return err
		}
		same, err := previous.traffic.Equal(t, limit)
		if err != nil {
			return err
		}
		if same && (previous.window == nil && window == nil || previous.window != nil && window != nil &&
			previous.window.Start.Equal(window.Start) && previous.window.End.Equal(window.End)) {
			refs, err := d.mergeSources(ctx, previous.sources, sources)
			if err != nil {
				return err
			}
			if !slices.Equal(previous.sources, refs) {
				d.variants[i].sources = refs
				if !d.queued[i] {
					d.pending = append(d.pending, i)
					d.queued[i] = true
				}
			}
			return nil
		}
	}
	if len(d.variants) >= d.batch.engine.Limits.WithDefaults().MaxCombinations {
		return policy.ErrBudget
	}
	d.pending = append(d.pending, len(d.variants))
	d.queued = append(d.queued, true)
	d.variants = append(d.variants, relatedTraffic{traffic: t, sources: slices.Clone(sources), window: window, derived: true})
	return nil
}

// Candidate sources are a set. Revisited NAT associations retain every direct
// declaration reference without changing the exact traffic or its proof status.
func (d *discovery) mergeSources(ctx context.Context, a, b []string) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(a)+len(b) > d.batch.visits {
		return nil, policy.ErrBudget
	}
	d.batch.visits -= len(a) + len(b)
	refs := make([]string, 0, len(a)+len(b))
	refs = append(refs, a...)
	refs = append(refs, b...)
	slices.Sort(refs)
	refs = slices.Compact(refs)
	bytes := 0
	for _, ref := range refs {
		bytes += len(ref)
	}
	if bytes > MaxRequestBytes {
		return nil, policy.ErrBudget
	}
	return refs, nil
}

func trafficAddresses(t flow.Traffic) (flow.AddressSet, flow.AddressSet) {
	var src, dst []flow.AddressRange
	for _, box := range t.Regions() {
		src = append(src, box.Source)
		dst = append(dst, box.Destination)
	}
	a, _ := flow.NewAddressSet(src...)
	b, _ := flow.NewAddressSet(dst...)
	return a, b
}
func relatedDomain(t flow.Traffic, src, dst flow.AddressSet, limit int) (flow.Traffic, error) {
	var regions []flow.TrafficRegion
	for _, box := range t.Regions() {
		a, _ := flow.NewAddressSet(box.Source)
		b, _ := flow.NewAddressSet(box.Destination)
		hit := a.Intersection(src)
		for _, source := range hit.Ranges() {
			part := box
			part.Source = source
			regions = append(regions, part)
		}
		for _, source := range a.Difference(hit).Ranges() {
			for _, destination := range b.Intersection(dst).Ranges() {
				part := box
				part.Source, part.Destination = source, destination
				regions = append(regions, part)
				if len(regions) > limit {
					return flow.Traffic{}, policy.ErrBudget
				}
			}
		}
		if len(regions) > limit {
			return flow.Traffic{}, policy.ErrBudget
		}
	}
	return flow.NewTraffic(limit, regions...)
}

// establishedIngress returns only traffic whose source has one current ingress
// binding in this context and at least one endpoint has unique protection
// evidence. Address projections locate evidence; clipping each original region
// preserves the request's source/destination pairs.
func (r *targetBatch) establishedIngress(ctx context.Context, target AccessTarget, traffic flow.Traffic) (flow.Traffic, error) {
	if r.topology == nil {
		return flow.Traffic{}, nil
	}
	src, dst := trafficAddresses(traffic)
	limit := r.engine.Limits.WithDefaults().MaxRegions
	locate := func(addresses flow.AddressSet, role inventory.Role) (flow.AddressSet, error) {
		if err := r.charge(ctx); err != nil {
			return flow.AddressSet{}, err
		}
		q := inventory.Selection{Device: target.Device, Scope: &target.Request.Scope, VRF: &target.VRF, Role: role, View: inventory.Original}
		parts, err := r.topology.Locate(ctx, addresses, q, limit)
		if err != nil {
			return flow.AddressSet{}, err
		}
		var ranges []flow.AddressRange
		for _, p := range parts {
			if err := r.charge(ctx); err != nil {
				return flow.AddressSet{}, err
			}
			if len(p.Bindings) != 1 || p.Bindings[0].Revision != target.Revision || role == inventory.Ingress && p.Bindings[0].Zone != target.Request.FromZone {
				continue
			}
			if p.Addresses.RangeCount() > limit-len(ranges) {
				return flow.AddressSet{}, policy.ErrBudget
			}
			ranges = append(ranges, p.Addresses.Ranges()...)
		}
		return flow.NewAddressSet(ranges...)
	}
	ingress, err := locate(src, inventory.Ingress)
	if err != nil || ingress.Empty() {
		return flow.Traffic{}, err
	}
	source, err := locate(src, inventory.Protection)
	if err != nil {
		return flow.Traffic{}, err
	}
	destination, err := locate(dst, inventory.Protection)
	if err != nil {
		return flow.Traffic{}, err
	}
	owned, err := relatedDomain(traffic, source, destination, limit)
	if err != nil {
		return flow.Traffic{}, err
	}
	var regions []flow.TrafficRegion
	for _, region := range owned.Regions() {
		addresses, _ := flow.NewAddressSet(region.Source)
		for _, source := range addresses.Intersection(ingress).Ranges() {
			if err := r.charge(ctx); err != nil {
				return flow.Traffic{}, err
			}
			if len(regions) >= limit {
				return flow.Traffic{}, policy.ErrBudget
			}
			part := region
			part.Source = source
			regions = append(regions, part)
		}
	}
	return flow.NewTraffic(limit, regions...)
}
