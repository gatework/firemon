package plan

import (
	"context"
	"fmt"
	"reflect"
	"slices"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/internal/dependency"
	"github.com/gatework/firemon/policy"
)

// NativeAdditions is an additive declaration boundary. Existing declarations may
// be reused only in full; editing or deleting NAT and existing owners is forbidden.
// Rules can supply new policy-bound NAT owners/activators in the same transaction.
type NativeAdditions struct {
	Rules       []fm.RuleRecord       `json:"rules,omitempty"`
	Addresses   []fm.AddressRecord    `json:"addresses,omitempty"`
	Services    []fm.ServiceRecord    `json:"services,omitempty"`
	StaticNATs  []fm.StaticNATRecord  `json:"static_nats,omitempty"`
	DynamicNATs []fm.DynamicNATRecord `json:"dynamic_nats,omitempty"`
	NATPools    []fm.NATPoolRecord    `json:"nat_pools,omitempty"`
	Schedules   []fm.ScheduleRecord   `json:"schedules,omitempty"`
}
type NativeChanges struct {
	Rules     []Change
	Additions NativeAdditions
	Clock     *fm.ScheduleClock `json:",omitempty"`
}

// NativeRequest keeps the original policy view and original-wire NAT domain
// separate. Explicit declaration modes and ordered intent steps define the exact
// relation. Sources is uninterpreted business provenance, retained on rejection.
type NativeRequest struct {
	Lifetime  *ScheduleIntent
	Packet    *policy.PacketRequest
	Request   policy.Request
	Additions NativeAdditions
	NAT       []policy.NATIntent
	Sources   []string
}

// NativeOptions retains effective selection and resource options for exact
// reconstruction; transport/renderer implementations remain caller supplied.
type NativeOptions struct {
	MaxCandidates int
	Limits        policy.Limits
}

type NativeRenderer interface {
	RenderNative(context.Context, *fm.Firewall, *fm.Firewall, NativeChanges) ([]string, error)
}

func (p *Plan) NativeChanges() NativeChanges { return cloneNativeChanges(p.nativeChanges) }
func (p *Plan) NATProof() *policy.NATProof {
	if p.natProof == nil {
		return nil
	}
	v := *p.natProof
	return &v
}
func cloneNativeAdditions(a NativeAdditions) NativeAdditions {
	d := fm.Data{Rules: a.Rules, Addresses: a.Addresses, Services: a.Services, StaticNATs: a.StaticNATs, DynamicNATs: a.DynamicNATs, NATPools: a.NATPools, Schedules: a.Schedules}
	out := d.Clone()
	return NativeAdditions{Rules: out.Rules, Addresses: out.Addresses, Services: out.Services, StaticNATs: out.StaticNATs, DynamicNATs: out.DynamicNATs, NATPools: out.NATPools, Schedules: out.Schedules}
}
func cloneNativeChanges(c NativeChanges) NativeChanges {
	out := NativeChanges{Rules: cloneChanges(c.Rules), Additions: cloneNativeAdditions(c.Additions)}
	if c.Clock != nil {
		v := *c.Clock
		out.Clock = &v
	}
	return out
}
func cloneNativeInputs(in []NativeRequest) []NativeRequest {
	out := slices.Clone(in)
	for i := range out {
		out[i].Additions = cloneNativeAdditions(out[i].Additions)
		if out[i].Lifetime != nil {
			v := *out[i].Lifetime
			out[i].Lifetime = &v
		}
		out[i].Sources = slices.Clone(out[i].Sources)
		if out[i].Packet != nil {
			v := *out[i].Packet
			out[i].Packet = &v
		}
		out[i].NAT = slices.Clone(out[i].NAT)
		for j := range out[i].NAT {
			out[i].NAT[j].Steps = slices.Clone(out[i].NAT[j].Steps)
			if out[i].NAT[j].Window != nil {
				v := *out[i].NAT[j].Window
				out[i].NAT[j].Window = &v
			}
		}
	}
	return out
}
func nativeAppend(d *fm.Data, a NativeAdditions) {
	d.Rules = append(d.Rules, a.Rules...)
	d.Addresses = append(d.Addresses, a.Addresses...)
	d.Services = append(d.Services, a.Services...)
	d.StaticNATs = append(d.StaticNATs, a.StaticNATs...)
	d.DynamicNATs = append(d.DynamicNATs, a.DynamicNATs...)
	d.NATPools = append(d.NATPools, a.NATPools...)
	d.Schedules = append(d.Schedules, a.Schedules...)
}

// ValidateNativeChanges checks the entire typed delta, all dependencies, names,
// existing declaration identity and native order. It does not authorize writes.
func ValidateNativeChanges(ctx context.Context, before, after *fm.Firewall, c NativeChanges) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if before == nil || after == nil || !before.Complete() || !after.Complete() {
		return ErrInvalid
	}
	a, err := newAdditions(before, c.Additions)
	if err != nil {
		return err
	}
	if len(a.Rules) != len(c.Additions.Rules) || len(a.Addresses) != len(c.Additions.Addresses) || len(a.Services) != len(c.Additions.Services) || len(a.StaticNATs) != len(c.Additions.StaticNATs) || len(a.DynamicNATs) != len(c.Additions.DynamicNATs) || len(a.NATPools) != len(c.Additions.NATPools) || len(a.Schedules) != len(c.Additions.Schedules) {
		return fmt.Errorf("%w: delta includes reused declarations", ErrInvalid)
	}
	if len(c.Rules) != len(a.Rules) {
		return ErrInvalid
	}
	for i, r := range a.Rules {
		change := c.Rules[i]
		if change.Kind != CreateRule || change.Rule != r.ID || !sameMembers(change.Sources, r.Match.Sources) || !sameMembers(change.Destinations, r.Match.Destinations) || !sameMembers(change.Services, r.Match.Services) {
			return ErrInvalid
		}
	}
	if err := validateScheduleChanges(before, after, c); err != nil {
		return err
	}
	if err := validateNativeInlineOwnership(c.Additions); err != nil {
		return err
	}
	expected := before.Export()
	nativeAppend(&expected, a)
	chains := map[policy.RuleChain][]fm.ID{}
	for r := range before.OrderedRules() {
		key := policy.NativeRuleOrder(before.Metadata().Vendor, r.Record()).Chain
		chains[key] = append(chains[key], r.ID())
	}
	for r := range after.OrderedRules() {
		if before.Rule(r.ID()) == nil {
			continue
		}
		key := policy.NativeRuleOrder(after.Metadata().Vendor, r.Record()).Chain
		ids := chains[key]
		if len(ids) == 0 || ids[0] != r.ID() {
			return ErrInvalid
		}
		chains[key] = ids[1:]
	}
	for i := range expected.Rules {
		if r := after.Rule(expected.Rules[i].ID); r != nil {
			expected.Rules[i].Position = r.Position()
		}
	}
	want, err := normalized(expected)
	if err != nil {
		return err
	}
	got, err := normalized(after.Export())
	if err != nil {
		return err
	}
	if want.SemanticDigest() != got.SemanticDigest() {
		return fmt.Errorf("%w: undeclared native delta", ErrInvalid)
	}
	return ctx.Err()
}
func addRecords[T any](old, add []T, object func(T) fm.Object) ([]T, error) {
	return addNativeRecords(old, add, object, func(r T) string { return nativeNameKey(object(r)) }, false)
}
func addNativeRecords[T any](old, add []T, object func(T) fm.Object, key func(T) string, inline bool) ([]T, error) {
	var out []T
	byID := map[fm.ID]T{}
	names := map[string]fm.ID{}
	for _, r := range old {
		o := object(r)
		byID[o.ID] = r
		names[key(r)] = o.ID
	}
	for _, r := range add {
		o := object(r)
		if o.ID == "" || o.Inline && !inline || len(o.Unsupported) > 0 {
			return nil, ErrInvalid
		}
		if prior, ok := byID[o.ID]; ok {
			if !reflect.DeepEqual(prior, r) {
				return nil, fmt.Errorf("%w: native identity collision %s", ErrInvalid, o.ID)
			}
			continue
		}
		if names[key(r)] != "" {
			return nil, fmt.Errorf("%w: native name collision %s", ErrInvalid, o.Name)
		}
		byID[o.ID] = r
		names[key(r)] = o.ID
		out = append(out, r)
	}
	return out, nil
}
func nativeNameKey(o fm.Object) string {
	name := o.Name
	if name == "" {
		name = string(o.ID)
	}
	return o.Scope + "\x00" + name
}
func newAdditions(before *fm.Firewall, a NativeAdditions) (NativeAdditions, error) {
	d := before.Export()
	var out NativeAdditions
	var err error
	out.Rules, err = addRecords(d.Rules, a.Rules, func(r fm.RuleRecord) fm.Object { return r.Object })
	if err != nil {
		return out, err
	}
	out.Addresses, err = addNativeRecords(d.Addresses, a.Addresses, func(r fm.AddressRecord) fm.Object { return r.Object }, func(r fm.AddressRecord) string { return nativeNameKey(r.Object) }, true)
	if err != nil {
		return out, err
	}
	out.Services, err = addNativeRecords(d.Services, a.Services, func(r fm.ServiceRecord) fm.Object { return r.Object }, func(r fm.ServiceRecord) string { return nativeNameKey(r.Object) }, true)
	if err != nil {
		return out, err
	}
	out.StaticNATs, err = addNativeRecords(d.StaticNATs, a.StaticNATs, func(r fm.StaticNATRecord) fm.Object { return r.Object }, func(r fm.StaticNATRecord) string {
		return nativeNATKey(d.Metadata.Vendor, r.Object, r.Order, r.SourceVIP != (fm.AddressRef{}))
	}, false)
	if err != nil {
		return out, err
	}
	out.DynamicNATs, err = addNativeRecords(d.DynamicNATs, a.DynamicNATs, func(r fm.DynamicNATRecord) fm.Object { return r.Object }, func(r fm.DynamicNATRecord) string { return nativeNATKey(d.Metadata.Vendor, r.Object, r.Order, false) }, false)
	if err != nil {
		return out, err
	}
	out.NATPools, err = addRecords(d.NATPools, a.NATPools, func(r fm.NATPoolRecord) fm.Object { return r.Object })
	if err != nil {
		return out, err
	}
	out.Schedules, err = addRecords(d.Schedules, a.Schedules, func(r fm.ScheduleRecord) fm.Object { return r.Object })
	if err != nil {
		return out, err
	}
	combined := d
	nativeAppend(&combined, out)
	if err := validVIPProjections(d.Metadata.Vendor, combined); err != nil {
		return out, err
	}
	names := map[string]bool{}
	for _, n := range d.StaticNATs {
		names[nativeNATKey(d.Metadata.Vendor, n.Object, n.Order, n.SourceVIP != (fm.AddressRef{}))] = true
	}
	for _, n := range d.DynamicNATs {
		names[nativeNATKey(d.Metadata.Vendor, n.Object, n.Order, false)] = true
	}
	for _, n := range out.StaticNATs {
		key := nativeNATKey(d.Metadata.Vendor, n.Object, n.Order, n.SourceVIP != (fm.AddressRef{}))
		if names[key] {
			return out, fmt.Errorf("%w: shared native nat name", ErrInvalid)
		}
		names[key] = true
	}
	for _, n := range out.DynamicNATs {
		key := nativeNATKey(d.Metadata.Vendor, n.Object, n.Order, false)
		if names[key] {
			return out, fmt.Errorf("%w: shared native nat name", ErrInvalid)
		}
		names[key] = true
	}
	addressGroups, serviceGroups := map[string]bool{}, map[string]bool{}
	for _, g := range d.AddressGroups {
		addressGroups[nativeNameKey(g.Object)] = true
	}
	for _, g := range d.ServiceGroups {
		serviceGroups[nativeNameKey(g.Object)] = true
	}
	for _, a := range out.Addresses {
		if addressGroups[nativeNameKey(a.Object)] {
			return out, ErrInvalid
		}
	}
	for _, a := range out.Services {
		if serviceGroups[nativeNameKey(a.Object)] {
			return out, ErrInvalid
		}
	}
	for _, n := range out.DynamicNATs {
		if n.Rule != "" && before.Rule(n.Rule) != nil {
			return out, fmt.Errorf("%w: existing nat owner", ErrInvalid)
		}
	}
	return out, nil
}
func nativeDiff(before, after *fm.Firewall) NativeChanges {
	d := after.Export()
	a := NativeAdditions{}
	for _, r := range d.Rules {
		if before.Rule(r.ID) == nil {
			a.Rules = append(a.Rules, r)
		}
	}
	for _, r := range d.Addresses {
		if before.Address(r.ID) == nil {
			a.Addresses = append(a.Addresses, r)
		}
	}
	for _, r := range d.Services {
		if before.Service(r.ID) == nil {
			a.Services = append(a.Services, r)
		}
	}
	for _, r := range d.StaticNATs {
		if before.StaticNAT(r.ID) == nil {
			a.StaticNATs = append(a.StaticNATs, r)
		}
	}
	for _, r := range d.DynamicNATs {
		if before.DynamicNAT(r.ID) == nil {
			a.DynamicNATs = append(a.DynamicNATs, r)
		}
	}
	for _, r := range d.NATPools {
		if before.NATPool(r.ID) == nil {
			a.NATPools = append(a.NATPools, r)
		}
	}
	for _, r := range d.Schedules {
		if before.Schedule(r.ID) == nil {
			a.Schedules = append(a.Schedules, r)
		}
	}
	c := NativeChanges{Additions: a}
	for _, r := range a.Rules {
		c.Rules = append(c.Rules, Change{Kind: CreateRule, Rule: r.ID, Sources: r.Match.Sources, Destinations: r.Match.Destinations, Services: r.Match.Services})
	}
	return c
}

// PlanNativeBatch makes one isolated complete candidate per input. Rejected
// inputs retain provenance but contribute no declarations, names, or commands.
func (p Planner) PlanNativeBatch(ctx context.Context, fw *fm.Firewall, requests []NativeRequest) (result BatchResult, err error) {
	if err = ctx.Err(); err != nil {
		return result, err
	}
	if fw == nil || !fw.Complete() || len(requests) == 0 || len(requests) > 100 {
		return result, ErrInvalid
	}
	if err = PreflightNativeRequests(ctx, requests, p.Engine.Limits); err != nil {
		return result, err
	}
	inputs := cloneNativeInputs(requests)
	result.Version = 2
	for _, input := range inputs {
		if input.Lifetime != nil {
			result.Version = 3
			break
		}
	}
	visits := visitBudget(p.Engine.Limits.WithDefaults().MaxVisits)
	current := fw
	var accepted []NativeRequest
	attempts := 0
	maxAttempts := p.MaxCandidates
	if maxAttempts <= 0 {
		maxAttempts = 128
	}
	for index, input := range inputs {
		row := BatchInput{Index: index, Request: input.Request, Disposition: BatchRejected}
		result.Inputs = append(result.Inputs, row)
		if attempts >= maxAttempts {
			return result, policy.ErrBudget
		}
		attempts++
		if err = visits.takeGraphs(ctx, current); err != nil {
			return result, err
		}
		candidate, candidateErr := p.nativeCandidate(ctx, current, input, &visits)
		if candidateErr == nil {
			joined := append(slices.Clone(accepted), input)
			_, _, candidateErr = p.proveNative(ctx, fw, candidate, joined, &visits)
			if candidateErr == nil {
				changes := nativeDiff(fw, candidate)
				changes.Clock, candidateErr = nativeClock(joined)
				if candidateErr == nil {
					candidateErr = ValidateNativeChanges(ctx, fw, candidate, changes)
				}
				if candidateErr == nil {
					_, candidateErr = p.renderNative(ctx, fw, candidate, changes)
					if candidateErr != nil && !representationRejected(candidateErr) {
						return result, candidateErr
					}
				}
			}
			if candidateErr == nil {
				current = candidate
				accepted = joined
				result.Inputs[index].Disposition = BatchAccepted
				if current.SemanticDigest() == fw.SemanticDigest() {
					result.Inputs[index].Disposition = BatchCovered
				}
			}
		}
		if candidateErr != nil {
			if computationFailed(candidateErr) || ctx.Err() != nil {
				return result, candidateErr
			}
			result.Inputs[index].Attempts = []BatchAttempt{{Stage: PreservationRejection, Reason: candidateErr.Error()}}
		}
	}
	if len(accepted) == 0 {
		return result, nil
	}
	proof, natProof, err := p.proveNative(ctx, fw, current, accepted, &visits)
	if err != nil {
		return result, err
	}
	changes := nativeDiff(fw, current)
	changes.Clock, err = nativeClock(accepted)
	if err != nil {
		return result, err
	}
	if err = ValidateNativeChanges(ctx, fw, current, changes); err != nil {
		return result, err
	}
	commands, err := p.renderNative(ctx, fw, current, changes)
	if err != nil {
		return result, err
	}
	if err = p.preflightReadback(ctx, fw, current); err != nil {
		return result, err
	}
	out := &Plan{before: fw, after: current, changes: changes.Rules, commands: commands, proof: proof, engine: p.Engine, intent: nativeIntent{inputs: inputs, accepted: cloneNativeInputs(accepted), options: NativeOptions{MaxCandidates: maxAttempts, Limits: p.Engine.Limits.WithDefaults()}}, nativeChanges: changes, natProof: natProof}
	out.cost = Cost{NewRules: len(changes.Rules), NewObjects: len(changes.Additions.Addresses) + len(changes.Additions.Services) + len(changes.Additions.StaticNATs) + len(changes.Additions.DynamicNATs) + len(changes.Additions.NATPools) + len(changes.Additions.Schedules)}
	if err = out.seal(); err != nil {
		return result, err
	}
	result.Plan = out
	return result, nil
}
func (p Planner) nativeCandidate(ctx context.Context, fw *fm.Firewall, input NativeRequest, visits *visitBudget) (*fm.Firewall, error) {
	if err := validateNativeOwnership(input); err != nil {
		return nil, err
	}
	q := scheduleRequest(input)
	if err := validateScheduleInput(fw, input); err != nil {
		return nil, err
	}
	if q.Traffic.Empty() {
		return nil, ErrInvalid
	}
	if err := visits.take(ctx, len(input.Additions.Rules)+len(input.Additions.Addresses)+len(input.Additions.Services)+len(input.Additions.StaticNATs)+len(input.Additions.DynamicNATs)+len(input.Additions.NATPools)+len(input.Additions.Schedules)); err != nil {
		return nil, err
	}
	a, err := newAdditions(fw, input.Additions)
	if err != nil {
		return nil, err
	}
	d := fw.Export()
	nativeAppend(&d, a)
	candidate, err := fm.Seal(d)
	if err != nil || !candidate.Complete() {
		return nil, ErrUnsafe
	}
	evaluated, err := p.Engine.Query(ctx, candidate, q)
	if err != nil {
		return nil, err
	}
	if !evaluated.Complete || !evaluated.Unknown.Empty() {
		return nil, ErrUnsafe
	}
	gap, err := q.Traffic.Difference(evaluated.Allowed, p.Engine.Limits.WithDefaults().MaxRegions)
	if err != nil {
		return nil, err
	}
	if !gap.Empty() {
		candidate, _, _, err = createCandidate(ctx, candidate, q, gap, visits)
		if err != nil {
			return nil, err
		}
	}
	if input.Lifetime != nil && !gap.Empty() {
		data := candidate.Export()
		for i := range data.Rules {
			if fw.Rule(data.Rules[i].ID) == nil {
				data.Rules[i].Match.Schedule = input.Lifetime.Schedule
			}
		}
		candidate, err = fm.Seal(data)
		if err != nil || !candidate.Complete() {
			return nil, ErrUnsafe
		}
	}
	return candidate, nil
}
func (p Planner) renderNative(ctx context.Context, before, after *fm.Firewall, c NativeChanges) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	a := c.Additions
	if len(c.Rules)+len(a.Rules)+len(a.Addresses)+len(a.Services)+len(a.StaticNATs)+len(a.DynamicNATs)+len(a.NATPools)+len(a.Schedules) == 0 {
		return nil, nil
	}
	if dependency.Nil(p.NativeRenderer) {
		return nil, fmt.Errorf("%w: native renderer required", ErrRender)
	}
	commands, err := p.NativeRenderer.RenderNative(ctx, before, after, cloneNativeChanges(c))
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return slices.Clone(commands), err
}
func (p Planner) proveNative(ctx context.Context, before, after *fm.Firewall, inputs []NativeRequest, visits *visitBudget) (Proof, *policy.NATProof, error) {
	var targets []policy.Request
	var intents []policy.NATIntent
	var windows []fm.TimeWindow
	for _, i := range inputs {
		targets = append(targets, scheduleRequest(i))
		var window fm.TimeWindow
		if i.Lifetime != nil {
			window = i.Lifetime.Window
		}
		windows = append(windows, window)
		for _, n := range i.NAT {
			n.Request = normalizedRequest(n.Request)
			if i.Lifetime != nil {
				n.Window = &window
				n.Request.At = window.Start
			}
			intents = append(intents, n)
		}
	}
	proof, err := p.proveBatchPolicyWindows(ctx, before, after, targets, windows, nil, visits, len(intents) == 0)
	if err != nil {
		return Proof{}, nil, err
	}
	if len(intents) == 0 {
		for _, input := range inputs {
			if input.Packet != nil {
				if err := p.proveScheduledPacket(ctx, before, after, input); err != nil {
					return Proof{}, nil, err
				}
			}
		}
		return proof, nil, nil
	}
	natProof, err := p.Engine.ProveNATEffects(ctx, before, after, intents)
	if err != nil {
		return Proof{}, nil, err
	}
	for _, input := range inputs {
		if input.Packet != nil {
			if err := p.proveScheduledPacket(ctx, before, after, input); err != nil {
				return Proof{}, nil, err
			}
		}
	}
	proof.NATUnchanged = false
	return proof, &natProof, nil
}

func validateNativeOwnership(input NativeRequest) error {
	steps := map[fm.NATRef]bool{}
	pools := map[fm.ID]bool{}
	addresses := map[fm.ID]bool{}
	services := map[fm.ID]bool{}
	match := func(m fm.Match) {
		for _, r := range append(slices.Clone(m.Sources), m.Destinations...) {
			if r.Kind == fm.AddressObject {
				addresses[r.ID] = true
			}
		}
		for _, r := range m.Services {
			if r.Kind == fm.ServiceObject {
				services[r.ID] = true
			}
		}
	}
	for _, n := range input.NAT {
		for _, s := range n.Steps {
			steps[fm.NATRef{Kind: s.Kind, ID: s.ID}] = true
		}
	}
	for _, r := range input.Additions.Rules {
		if r.Disabled || r.Builtin || r.Action != fm.Permit {
			return ErrInvalid
		}
		match(r.Match)
	}
	for _, n := range input.Additions.StaticNATs {
		ownedProjection := false
		if n.SourceVIP.Kind == fm.AddressObject {
			for _, a := range input.Additions.Addresses {
				if a.ID == n.SourceVIP.ID && steps[a.VIP] {
					ownedProjection = true
					break
				}
			}
		}
		if !steps[fm.NATRef{Kind: fm.StaticNATObject, ID: n.ID}] && !ownedProjection || n.Disabled {
			return ErrInvalid
		}
		match(n.Match)
		if n.SourceVIP.Kind == fm.AddressObject {
			addresses[n.SourceVIP.ID] = true
		}
	}
	for _, n := range input.Additions.DynamicNATs {
		if !steps[fm.NATRef{Kind: fm.DynamicNATObject, ID: n.ID}] || n.Disabled {
			return ErrInvalid
		}
		match(n.Match)
		pools[n.SourcePool], pools[n.DestinationPool] = true, true
	}
	for _, r := range input.Additions.NATPools {
		if !pools[r.ID] {
			return fmt.Errorf("%w: unowned nat pool", ErrInvalid)
		}
	}
	for _, r := range input.Additions.Addresses {
		if !addresses[r.ID] {
			return fmt.Errorf("%w: unowned address", ErrInvalid)
		}
	}
	for _, r := range input.Additions.Services {
		if !services[r.ID] {
			return fmt.Errorf("%w: unowned service", ErrInvalid)
		}
	}
	for _, s := range input.Additions.Schedules {
		if input.Lifetime == nil || input.Lifetime.Schedule != s.ID {
			return ErrInvalid
		}
	}
	return nil
}

func (r NativeRequest) Clone() NativeRequest { return cloneNativeInputs([]NativeRequest{r})[0] }
func (p Planner) proveNativePacket(ctx context.Context, fw *fm.Firewall, input NativeRequest) error {
	result, err := p.Engine.QueryPacket(ctx, fw, *input.Packet)
	if err != nil {
		return err
	}
	if !result.Complete || !result.Unknown.Empty() {
		return ErrUnsafe
	}
	limit := p.Engine.Limits.WithDefaults().MaxRegions
	var covered flow.Traffic
	target := normalizedRequest(input.Request)
	for _, path := range result.Paths {
		if !path.Policy.Complete || !path.Policy.Unknown.Empty() || !path.Policy.Denied.Empty() || !path.Policy.Unmatched.Empty() || path.Policy.Allowed.Empty() {
			return ErrUnsafe
		}
		if len(path.NativeRequests) != 1 {
			return ErrUnsafe
		}
		native := normalizedRequest(path.NativeRequests[0])
		if native.Scope != target.Scope || native.RuleSet != target.RuleSet || native.FromZone != target.FromZone || native.ToZone != target.ToZone {
			return ErrUnsafe
		}
		ok, err := target.Traffic.Contains(native.Traffic, limit)
		if err != nil {
			return err
		}
		if !ok {
			return ErrUnsafe
		}
		covered, err = covered.Union(path.Original, limit)
		if err != nil {
			return err
		}
	}
	same, err := covered.Equal(input.Packet.Traffic, limit)
	if err != nil {
		return err
	}
	if !same {
		return ErrUnsafe
	}
	return nil
}

func nativeTrafficRegions(t flow.Traffic) []flow.TrafficRegion {
	regions := t.Regions()
	slices.SortFunc(regions, compareBatchRegion)
	return regions
}
