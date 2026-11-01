package operations

import (
	"context"
	"errors"
	"slices"
	"sort"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/internal/dependency"
	"github.com/gatework/firemon/inventory"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/policy"
	"github.com/gatework/firemon/snapshot"
	"github.com/gatework/firemon/vendors"
)

// BatchStore reads one manifest then immutable revisions. Current is deliberately
// absent: it would recapture a potentially different generation for each input.
type BatchStore interface {
	inventory.ManifestReader
	inventory.RevisionLoader
}
type BatchDesignerOptions struct {
	Store          BatchStore
	NativeRenderer plan.NativeRenderer
	Engine         policy.Engine
	MaxCandidates  int
	Timeout        time.Duration
}
type BatchDesigner struct{ options BatchDesignerOptions }

func NewBatchDesigner(o BatchDesignerOptions) (*BatchDesigner, error) {
	if dependency.Nil(o.Store) || o.NativeRenderer != nil && dependency.Nil(o.NativeRenderer) || o.MaxCandidates < 0 || o.Timeout < 0 {
		return nil, ErrInvalid
	}
	return &BatchDesigner{options: o}, nil
}

type BatchRequest struct {
	Version  int
	Requests []AccessRequest
	Topology *inventory.Topology
}

// AccessRequest preserves the business input. Automatic location uses Original
// wire coordinates unless an explicit view is supplied. Scope/VRF nil means all.
type AccessRequest struct {
	Native         *NativeEffects
	ID             string
	Traffic        flow.Traffic
	View           inventory.View
	Scope, VRF     *string
	At             time.Time
	Targets        []AccessTarget
	WireCandidates []WireCandidate
	Sources        []string
}

// AccessTarget is an explicit policy view by default. Packet=true requests native
// packet traversal; its FromZone is explicit ingress evidence, never a route guess.
// Request.Traffic must be empty; AccessRequest owns the exact input traffic.
// WireCandidate proposes a wire request for translated business traffic. It is
// accepted only after exact forward packet traversal proves the translated view.
type WireCandidate struct {
	Traffic flow.Traffic
	Target  AccessTarget
}

type AccessTarget struct {
	Device, Revision string
	Request          policy.Request
	VRF              string
	Packet           bool
}
type Issue struct {
	Input                        int
	TrafficView                  string
	Device, Stage, Code, Message string
	Traffic                      flow.Traffic
	Sources                      []string
}
type TargetOutcome struct {
	Device, Revision string
	Wire             flow.Traffic
	Real             flow.Traffic
	NativeRequests   []policy.Request
	Sources          []string
	Policy           policy.Result
	NAT              policy.NATRelation
	Disposition      plan.BatchDisposition
}
type RequestOutcome struct {
	Index    int
	Request  AccessRequest
	Outcomes []TargetOutcome
}

// BatchSource connects a device-local PlanBatch input to the original business input.
type BatchSource struct{ Index, Input, Outcome int }
type DevicePlan struct {
	Sources                          []BatchSource
	Device, Revision, SemanticDigest string
	Batch                            plan.BatchResult
}
type BatchReport struct {
	Topology   *inventory.Topology
	Version    int
	Generation uint64
	Inputs     []RequestOutcome
	Devices    []DevicePlan
	Issues     []Issue
}

type batchWork struct {
	native         *plan.NativeRequest
	input, outcome int
	request        policy.Request
	packet         *policy.PacketRequest
	viewTraffic    *flow.Traffic
	trafficView    string
	view           policy.AliasView
}
type batchRun struct {
	designer   BatchDesigner
	manifest   snapshot.Manifest
	report     BatchReport
	graphs     map[string]*fm.Firewall
	loadErrors map[string]error
	work       map[string][]batchWork
	visits     int
	emitted    int
	budgetErr  error
	issueBytes int
}

func (d BatchDesigner) Design(ctx context.Context, q BatchRequest) (BatchReport, error) {
	return d.run(ctx, q, true)
}
func (d BatchDesigner) Query(ctx context.Context, q BatchRequest) (BatchReport, error) {
	return d.run(ctx, q, false)
}
func (d BatchDesigner) run(ctx context.Context, q BatchRequest, design bool) (report BatchReport, err error) {
	if err = ctx.Err(); err != nil {
		return report, err
	}
	if dependency.Nil(d.options.Store) || q.Version != 1 || len(q.Requests) == 0 || len(q.Requests) > 100 {
		return report, ErrInvalid
	}
	if err = preflightBusinessNative(ctx, q.Requests, d.options.Engine.Limits); err != nil {
		return report, err
	}
	if q.Topology != nil {
		if err = q.Topology.Validate(); err != nil {
			return report, err
		}
		frozen := *q.Topology
		frozen.Bindings = slices.Clone(q.Topology.Bindings)
		for i := range frozen.Bindings {
			frozen.Bindings[i].Networks = slices.Clone(frozen.Bindings[i].Networks)
			frozen.Bindings[i].Sources = slices.Clone(frozen.Bindings[i].Sources)
		}
		q.Topology = &frozen
	}
	totalRegions := 0
	for _, a := range q.Requests {
		totalRegions += a.Traffic.RegionCount()
		if a.Native != nil {
			if len(a.Targets) != 1 || len(a.WireCandidates) != 0 || (a.View != "" && a.View != inventory.Original) {
				return report, ErrInvalid
			}
			totalRegions += a.Native.PolicyTraffic.RegionCount()
			for _, n := range a.Native.NAT {
				totalRegions += n.Request.Traffic.RegionCount()
			}
		}
		if a.View != "" && a.View != inventory.Original && a.View != inventory.Real && a.View != inventory.Translated {
			return report, ErrInvalid
		}
		if len(a.WireCandidates) > 100 || len(a.WireCandidates) > 0 && (len(a.Targets) > 0 || (a.View != inventory.Translated && a.View != inventory.Real)) {
			return report, ErrInvalid
		}
		for _, c := range a.WireCandidates {
			totalRegions += c.Traffic.RegionCount()
			if c.Target.Device == "" || !c.Target.Request.Traffic.Empty() || c.Traffic.Empty() {
				return report, ErrInvalid
			}
		}
		if totalRegions > d.options.Engine.Limits.WithDefaults().MaxRegions {
			return report, ErrInvalid
		}
		if len(a.Targets) > 100 || a.Traffic.RegionCount() > d.options.Engine.Limits.WithDefaults().MaxRegions {
			return report, ErrInvalid
		}
		for _, t := range a.Targets {
			if t.Device == "" || !t.Request.Traffic.Empty() {
				return report, ErrInvalid
			}
		}
	}
	ctx, cancel := operationContext(ctx, d.options.Timeout)
	defer cancel()
	manifest, err := d.options.Store.Manifest(ctx)
	if err != nil {
		return report, err
	}
	if err = ctx.Err(); err != nil {
		return report, err
	}
	if manifest.Version != 1 {
		return report, snapshot.ErrFormat
	}
	// Detach maps from custom stores before any Load callback can advance state.
	frozen := snapshot.Manifest{Version: manifest.Version, Generation: manifest.Generation, Devices: make(map[string]snapshot.Head), Reservations: make(map[string]snapshot.Reservation)}
	for k, v := range manifest.Devices {
		frozen.Devices[k] = v
	}
	for k, v := range manifest.Reservations {
		frozen.Reservations[k] = v
	}
	r := batchRun{designer: d, manifest: frozen, report: BatchReport{Version: 1, Generation: frozen.Generation, Topology: q.Topology}, graphs: make(map[string]*fm.Firewall), loadErrors: make(map[string]error), work: make(map[string][]batchWork), visits: d.options.Engine.Limits.WithDefaults().MaxVisits}
	defer func() {
		if err != nil {
			for i := range report.Devices {
				report.Devices[i].Batch.Plan = nil
			}
		}
	}()
	for i, a := range q.Requests {
		a.Native = cloneNativeEffects(a.Native)
		a.Targets = slices.Clone(a.Targets)
		a.WireCandidates = slices.Clone(a.WireCandidates)
		a.Sources = slices.Clone(a.Sources)
		if a.Scope != nil {
			v := *a.Scope
			a.Scope = &v
		}
		if a.VRF != nil {
			v := *a.VRF
			a.VRF = &v
		}
		r.report.Inputs = append(r.report.Inputs, RequestOutcome{Index: i, Request: a})
		inputView := string(a.View)
		if inputView == "" {
			inputView = string(inventory.Original)
		}
		if a.Traffic.Empty() {
			r.issue(i, "", "input", "empty_request", a.Traffic, inputView, nil, "")
			continue
		}
		if len(a.WireCandidates) > 0 {
			if err = r.candidates(ctx, i, a, design); err != nil {
				return r.report, err
			}
		} else if len(a.Targets) > 0 {
			for _, target := range a.Targets {
				if target.Packet && a.View != "" && a.View != inventory.Original {
					r.issue(i, target.Device, "nat", "wire_evidence_required", a.Traffic, inputView, nil, "")
					continue
				}
				if err = r.target(ctx, i, a.Traffic, target, nil, design); err != nil {
					return r.report, err
				}
			}
		} else {
			if q.Topology == nil {
				r.issue(i, "", "location", "topology_missing", a.Traffic, inputView, nil, "")
				continue
			}
			if err = r.locate(ctx, i, a, *q.Topology, design); err != nil {
				return r.report, err
			}
		}
	}
	if r.budgetErr != nil {
		return r.report, r.budgetErr
	}
	if design {
		if err = r.compile(ctx); err != nil {
			return r.report, err
		}
	}
	if r.budgetErr != nil {
		return r.report, r.budgetErr
	}
	return r.report, ctx.Err()
}
func (r *batchRun) charge(ctx context.Context) error {
	if r.budgetErr != nil {
		return r.budgetErr
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if r.visits <= 0 {
		return policy.ErrBudget
	}
	r.visits--
	return nil
}
func (r *batchRun) issue(input int, device, stage, code string, t flow.Traffic, view string, sources []string, message string) {
	if err := r.emit(max(1, t.RegionCount())); err != nil {
		return
	}
	refs := slices.Clone(r.report.Inputs[input].Request.Sources)
	refs = append(refs, sources...)
	size := 1024*max(1, t.RegionCount()) + 6*(len(device)+len(stage)+len(code)+len(message))
	for _, ref := range refs {
		size += 6*len(ref) + 3
	}
	if r.issueBytes+size > MaxRequestBytes {
		r.budgetErr = policy.ErrBudget
		return
	}
	r.issueBytes += size

	r.report.Issues = append(r.report.Issues, Issue{Input: input, TrafficView: view, Device: device, Stage: stage, Code: code, Traffic: t, Sources: refs, Message: message})
}
func (r *batchRun) load(ctx context.Context, input int, t flow.Traffic, view string, target AccessTarget, sources []string) (*fm.Firewall, error) {
	if err := r.charge(ctx); err != nil {
		return nil, err
	}
	h, ok := r.manifest.Devices[target.Device]
	code := ""
	switch {
	case !ok:
		code = "snapshot_missing"
	case r.manifest.Reservations[target.Device].Token != "":
		code = "snapshot_reserved"
	case !h.Complete:
		code = "snapshot_incomplete"
	case target.Revision != "" && target.Revision != h.Revision:
		code = "stale_topology"
	}
	if _, reserved := r.manifest.Reservations[target.Device]; reserved {
		code = "snapshot_reserved"
	}
	if code != "" {
		r.issue(input, target.Device, "snapshot", code, t, view, sources, "")
		return nil, nil
	}
	fw, seen := r.graphs[h.Revision]
	loadErr := r.loadErrors[h.Revision]
	if !seen && loadErr == nil {
		fw, loadErr = r.designer.options.Store.Load(ctx, h.Revision)
		if loadErr == nil && fw == nil {
			loadErr = snapshot.ErrFormat
		}
		if loadErr == nil {
			r.graphs[h.Revision] = fw
		} else {
			r.loadErrors[h.Revision] = loadErr
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if loadErr != nil {
		r.issue(input, target.Device, "snapshot", "snapshot_load", t, view, sources, loadErr.Error())
		return nil, nil
	}
	if fw.Metadata().Device != target.Device || !fw.Complete() || h.Revision == "" || fw.SemanticDigest() != h.SemanticDigest || fw.Metadata().SourceDigest != h.SourceDigest {
		r.issue(input, target.Device, "snapshot", "snapshot_mismatch", t, view, sources, "")
		return nil, nil
	}
	return fw, nil
}
func fatalBatch(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, policy.ErrBudget) || errors.Is(err, flow.ErrBudget)
}
func (r *batchRun) target(ctx context.Context, input int, traffic flow.Traffic, target AccessTarget, sources []string, design bool) error {
	return r.targetWithProof(ctx, input, traffic, target, sources, design, nil)
}
func (r *batchRun) targetWithProof(ctx context.Context, input int, traffic flow.Traffic, target AccessTarget, sources []string, design bool, expected *flow.Traffic) error {
	trafficView := "policy"
	if target.Packet {
		trafficView = string(inventory.Original)
	}
	fw, err := r.load(ctx, input, traffic, trafficView, target, sources)
	if err != nil || fw == nil {
		return err
	}
	q := target.Request
	q.Traffic = traffic
	if q.Scope == "" {
		q.Scope = fw.Metadata().Context
	}
	if q.RuleSet == "" {
		q.RuleSet = "security"
	}
	if q.At.IsZero() {
		q.At = r.report.Inputs[input].Request.At
	}
	if q.FromZone == "" || !target.Packet && q.ToZone == "" {
		r.issue(input, target.Device, "query", "zone_missing", traffic, trafficView, sources, "")
		return nil
	}
	if r.report.Inputs[input].Request.Native != nil {
		if !design {
			r.issue(input, target.Device, "nat", "native_intent_requires_design", traffic, trafficView, sources, "")
			return nil
		}
		return r.nativeTarget(input, traffic, target, q, sources)
	}
	if target.Packet {
		result, err := r.designer.options.Engine.QueryPacket(ctx, fw, policy.PacketRequest{Request: q, VRF: target.VRF})
		if err != nil {
			if fatalBatch(err) {
				return err
			}
			r.issue(input, target.Device, "packet", "unsupported_packet", traffic, trafficView, sources, err.Error())
			return nil
		}
		if !result.Unknown.Empty() {
			r.issue(input, target.Device, "packet", "unknown_path", result.Unknown, trafficView, sources, "")
		}
		var accounted flow.Traffic
		for _, p := range result.Paths {
			if err := r.charge(ctx); err != nil {
				return err
			}
			accounted, err = accounted.Union(p.Original, r.designer.options.Engine.Limits.WithDefaults().MaxRegions)
			if err != nil {
				return err
			}
			if expected != nil {
				limit := r.designer.options.Engine.Limits.WithDefaults().MaxRegions
				same, err := p.Original.Equal(p.NAT.Original, limit)
				if err != nil {
					return err
				}
				actual, known := p.View(policy.AliasView(r.report.Inputs[input].Request.View))
				subset, err := expected.Contains(actual, limit)
				if err != nil {
					return err
				}
				if !same || !subset || !known {
					r.issue(input, target.Device, "nat", "forward_validation_failed", p.Original, trafficView, sources, "")
					continue
				}
			}
			outcome := TargetOutcome{Device: target.Device, Revision: r.manifest.Devices[target.Device].Revision, Wire: p.Original, Real: p.Real, NativeRequests: slices.Clone(p.NativeRequests), Sources: slices.Clone(sources), Policy: p.Policy, NAT: p.NAT, Disposition: plan.BatchPending}
			if p.Policy.Complete && p.Policy.Denied.Empty() && p.Policy.Unmatched.Empty() && p.Policy.Unknown.Empty() && !p.Policy.Allowed.Empty() {
				outcome.Disposition = plan.BatchCovered
			}
			idx := len(r.report.Inputs[input].Outcomes)
			if err := r.emit(max(1, outcome.Wire.RegionCount())); err != nil {
				return err
			}
			r.report.Inputs[input].Outcomes = append(r.report.Inputs[input].Outcomes, outcome)
			uncertain, err := p.Original.Intersection(result.Unknown, r.designer.options.Engine.Limits.WithDefaults().MaxRegions)
			if err != nil {
				return err
			}
			if !uncertain.Empty() {
				r.issue(input, target.Device, "packet", "unknown_path", p.Original, trafficView, sources, "")
				continue
			}
			if !p.Policy.Complete || !p.Policy.Unknown.Empty() {
				r.issue(input, target.Device, "query", "unknown_policy", p.Original, trafficView, sources, "")
				continue
			}
			if design && p.DesignUnsupported != "" {
				if outcome.Disposition != plan.BatchCovered {
					r.issue(input, target.Device, "design", "unsupported_native_composition", p.Original, trafficView, sources, p.DesignUnsupported)
				}
				continue
			}
			if len(p.NativeRequests) != 1 {
				if outcome.Disposition != plan.BatchCovered {
					r.issue(input, target.Device, "design", "native_target_missing", p.Original, trafficView, sources, "")
				}
				continue
			}
			if design {
				packet := policy.PacketRequest{Request: q, VRF: target.VRF}
				packet.Traffic = p.Original
				w := batchWork{input: input, outcome: idx, request: p.NativeRequests[0], packet: &packet, trafficView: trafficView}
				if expected != nil {
					w.view = policy.AliasView(r.report.Inputs[input].Request.View)
					actual, _ := p.View(w.view)
					w.viewTraffic = &actual
				}
				r.work[target.Device] = append(r.work[target.Device], w)
			}
		}
		accounted, err = accounted.Union(result.Unknown, r.designer.options.Engine.Limits.WithDefaults().MaxRegions)
		if err != nil {
			return err
		}
		missing, err := traffic.Difference(accounted, r.designer.options.Engine.Limits.WithDefaults().MaxRegions)
		if err != nil {
			return err
		}
		if !missing.Empty() {
			r.issue(input, target.Device, "packet", "unknown_path", missing, trafficView, sources, "")
		}
		return nil
	}
	result, err := r.designer.options.Engine.Query(ctx, fw, q)
	if err != nil {
		if fatalBatch(err) {
			return err
		}
		r.issue(input, target.Device, "query", "query_failed", traffic, trafficView, sources, err.Error())
		return nil
	}
	idx := len(r.report.Inputs[input].Outcomes)
	o := TargetOutcome{Device: target.Device, Revision: r.manifest.Devices[target.Device].Revision, Wire: traffic, NativeRequests: []policy.Request{q}, Sources: slices.Clone(sources), Policy: result, Disposition: plan.BatchPending}
	if result.Complete && result.Denied.Empty() && result.Unmatched.Empty() && result.Unknown.Empty() {
		o.Disposition = plan.BatchCovered
	}
	if err := r.emit(max(1, o.Wire.RegionCount())); err != nil {
		return err
	}
	r.report.Inputs[input].Outcomes = append(r.report.Inputs[input].Outcomes, o)
	if !result.Complete || !result.Unknown.Empty() {
		r.issue(input, target.Device, "query", "unknown_policy", traffic, trafficView, sources, "")
		return nil
	}
	if design {
		r.work[target.Device] = append(r.work[target.Device], batchWork{input: input, outcome: idx, request: q, trafficView: trafficView})
	}
	return nil
}
func (r *batchRun) compile(ctx context.Context) error {
	devices := make([]string, 0, len(r.work))
	for device := range r.work {
		devices = append(devices, device)
	}
	sort.Strings(devices)
	for _, device := range devices {
		if err := r.charge(ctx); err != nil {
			return err
		}
		work := r.work[device]
		h := r.manifest.Devices[device]
		fw := r.graphs[h.Revision]
		renderer, err := vendors.Renderer(fw.Metadata().Vendor)
		if err != nil {
			for _, w := range work {
				r.issue(w.input, device, "design", "unsupported_renderer", r.report.Inputs[w.input].Outcomes[w.outcome].Wire, w.trafficView, r.report.Inputs[w.input].Outcomes[w.outcome].Sources, err.Error())
			}
			continue
		}
		requests := make([]policy.Request, len(work))
		for i, w := range work {
			requests[i] = w.request
		}
		planner := plan.Planner{Renderer: renderer, Engine: r.designer.options.Engine, MaxCandidates: r.designer.options.MaxCandidates}
		var result plan.BatchResult
		hasNative := false
		for _, w := range work {
			hasNative = hasNative || w.native != nil
		}
		if hasNative {
			planner.NativeRenderer = r.designer.options.NativeRenderer
			if planner.NativeRenderer == nil {
				planner.NativeRenderer, _ = renderer.(plan.NativeRenderer)
			}
			nativeRequests := make([]plan.NativeRequest, len(work))
			for i, w := range work {
				if w.native != nil {
					nativeRequests[i] = w.native.Clone()
				} else {
					nativeRequests[i] = plan.NativeRequest{Request: w.request, Packet: w.packet, Sources: r.report.Inputs[w.input].Request.Sources}
				}
			}
			result, err = planner.PlanNativeBatch(ctx, fw, nativeRequests)
		} else {
			result, err = planner.PlanBatch(ctx, fw, requests)
		}
		failureCode := "plan_failed"
		if err == nil && result.Plan != nil {
			valid, checkErr := r.recheck(ctx, result.Plan.After(), work, result)
			if checkErr != nil {
				return checkErr
			}
			if !valid {
				result.Plan = nil
				err = plan.ErrUnsafe
				failureCode = "packet_recheck_failed"
				for i := range result.Inputs {
					if result.Inputs[i].Disposition == plan.BatchAccepted {
						result.Inputs[i].Disposition = plan.BatchPending
					}
				}
			}
		}
		if fatalBatch(err) {
			return err
		}
		sources := make([]BatchSource, len(work))
		for i, w := range work {
			sources[i] = BatchSource{Index: i, Input: w.input, Outcome: w.outcome}
		}
		r.report.Devices = append(r.report.Devices, DevicePlan{Device: device, Revision: h.Revision, SemanticDigest: h.SemanticDigest, Batch: result, Sources: sources})
		for i, w := range work {
			if i < len(result.Inputs) {
				r.report.Inputs[w.input].Outcomes[w.outcome].Disposition = result.Inputs[i].Disposition
			}
			if err != nil {
				r.issue(w.input, device, "design", failureCode, r.report.Inputs[w.input].Outcomes[w.outcome].Wire, w.trafficView, r.report.Inputs[w.input].Outcomes[w.outcome].Sources, err.Error())
			} else if i < len(result.Inputs) && result.Inputs[i].Disposition == plan.BatchRejected {
				r.issue(w.input, device, "design", "plan_rejected", r.report.Inputs[w.input].Outcomes[w.outcome].Wire, w.trafficView, r.report.Inputs[w.input].Outcomes[w.outcome].Sources, "")
			}
		}
	}
	return ctx.Err()
}

func (r *batchRun) emit(count int) error {
	if r.emitted+count > r.designer.options.Engine.Limits.WithDefaults().MaxRegions {
		r.budgetErr = policy.ErrBudget
		return r.budgetErr
	}
	r.emitted += count
	return nil
}
