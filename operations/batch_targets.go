package operations

import (
	"context"
	"errors"
	"slices"
	"sort"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/inventory"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/policy"
	"github.com/gatework/firemon/snapshot"
	"github.com/gatework/firemon/vendors"
)

// targetBatch owns discovery, planning and final evidence for one frozen manifest.
// Only finish projects entries into a public report; planning never indexes it.
type targetBatch struct {
	designer   BatchDesigner
	manifest   snapshot.Manifest
	topology   *inventory.Topology
	design     bool
	inputs     []targetInput
	devices    []DevicePlan
	issues     []Issue
	graphs     map[string]*fm.Firewall
	loadErrors map[string]error
	work       map[string][]*targetEntry
	visits     int
	emitted    int
	budgetErr  error
	issueBytes int
}

type targetInput struct {
	index   int
	request AccessRequest
	entries []*targetEntry
}

// Origin uses discovery order, including entries that never reach a planner.
// Device-local BatchSource.Index is assigned only from its queued entries.
type targetOrigin struct{ input, outcome int }

// An entry keeps its report position even when it cannot become a planning input.
// Device work refers to the entry, so dispositions and proofs share one identity.
type targetEntry struct {
	origin      targetOrigin
	outcome     TargetOutcome
	trafficView string
	planning    *targetPlanning
	proof       *targetPacketProof
}

type targetPlanning struct {
	request policy.Request
	native  *plan.NativeRequest
}

type targetPacketProof struct {
	// Keep the admitted request intact; final proof may sample a copied request
	// inside a finite lifetime, without changing reconstruction material.
	packet   policy.PacketRequest
	expected *targetView
}

type targetView struct {
	view    policy.AliasView
	traffic flow.Traffic
}

type targetProposal struct {
	traffic  flow.Traffic
	target   AccessTarget
	sources  []string
	expected *targetView
}

func (r *targetBatch) resolve(ctx context.Context, i int, a AccessRequest) error {
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
	r.inputs = append(r.inputs, targetInput{index: i, request: a})
	inputView := string(a.View)
	if inputView == "" {
		inputView = string(inventory.Original)
	}
	if a.Traffic.Empty() {
		r.issue(i, "", "input", "empty_request", a.Traffic, inputView, nil, "")
		return nil
	}
	if len(a.WireCandidates) > 0 {
		if err := r.candidates(ctx, i, a); err != nil {
			return err
		}
	} else if len(a.Targets) > 0 {
		for _, target := range a.Targets {
			if target.Packet && a.View != "" && a.View != inventory.Original {
				r.issue(i, target.Device, "nat", "wire_evidence_required", a.Traffic, inputView, nil, "")
				continue
			}
			if _, err := r.evaluate(ctx, i, targetProposal{traffic: a.Traffic, target: target}); err != nil {
				return err
			}
		}
	} else {
		if r.topology == nil {
			r.issue(i, "", "location", "topology_missing", a.Traffic, inputView, nil, "")
			return nil
		}
		if err := r.locate(ctx, i, a, *r.topology); err != nil {
			return err
		}
	}
	return nil
}

// finish transfers the owned evidence to the caller, including partial discovery.
// A fatal run cannot leave a plan from an earlier device available for selection.
func (r *targetBatch) finish(runErr error) BatchReport {
	if runErr != nil {
		for i := range r.devices {
			r.devices[i].Batch.Plan = nil
		}
	}
	report := BatchReport{
		Version: 1, Generation: r.manifest.Generation, Topology: r.topology,
		Devices: r.devices, Issues: r.issues,
	}
	for _, input := range r.inputs {
		row := RequestOutcome{Index: input.index, Request: input.request}
		for _, entry := range input.entries {
			row.Outcomes = append(row.Outcomes, entry.outcome)
		}
		report.Inputs = append(report.Inputs, row)
	}
	return report
}

func (r *targetBatch) record(input int, outcome TargetOutcome, view string) (*targetEntry, error) {
	if err := r.emit(max(1, outcome.Wire.RegionCount())); err != nil {
		return nil, err
	}
	row := &r.inputs[input]
	entry := &targetEntry{
		origin:  targetOrigin{input: input, outcome: len(row.entries)},
		outcome: outcome, trafficView: view,
	}
	row.entries = append(row.entries, entry)
	return entry, nil
}

func (r *targetBatch) queue(entry *targetEntry, input targetPlanning, proof *targetPacketProof) {
	entry.planning, entry.proof = &input, proof
	device := entry.outcome.Device
	r.work[device] = append(r.work[device], entry)
}
func (r *targetBatch) charge(ctx context.Context) error {
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
func (r *targetBatch) issue(input int, device, stage, code string, t flow.Traffic, view string, sources []string, message string) {
	if err := r.emit(max(1, t.RegionCount())); err != nil {
		return
	}
	refs := slices.Clone(r.inputs[input].request.Sources)
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

	r.issues = append(r.issues, Issue{Input: input, TrafficView: view, Device: device, Stage: stage, Code: code, Traffic: t, Sources: refs, Message: message})
}
func (r *targetBatch) load(ctx context.Context, input int, t flow.Traffic, view string, target AccessTarget, sources []string) (*fm.Firewall, error) {
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
func (r *targetBatch) evaluate(ctx context.Context, input int, proposal targetProposal) (entries []*targetEntry, err error) {
	traffic, target, sources, expected := proposal.traffic, proposal.target, proposal.sources, proposal.expected
	trafficView := "policy"
	if target.Packet {
		trafficView = string(inventory.Original)
	}
	fw, err := r.load(ctx, input, traffic, trafficView, target, sources)
	if err != nil || fw == nil {
		return entries, err
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
		q.At = r.inputs[input].request.At
	}
	if q.FromZone == "" || !target.Packet && q.ToZone == "" {
		r.issue(input, target.Device, "query", "zone_missing", traffic, trafficView, sources, "")
		return entries, nil
	}
	if r.inputs[input].request.Native != nil {
		if !r.design {
			r.issue(input, target.Device, "nat", "native_intent_requires_design", traffic, trafficView, sources, "")
			return entries, nil
		}
		entry, err := r.nativeTarget(input, traffic, target, q, sources)
		if entry != nil {
			entries = append(entries, entry)
		}
		return entries, err
	}
	if target.Packet {
		result, err := r.designer.options.Engine.QueryPacket(ctx, fw, policy.PacketRequest{Request: q, VRF: target.VRF})
		if err != nil {
			if fatalBatch(err) {
				return entries, err
			}
			r.issue(input, target.Device, "packet", "unsupported_packet", traffic, trafficView, sources, err.Error())
			return entries, nil
		}
		if !result.Unknown.Empty() {
			r.issue(input, target.Device, "packet", "unknown_path", result.Unknown, trafficView, sources, "")
		}
		var accounted flow.Traffic
		for _, p := range result.Paths {
			if err := r.charge(ctx); err != nil {
				return entries, err
			}
			accounted, err = accounted.Union(p.Original, r.designer.options.Engine.Limits.WithDefaults().MaxRegions)
			if err != nil {
				return entries, err
			}
			if expected != nil {
				limit := r.designer.options.Engine.Limits.WithDefaults().MaxRegions
				same, err := p.Original.Equal(p.NAT.Original, limit)
				if err != nil {
					return entries, err
				}
				actual, known := p.View(expected.view)
				subset, err := expected.traffic.Contains(actual, limit)
				if err != nil {
					return entries, err
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
			entry, err := r.record(input, outcome, trafficView)
			if err != nil {
				return entries, err
			}
			entries = append(entries, entry)
			uncertain, err := p.Original.Intersection(result.Unknown, r.designer.options.Engine.Limits.WithDefaults().MaxRegions)
			if err != nil {
				return entries, err
			}
			if !uncertain.Empty() {
				r.issue(input, target.Device, "packet", "unknown_path", p.Original, trafficView, sources, "")
				continue
			}
			if !p.Policy.Complete || !p.Policy.Unknown.Empty() {
				r.issue(input, target.Device, "query", "unknown_policy", p.Original, trafficView, sources, "")
				continue
			}
			if r.design && p.DesignUnsupported != "" {
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
			if r.design {
				packet := policy.PacketRequest{Request: q, VRF: target.VRF}
				packet.Traffic = p.Original
				proof := &targetPacketProof{packet: packet}
				if expected != nil {
					actual, _ := p.View(expected.view)
					proof.expected = &targetView{view: expected.view, traffic: actual}
				}
				r.queue(entry, targetPlanning{request: p.NativeRequests[0]}, proof)
			}
		}
		accounted, err = accounted.Union(result.Unknown, r.designer.options.Engine.Limits.WithDefaults().MaxRegions)
		if err != nil {
			return entries, err
		}
		missing, err := traffic.Difference(accounted, r.designer.options.Engine.Limits.WithDefaults().MaxRegions)
		if err != nil {
			return entries, err
		}
		if !missing.Empty() {
			r.issue(input, target.Device, "packet", "unknown_path", missing, trafficView, sources, "")
		}
		return entries, nil
	}
	result, err := r.designer.options.Engine.Query(ctx, fw, q)
	if err != nil {
		if fatalBatch(err) {
			return entries, err
		}
		r.issue(input, target.Device, "query", "query_failed", traffic, trafficView, sources, err.Error())
		return entries, nil
	}
	o := TargetOutcome{Device: target.Device, Revision: r.manifest.Devices[target.Device].Revision, Wire: traffic, NativeRequests: []policy.Request{q}, Sources: slices.Clone(sources), Policy: result, Disposition: plan.BatchPending}
	if result.Complete && result.Denied.Empty() && result.Unmatched.Empty() && result.Unknown.Empty() {
		o.Disposition = plan.BatchCovered
	}
	entry, err := r.record(input, o, trafficView)
	if err != nil {
		return entries, err
	}
	entries = append(entries, entry)
	if !result.Complete || !result.Unknown.Empty() {
		r.issue(input, target.Device, "query", "unknown_policy", traffic, trafficView, sources, "")
		return entries, nil
	}
	if r.design {
		r.queue(entry, targetPlanning{request: q}, nil)
	}
	return entries, nil
}
func (r *targetBatch) plan(ctx context.Context) error {
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
				r.issue(w.origin.input, device, "design", "unsupported_renderer", w.outcome.Wire, w.trafficView, w.outcome.Sources, err.Error())
			}
			continue
		}
		requests := make([]policy.Request, len(work))
		for i, w := range work {
			requests[i] = w.planning.request
		}
		planner := plan.Planner{Renderer: renderer, Engine: r.designer.options.Engine, MaxCandidates: r.designer.options.MaxCandidates}
		var result plan.BatchResult
		hasNative := false
		for _, w := range work {
			hasNative = hasNative || w.planning.native != nil
		}
		if hasNative {
			planner.NativeRenderer = r.designer.options.NativeRenderer
			if planner.NativeRenderer == nil {
				planner.NativeRenderer, _ = renderer.(plan.NativeRenderer)
			}
			nativeRequests := make([]plan.NativeRequest, len(work))
			for i, w := range work {
				if w.planning.native != nil {
					nativeRequests[i] = w.planning.native.Clone()
				} else {
					nativeRequests[i] = plan.NativeRequest{Request: w.planning.request, Sources: r.inputs[w.origin.input].request.Sources}
					if w.proof != nil {
						packet := w.proof.packet
						nativeRequests[i].Packet = &packet
					}
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
			sources[i] = BatchSource{Index: i, Input: w.origin.input, Outcome: w.origin.outcome}
		}
		r.devices = append(r.devices, DevicePlan{Device: device, Revision: h.Revision, SemanticDigest: h.SemanticDigest, Batch: result, Sources: sources})
		for i, w := range work {
			if i < len(result.Inputs) {
				w.outcome.Disposition = result.Inputs[i].Disposition
			}
			if err != nil {
				r.issue(w.origin.input, device, "design", failureCode, w.outcome.Wire, w.trafficView, w.outcome.Sources, err.Error())
			} else if i < len(result.Inputs) && result.Inputs[i].Disposition == plan.BatchRejected {
				r.issue(w.origin.input, device, "design", "plan_rejected", w.outcome.Wire, w.trafficView, w.outcome.Sources, "")
			}
		}
	}
	return ctx.Err()
}

func (r *targetBatch) emit(count int) error {
	if r.emitted+count > r.designer.options.Engine.Limits.WithDefaults().MaxRegions {
		r.budgetErr = policy.ErrBudget
		return r.budgetErr
	}
	r.emitted += count
	return nil
}
