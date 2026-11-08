package operations

import (
	"context"
	"maps"
	"slices"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/internal/dependency"
	"github.com/gatework/firemon/inventory"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/policy"
	"github.com/gatework/firemon/snapshot"
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
	maps.Copy(frozen.Devices, manifest.Devices)
	maps.Copy(frozen.Reservations, manifest.Reservations)
	r := targetBatch{
		designer: d, manifest: frozen, topology: q.Topology, design: design,
		graphs: make(map[string]*fm.Firewall), loadErrors: make(map[string]error),
		work: make(map[string][]*targetEntry), visits: d.options.Engine.Limits.WithDefaults().MaxVisits,
	}
	defer func() { report = r.finish(err) }()
	for i, a := range q.Requests {
		if err = r.resolve(ctx, i, a); err != nil {
			return report, err
		}
	}
	if r.budgetErr != nil {
		return report, r.budgetErr
	}
	if design {
		if err = r.plan(ctx); err != nil {
			return report, err
		}
	}
	if r.budgetErr != nil {
		return report, r.budgetErr
	}
	return report, ctx.Err()
}
