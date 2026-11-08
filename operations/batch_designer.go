package operations

import (
	"context"
	"maps"
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
	Topology       *inventory.Topology
	Clocks         map[string]fm.ScheduleClock
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
	if _, ok := o.Store.(*inventory.Cache); !ok {
		cache, err := inventory.NewCache(o.Store, inventory.CacheLimits{})
		if err != nil {
			return nil, err
		}
		o.Store = cache
	}
	var err error
	o.Topology, err = copyTopology(context.Background(), o.Topology, o.Engine.Limits)
	if err != nil {
		return nil, err
	}
	o.Clocks = maps.Clone(o.Clocks)
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
	// Src, Dst and Service are business input. Traffic is the exact native form;
	// callers choose one form. A missing service is a query filter, not a grant.
	Src, Dst, Service string
	Window            *fm.TimeWindow
	Native            *NativeEffects
	ID                string
	Traffic           flow.Traffic
	View              inventory.View
	Scope, VRF        *string
	At                time.Time
	Targets           []AccessTarget
	WireCandidates    []WireCandidate
	Sources           []string
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
	// TrafficView identifies Wire and Matches.Original coordinates.
	TrafficView      string
	At               time.Time
	Window           *fm.TimeWindow
	Conditional      bool
	Matches          []RuleMatch
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
	Normalized *NormalizedInput
	Error      *InputError
	Index      int
	Request    AccessRequest
	Outcomes   []TargetOutcome
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
	if err := preflightBusinessNative(ctx, q.Requests, d.options.Engine.Limits); err != nil {
		return BatchReport{}, err
	}
	ctx, cancel := operationContext(ctx, d.options.Timeout)
	defer cancel()
	if q.Topology == nil {
		q.Topology = d.options.Topology
	}
	r, err := resolveBatch(ctx, d.options.Store, d.options.Engine, q)
	if r == nil {
		return BatchReport{}, err
	}
	if err == nil {
		r.renderer, r.maxCandidates, r.clocks = d.options.NativeRenderer, d.options.MaxCandidates, d.options.Clocks
		err = r.plan(ctx)
	}
	if err == nil {
		err = r.budgetErr
	}
	return r.finish(err), err
}

func resolveBatch(ctx context.Context, store BatchStore, engine policy.Engine, q BatchRequest) (r *targetBatch, err error) {
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	if q.Version == 0 {
		q.Version = 1
	}
	if dependency.Nil(store) || q.Version != 1 || len(q.Requests) == 0 || len(q.Requests) > 100 {
		return nil, ErrInvalid
	}
	if q.Topology, err = copyTopology(ctx, q.Topology, engine.Limits); err != nil {
		return nil, err
	}
	totalRegions := 0
	totalBytes := 0
	remaining := engine.Limits.WithDefaults().MaxVisits
	for _, a := range q.Requests {
		cost := 1 + len(a.Sources) + len(a.Targets) + len(a.WireCandidates)
		if cost > remaining {
			return nil, policy.ErrBudget
		}
		remaining -= cost
		totalBytes += len(a.Src) + len(a.Dst) + len(a.Service) + len(a.ID)
		if a.Scope != nil {
			totalBytes += len(*a.Scope)
		}
		if a.VRF != nil {
			totalBytes += len(*a.VRF)
		}
		for _, target := range a.Targets {
			totalBytes += targetBytes(target)
		}
		for _, candidate := range a.WireCandidates {
			totalBytes += targetBytes(candidate.Target)
		}

		for _, source := range a.Sources {
			totalBytes += len(source)
		}
		if totalBytes > MaxRequestBytes {
			return nil, policy.ErrBudget
		}
		totalRegions += a.Traffic.RegionCount()
		if a.Src != "" || a.Dst != "" || a.Service != "" {
			if len(a.Targets) > 100 || len(a.WireCandidates) > 100 {
				return nil, policy.ErrBudget
			}
			continue
		}
		if a.Native != nil {
			if len(a.Targets) != 1 || len(a.WireCandidates) != 0 || (a.View != "" && a.View != inventory.Original) {
				return nil, ErrInvalid
			}
			totalRegions += a.Native.PolicyTraffic.RegionCount()
			for _, n := range a.Native.NAT {
				totalRegions += n.Request.Traffic.RegionCount()
			}
		}
		if a.View != "" && a.View != inventory.Original && a.View != inventory.Real && a.View != inventory.Translated {
			return nil, ErrInvalid
		}
		if len(a.WireCandidates) > 100 || len(a.WireCandidates) > 0 && (len(a.Targets) > 0 || (a.View != inventory.Translated && a.View != inventory.Real)) {
			return nil, ErrInvalid
		}
		for _, c := range a.WireCandidates {
			totalRegions += c.Traffic.RegionCount()
			if c.Target.Device == "" || !c.Target.Request.Traffic.Empty() || c.Traffic.Empty() {
				return nil, ErrInvalid
			}
		}
		if totalRegions > engine.Limits.WithDefaults().MaxRegions {
			return nil, ErrInvalid
		}
		if len(a.Targets) > 100 || a.Traffic.RegionCount() > engine.Limits.WithDefaults().MaxRegions {
			return nil, ErrInvalid
		}
		for _, t := range a.Targets {
			if t.Device == "" || !t.Request.Traffic.Empty() {
				return nil, ErrInvalid
			}
		}
	}
	manifest, err := store.Manifest(ctx)
	if err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	if len(manifest.Devices)+len(manifest.Reservations) > engine.Limits.WithDefaults().MaxVisits {
		return nil, policy.ErrBudget
	}
	if manifest.Version != 1 {
		return nil, snapshot.ErrFormat
	}
	// Detach maps from custom stores before any Load callback can advance state.
	frozen := snapshot.Manifest{Version: manifest.Version, Generation: manifest.Generation, Devices: make(map[string]snapshot.Head), Reservations: make(map[string]snapshot.Reservation)}
	maps.Copy(frozen.Devices, manifest.Devices)
	maps.Copy(frozen.Reservations, manifest.Reservations)
	r = &targetBatch{
		store: store, engine: engine, manifest: frozen, topology: q.Topology,
		graphs: make(map[string]*fm.Firewall), loadErrors: make(map[string]error),
		work: make(map[string][]*targetEntry), visits: engine.Limits.WithDefaults().MaxVisits,
	}
	now := time.Now().Round(0).UTC()
	for i, a := range q.Requests {
		if a.At.IsZero() && a.Window == nil && (a.Src != "" || a.Dst != "") {
			a.At = now
		}
		if err = r.resolve(ctx, i, a); err != nil {
			return r, err
		}
	}
	if r.budgetErr != nil {
		return r, r.budgetErr
	}

	return r, ctx.Err()
}

func targetBytes(t AccessTarget) int {
	q := t.Request
	return len(t.Device) + len(t.Revision) + len(t.VRF) + len(q.Scope) + len(q.RuleSet) + len(q.FromZone) + len(q.ToZone) + len(q.EgressInterface)
}
