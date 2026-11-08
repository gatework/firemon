package operations

import (
	"context"
	"slices"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/internal/dependency"
	"github.com/gatework/firemon/inventory"
	"github.com/gatework/firemon/policy"
)

// Searcher owns the reusable object cache. Query pins one manifest generation;
// policy and schedule decisions are always evaluated for this request's time.
type Searcher struct {
	store    *inventory.Cache
	engine   policy.Engine
	topology *inventory.Topology
	now      func() time.Time
	timeout  time.Duration
}
type SearcherOptions struct {
	Store    BatchStore
	Engine   policy.Engine
	Topology *inventory.Topology
	Now      func() time.Time
	Timeout  time.Duration
}

func NewSearcher(o SearcherOptions) (*Searcher, error) {
	if dependency.Nil(o.Store) || o.Timeout < 0 {
		return nil, ErrInvalid
	}
	cache, ok := o.Store.(*inventory.Cache)
	if !ok {
		var err error
		cache, err = inventory.NewCache(o.Store, inventory.CacheLimits{})
		if err != nil {
			return nil, err
		}
	}
	top, err := copyTopology(context.Background(), o.Topology, o.Engine.Limits)
	if err != nil {
		return nil, err
	}
	now := o.Now
	if now == nil {
		now = time.Now
	}
	return &Searcher{store: cache, engine: o.Engine, topology: top, now: now, timeout: o.Timeout}, nil
}
func copyTopology(ctx context.Context, t *inventory.Topology, limits policy.Limits) (*inventory.Topology, error) {
	if t == nil {
		return nil, nil
	}
	limits = limits.WithDefaults()
	if len(t.Bindings) > limits.MaxRegions {
		return nil, policy.ErrBudget
	}
	remaining := limits.MaxVisits
	bytes := 0
	for _, binding := range t.Bindings {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		cost := 1 + len(binding.Networks) + len(binding.Sources)
		if cost > remaining {
			return nil, policy.ErrBudget
		}
		remaining -= cost
		bytes += len(binding.Device) + len(binding.Revision) + len(binding.Scope) + len(binding.VRF) + len(binding.Zone)
		for _, source := range binding.Sources {
			bytes += len(source)
		}
		if bytes > MaxRequestBytes {
			return nil, policy.ErrBudget
		}
	}
	if err := t.Validate(); err != nil {
		return nil, err
	}
	copy := *t
	copy.Bindings = slices.Clone(t.Bindings)
	for i := range copy.Bindings {
		copy.Bindings[i].Networks = slices.Clone(copy.Bindings[i].Networks)
		copy.Bindings[i].Sources = slices.Clone(copy.Bindings[i].Sources)
	}
	return &copy, nil
}

func (s *Searcher) Query(ctx context.Context, q BatchRequest) (BatchReport, error) {
	if err := ctx.Err(); err != nil {
		return BatchReport{}, err
	}
	if s == nil || s.store == nil || s.now == nil {
		return BatchReport{}, ErrInvalid
	}
	ctx, cancel := operationContext(ctx, s.timeout)
	defer cancel()
	if len(q.Requests) == 0 || len(q.Requests) > 100 {
		return BatchReport{}, ErrInvalid
	}
	if err := preflightBusinessNative(ctx, q.Requests, s.engine.Limits); err != nil {
		return BatchReport{}, err
	}
	q.Requests = slices.Clone(q.Requests)
	now := s.now().Round(0).UTC()
	for i := range q.Requests {
		if q.Requests[i].At.IsZero() && q.Requests[i].Window == nil {
			q.Requests[i].At = now
		}
		if a := q.Requests[i]; a.Native != nil && a.Src == "" && a.Dst == "" && a.Service == "" {
			return BatchReport{}, ErrInvalid
		}
	}
	if q.Topology == nil {
		q.Topology = s.topology
	}
	r, err := resolveBatch(ctx, s.store, s.engine, q)
	if r == nil {
		return BatchReport{}, err
	}
	if err == nil {
		err = r.describe(ctx)
	}
	if err == nil {
		err = r.budgetErr
	}
	return r.finish(err), err
}

// RuleMatch distinguishes a declaration from its effective first-match traffic.
// Original uses wire coordinates only for established packet paths. A direct
// native-policy query retains native coordinates and is marked by the outcome.
type RuleMatch struct {
	Rule           fm.ID                `json:"rule"`
	Name           string               `json:"name,omitempty"`
	Action         fm.Action            `json:"action"`
	Disabled       bool                 `json:"disabled"`
	Schedule       fm.ID                `json:"schedule,omitempty"`
	ScheduleState  string               `json:"schedule_state"`
	Windows        []fm.TimeWindow      `json:"windows,omitempty"`
	Weekly         []fm.WeeklyPeriod    `json:"weekly,omitempty"`
	Timezone       string               `json:"timezone,omitempty"`
	Declared       []flow.TrafficRegion `json:"declared"`
	Effective      []flow.TrafficRegion `json:"effective"`
	Original       []flow.TrafficRegion `json:"original"`
	DeclaredKnown  bool                 `json:"declared_known"`
	EffectiveKnown bool                 `json:"effective_known"`
	OriginalKnown  bool                 `json:"original_known"`
}

func (r *targetBatch) describe(ctx context.Context) error {
	for _, input := range r.inputs {
		for _, entry := range input.entries {
			if err := r.describeEntry(ctx, input.index, entry); err != nil {
				return err
			}
		}
	}
	return ctx.Err()
}

func (r *targetBatch) describeEntry(ctx context.Context, input int, entry *targetEntry) error {
	fw := r.graphs[entry.outcome.Revision]
	if fw == nil {
		return nil
	}
	limit := r.engine.Limits.WithDefaults().MaxRegions
	declared := make(map[fm.ID]policy.RuleMatch)
	for _, q := range entry.outcome.NativeRequests {
		if err := r.chargeGraph(ctx, fw); err != nil {
			return err
		}
		matches, err := r.engine.Declared(ctx, fw, q, entry.packet)
		if err != nil {
			return err
		}
		for _, match := range matches {
			if prior, ok := declared[match.Rule]; ok {
				match.Traffic, err = prior.Traffic.Union(match.Traffic, limit)
				if err != nil {
					return err
				}
				match.Known = match.Known && prior.Known
			}
			declared[match.Rule] = match
		}
	}
	decisions := make(map[fm.ID]policy.RuleDecision)
	for _, decision := range entry.outcome.Policy.Decisions {
		if prior, ok := decisions[decision.Rule]; ok {
			var err error
			decision.Traffic, err = prior.Traffic.Union(decision.Traffic, limit)
			if err != nil {
				return err
			}
			decision.Known = decision.Known && prior.Known && decision.Action == prior.Action
		}
		decisions[decision.Rule] = decision
	}
	for rule := range fw.OrderedRules() {
		if err := r.charge(ctx); err != nil {
			return err
		}
		match := declared[rule.ID()]
		effective := decisions[rule.ID()]
		if match.Traffic.Empty() && effective.Traffic.Empty() {
			continue
		}
		if err := r.emit(1 + match.Traffic.RegionCount() + effective.Traffic.RegionCount()); err != nil {
			return err
		}
		record := rule.Record()
		m := RuleMatch{Rule: record.ID, Name: record.Name, Action: record.Action, Disabled: record.Disabled,
			Schedule: record.Match.Schedule, Declared: match.Traffic.Regions(), Effective: effective.Traffic.Regions(),
			DeclaredKnown: match.Known, EffectiveKnown: effective.Known || entry.outcome.Policy.Complete}
		if schedule := fw.Schedule(record.Match.Schedule); schedule != nil {
			count := schedule.WeeklyCount() + schedule.WeeklyWindowCount()
			for range schedule.Windows() {
				count++
			}
			if err := r.emit(count); err != nil {
				return err
			}
			record := schedule.Record()
			m.Windows, m.Weekly, m.Timezone = record.Windows, record.Weekly, record.Timezone
		}
		m.ScheduleState = scheduleState(fw, record.Match.Schedule, entry.outcome.At)
		m.OriginalKnown = m.EffectiveKnown
		if !effective.Traffic.Empty() {
			original := effective.Traffic
			var err error
			if entry.packet != nil {
				if err := r.chargeGraph(ctx, fw); err != nil {
					return err
				}
				original, err = r.engine.OriginalTraffic(ctx, fw, *entry.packet, effective.Traffic)
			}
			if err != nil {
				if fatalBatch(err) {
					return err
				}
				m.OriginalKnown = false
				r.issue(input, entry.outcome.Device, "policy", "unknown_original_traffic", entry.outcome.Wire, entry.trafficView, nil, err.Error())
			} else {
				if err := r.emit(original.RegionCount()); err != nil {
					return err
				}
				m.Original, m.OriginalKnown = original.Regions(), effective.Known
			}
		}
		entry.outcome.Matches = append(entry.outcome.Matches, m)
	}
	return nil
}

func scheduleState(fw *fm.Firewall, id fm.ID, at time.Time) string {
	if id == "" {
		return "always"
	}
	s := fw.Schedule(id)
	if s == nil {
		return "unknown"
	}
	active, known := s.ActiveAt(at)
	if !known {
		return "unknown"
	}
	if active {
		return "active"
	}
	if expired, known := s.ExpiredAt(at); known && expired {
		return "expired"
	}
	future := true
	for w := range s.Windows() {
		future = future && at.Before(w.Start)
	}
	for p := range s.Weekly() {
		future = future && !p.Start.IsZero() && at.Before(p.Start)
	}
	if future {
		return "not_started"
	}
	return "inactive"
}
func (r *targetBatch) chargeGraph(ctx context.Context, fw *fm.Firewall) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if fw.DeclarationSize() > r.visits {
		return policy.ErrBudget
	}
	r.visits -= fw.DeclarationSize()
	return nil
}
