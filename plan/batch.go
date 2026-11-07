package plan

import (
	"context"
	"encoding/json"
	"slices"
	"strings"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/internal/dependency"
	"github.com/gatework/firemon/policy"
)

// BatchDisposition describes a whole input. Covered means the original baseline
// already allowed it; accepted means the shared result establishes its coverage.
type BatchDisposition string

const (
	BatchAccepted BatchDisposition = "accepted"
	BatchCovered  BatchDisposition = "covered"
	BatchRejected BatchDisposition = "rejected"
	BatchPending  BatchDisposition = "pending"
)

// BatchAttempt is a bounded explanation, never executable approval material.
type BatchAttempt struct {
	Stage  RejectionStage
	Rule   fm.ID
	Reason string
}

// BatchInput preserves the original input and local candidate outcome. Accepted
// is provisional if the enclosing result has an error or no executable Plan.
type BatchInput struct {
	Index       int
	Request     policy.Request
	Disposition BatchDisposition
	Attempts    []BatchAttempt
}

// BatchResult retains input order, including refused and already covered inputs.
// A non-nil error always implies Plan == nil. Report fields are caller owned.
type BatchResult struct {
	Version int
	Inputs  []BatchInput
	Plan    *Plan
}

// BatchOptions retains the effective search and proof budgets for reconstruction.
// It does not change the existing policy-batch approval digest format.
type BatchOptions struct {
	MaxCandidates int
	Limits        policy.Limits
}

type batchGroup struct {
	request policy.Request
	inputs  []int
}

func batchKey(q policy.Request) string {
	q.Traffic = flow.Traffic{}
	b, _ := json.Marshal(q)
	return string(b)
}
func normalizedRequest(q policy.Request) policy.Request {
	if q.RuleSet == "" {
		q.RuleSet = "security"
	}
	q.At = q.At.UTC()
	return q
}

// prepareBatchInputs is the single canonical preparation path for both grouped
// attempts and singleton retries. Keep original report requests untouched.
func prepareBatchInputs(ctx context.Context, inputs []BatchInput, indexes []int, limit int, visits *visitBudget) ([]batchGroup, error) {
	if err := visits.take(ctx, len(indexes)); err != nil {
		return nil, err
	}
	prepared := make([]batchGroup, 0, len(indexes))
	keys := make(map[int]string, len(indexes))
	for _, i := range indexes {
		q := normalizedRequest(inputs[i].Request)
		if err := visits.take(ctx, q.Traffic.RegionCount()); err != nil {
			return nil, err
		}
		regions := q.Traffic.Regions()
		slices.SortFunc(regions, compareBatchRegion)
		var err error
		q.Traffic, err = flow.NewTraffic(limit, regions...)
		if err != nil {
			return nil, err
		}
		b, _ := json.Marshal(regions)
		keys[i] = string(b)
		prepared = append(prepared, batchGroup{q, []int{i}})
	}
	slices.SortStableFunc(prepared, func(a, b batchGroup) int { return strings.Compare(keys[a.inputs[0]], keys[b.inputs[0]]) })
	return prepared, nil
}

func groupBatch(ctx context.Context, inputs []BatchInput, indexes []int, limit int, visits *visitBudget) ([]batchGroup, error) {
	prepared, err := prepareBatchInputs(ctx, inputs, indexes, limit, visits)
	if err != nil {
		return nil, err
	}
	byKey := make(map[string]int)
	var groups []batchGroup
	for _, input := range prepared {
		q := input.request
		key := batchKey(q)
		if n, ok := byKey[key]; ok {
			groups[n].request.Traffic, err = groups[n].request.Traffic.Union(q.Traffic, limit)
			if err != nil {
				return nil, err
			}
			groups[n].inputs = append(groups[n].inputs, input.inputs...)
		} else {
			byKey[key] = len(groups)
			groups = append(groups, input)
		}
	}
	slices.SortFunc(groups, func(a, b batchGroup) int { return strings.Compare(batchKey(a.request), batchKey(b.request)) })
	return groups, nil
}

// PlanBatch compiles independently classified inputs against one immutable
// baseline. Candidate names, objects and deltas are committed only after full
// joint safety and representation checks. Budget and dependency errors abort
// the device result, while expected candidate refusals leave siblings intact.
func (p Planner) PlanBatch(ctx context.Context, before *fm.Firewall, requests []policy.Request) (BatchResult, error) {
	out := BatchResult{Version: 1}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	if before == nil || len(requests) == 0 || len(requests) > 100 || p.Renderer != nil && dependency.Nil(p.Renderer) {
		return out, ErrInvalid
	}
	limits := p.Engine.Limits.WithDefaults()
	visits := visitBudget(limits.MaxVisits)
	if err := visits.take(ctx, len(requests)); err != nil {
		return out, err
	}
	out.Inputs = make([]BatchInput, len(requests))
	for i, q := range requests {
		out.Inputs[i] = BatchInput{Index: i, Request: q, Disposition: BatchPending}
	}
	if !before.Complete() {
		return out, ErrUnsafe
	}
	var pending, accepted []int
	for i, q := range requests {
		if _, err := q.At.MarshalJSON(); err != nil {
			out.Inputs[i].Disposition = BatchRejected
			out.Inputs[i].Attempts = []BatchAttempt{{Stage: DeclarationRejection, Reason: "invalid request time"}}
			continue
		}
		if q.Traffic.RegionCount() > limits.MaxRegions {
			return out, flow.ErrBudget
		}
		if q.Traffic.Empty() {
			out.Inputs[i].Disposition = BatchRejected
			out.Inputs[i].Attempts = []BatchAttempt{{Stage: DeclarationRejection, Reason: "empty traffic"}}
			continue
		}
		if err := visits.take(ctx, before.RuleCount()); err != nil {
			return out, err
		}
		r, err := p.Engine.Query(ctx, before, q)
		if err != nil {
			return out, err
		}
		if !r.Complete || !r.Unknown.Empty() {
			out.Inputs[i].Disposition = BatchRejected
			out.Inputs[i].Attempts = []BatchAttempt{{Stage: PreservationRejection, Reason: "target has unknown policy evidence"}}
			continue
		}
		covered, err := r.Allowed.Contains(q.Traffic, limits.MaxRegions)
		if err != nil {
			return out, err
		}
		if covered {
			out.Inputs[i].Disposition = BatchCovered
			accepted = append(accepted, i)
		} else {
			pending = append(pending, i)
		}
	}
	groups, err := groupBatch(ctx, out.Inputs, pending, limits.MaxRegions, &visits)
	if err != nil {
		return out, err
	}
	state := batchState{planner: p, before: before, after: before, visits: &visits, baseline: make(map[string]policy.Result), attempts: newCandidateAttempts(p.MaxCandidates)}
	accept := func(g batchGroup) (bool, error) {
		ids := append(slices.Clone(accepted), g.inputs...)
		all, err := groupBatch(ctx, out.Inputs, ids, limits.MaxRegions, &visits)
		if err != nil {
			return false, err
		}
		targets := make([]policy.Request, len(all))
		for i := range all {
			targets[i] = all[i].request
		}
		ok, attempts, err := state.add(ctx, g.request, targets)
		for _, i := range g.inputs {
			out.Inputs[i].Attempts = append(out.Inputs[i].Attempts, attempts...)
			if len(out.Inputs[i].Attempts) > 16 {
				out.Inputs[i].Attempts = out.Inputs[i].Attempts[:16]
			}
		}
		if err != nil {
			return false, err
		}
		if ok {
			accepted = ids
			for _, i := range g.inputs {
				out.Inputs[i].Disposition = BatchAccepted
			}
		}
		return ok, nil
	}
	for _, g := range groups {
		ok, err := accept(g)
		if err != nil {
			return out, err
		}
		if ok {
			continue
		}
		// A combined representation refusal must not discard independently safe
		// inputs in the same context. Retry individual exact traffic deterministically.
		if len(g.inputs) > 1 {
			prepared, err := prepareBatchInputs(ctx, out.Inputs, g.inputs, limits.MaxRegions, &visits)
			if err != nil {
				return out, err
			}
			for _, input := range prepared {
				ok, err := accept(input)
				if err != nil {
					return out, err
				}
				if !ok {
					out.Inputs[input.inputs[0]].Disposition = BatchRejected
				}
			}
		} else {
			out.Inputs[g.inputs[0]].Disposition = BatchRejected
		}
	}
	if len(accepted) == 0 {
		return out, nil
	}
	finalGroups, err := groupBatch(ctx, out.Inputs, accepted, limits.MaxRegions, &visits)
	if err != nil {
		return out, err
	}
	targets := make([]policy.Request, len(finalGroups))
	for i := range finalGroups {
		targets[i] = finalGroups[i].request
	}
	proof, err := p.proveBatch(ctx, before, state.after, targets, state.baseline, &visits)
	if err != nil {
		return out, err
	}
	if err := p.preflightReadback(ctx, before, state.after); err != nil {
		return out, err
	}
	result := &Plan{before: before, after: state.after, changes: cloneChanges(state.changes), commands: slices.Clone(state.commands), cost: state.cost, proof: proof, engine: p.Engine, intent: batchIntent{targets: targets, inputs: slices.Clone(requests), options: BatchOptions{MaxCandidates: state.attempts.limit, Limits: limits}}}
	if err := result.seal(); err != nil {
		return out, err
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	out.Plan = result
	return out, nil
}

func compareBatchRegion(a, b flow.TrafficRegion) int {
	aa, _ := json.Marshal(a)
	bb, _ := json.Marshal(b)
	return strings.Compare(string(aa), string(bb))
}
