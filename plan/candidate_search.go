package plan

import (
	"container/heap"
	"context"
	"errors"
	"iter"
	"slices"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/policy"
)

// candidate is an owned draft, not a proven or renderable Plan.
type candidate struct {
	after   *fm.Firewall
	changes []Change
	cost    Cost
}

// candidateAttempts counts complete proof/render attempts, independently of
// discovery work. A batch retains one budget across groups and singleton retries.
type candidateAttempts struct {
	used, limit int
}

func newCandidateAttempts(limit int) candidateAttempts {
	if limit <= 0 {
		limit = 128
	}
	return candidateAttempts{limit: limit}
}

func (b *candidateAttempts) available() bool { return b.used < b.limit }

func (b *candidateAttempts) take() error {
	if !b.available() {
		return policy.ErrBudget
	}
	b.used++
	return nil
}

// candidateSearch owns drafts until an adapter proves and accepts one. Each
// search uses the prior evaluation of its own immutable graph and context.
type candidateSearch struct {
	planner  Planner
	before   *fm.Firewall
	request  policy.Request
	gap      flow.Traffic
	prior    *policy.Result
	visits   *visitBudget
	attempts *candidateAttempts
}

// candidateSearchAdapter retains the access and batch contracts at the points
// where they differ: discovery accounting, refusal evidence and complete proof.
type candidateSearchAdapter interface {
	rules(context.Context) iter.Seq2[*fm.Rule, error]
	decline(context.Context, RejectionStage, fm.ID, error) error
	attempt(context.Context, candidate) (bool, error)
}

func (s *candidateSearch) run(ctx context.Context, adapter candidateSearchAdapter) (bool, error) {
	// Keep the configured limit even when a batch has spent earlier attempts.
	// Discovery and its refusal evidence precede the complete-attempt check.
	selection := candidateSelection{limit: s.attempts.limit}
	q := s.request
	for rule, err := range adapter.rules(ctx) {
		if err != nil {
			return false, err
		}
		r := rule.Record()
		if r.Disabled || r.Builtin || r.Action != fm.Permit || r.Scope != q.Scope || r.RuleSet != q.RuleSet || r.Log == fm.Unknown || !sameZones(r.Match, q) {
			continue
		}
		next, changes, cost, err := s.planner.appendCandidate(ctx, s.before, r, s.gap, s.visits)
		if err != nil {
			if err := adapter.decline(ctx, DeclarationRejection, r.ID, err); err != nil {
				return false, err
			}
			continue
		}
		if len(changes) == 0 {
			continue
		}
		possible, err := s.planner.Engine.AppendCanPreserve(ctx, s.before, next, r.ID, q, *s.prior)
		if err != nil {
			return false, err
		}
		if !possible {
			if err := adapter.decline(ctx, PreservationRejection, r.ID, nil); err != nil {
				return false, err
			}
			continue
		}
		selection.consider(candidate{after: next, changes: changes, cost: cost})
	}
	for _, draft := range selection.ordered() {
		if err := s.attempts.take(); err != nil {
			return false, err
		}
		accepted, err := adapter.attempt(ctx, draft)
		if err != nil || accepted {
			return accepted, err
		}
	}
	// Every append has fewer new rules than creation. An unused fallback must
	// not consume construction work, and a failed construction is no attempt.
	if !s.attempts.available() {
		return false, policy.ErrBudget
	}
	next, changes, cost, err := createCandidate(ctx, s.before, s.request, s.gap, s.visits)
	if err != nil {
		return false, err
	}
	if err := s.attempts.take(); err != nil {
		return false, err
	}
	return adapter.attempt(ctx, candidate{after: next, changes: changes, cost: cost})
}

// candidateHeap keeps the most expensive retained candidate at its root.
type candidateHeap []candidate

func (h candidateHeap) Len() int           { return len(h) }
func (h candidateHeap) Less(i, j int) bool { return h[j].cost.less(h[i].cost) }
func (h candidateHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *candidateHeap) Push(value any)    { *h = append(*h, value.(candidate)) }
func (h *candidateHeap) Pop() any {
	last := len(*h) - 1
	value := (*h)[last]
	(*h)[last] = candidate{}
	*h = (*h)[:last]
	return value
}

type candidateSelection struct {
	limit    int
	retained candidateHeap
}

func (s *candidateSelection) consider(value candidate) {
	if len(s.retained) < s.limit {
		heap.Push(&s.retained, value)
		return
	}
	if value.cost.less(s.retained[0].cost) {
		s.retained[0] = value
		heap.Fix(&s.retained, 0)
	}
}

// ordered consumes the selection after scanning the whole bounded search space.
func (s *candidateSelection) ordered() []candidate {
	result := []candidate(s.retained)
	s.retained = nil
	slices.SortFunc(result, func(a, b candidate) int {
		if a.cost.less(b.cost) {
			return -1
		}
		if b.cost.less(a.cost) {
			return 1
		}
		return 0
	})
	return result
}

// tryCandidate returns nil, nil for a proof or representation rejection. Fatal
// renderer errors are returned unchanged, even when they wrap ErrUnsafe.
func (p Planner) tryCandidate(
	ctx context.Context, before *fm.Firewall, draft candidate,
	request policy.Request, baseline *policy.Result, visits *visitBudget,
) (*Plan, error) {
	if err := p.preflightReadback(ctx, before, draft.after); err != nil {
		return nil, err
	}
	proof, err := p.proveWithBaseline(ctx, before, draft.after, request, baseline, visits)
	if err != nil {
		if errors.Is(err, policy.ErrBudget) || errors.Is(err, flow.ErrBudget) || ctx.Err() != nil {
			return nil, err
		}
		return nil, nil
	}
	commands, err := p.renderChanges(ctx, before, draft.after, draft.changes)
	if err != nil {
		if !representationRejected(err) {
			return nil, err
		}
		return nil, nil
	}
	if len(commands) == 0 {
		return nil, nil
	}
	result := &Plan{
		before: before, after: draft.after, changes: draft.changes, cost: draft.cost,
		proof: proof, commands: commands, intent: accessIntent{target: request}, engine: p.Engine,
	}
	if err := result.seal(); err != nil {
		return nil, err
	}
	return result, nil
}
