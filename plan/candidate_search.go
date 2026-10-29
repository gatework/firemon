package plan

import (
	"container/heap"
	"context"
	"errors"
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
	proof, err := p.proveWithBaseline(ctx, before, draft.after, request, baseline, visits)
	if err != nil {
		if errors.Is(err, policy.ErrBudget) || errors.Is(err, flow.ErrBudget) || ctx.Err() != nil {
			return nil, err
		}
		return nil, nil
	}
	commands, err := p.renderChanges(ctx, before, draft.after, draft.changes)
	if err != nil {
		if !errors.Is(err, ErrRender) {
			return nil, err
		}
		return nil, nil
	}
	if len(commands) == 0 {
		return nil, nil
	}
	result := &Plan{
		before: before, after: draft.after, changes: draft.changes, cost: draft.cost,
		proof: proof, commands: commands, target: request, engine: p.Engine,
	}
	if err := result.seal(); err != nil {
		return nil, err
	}
	return result, nil
}
