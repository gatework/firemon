package plan

import (
	"context"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/internal/dependency"
	"github.com/gatework/firemon/policy"
)

func (p *Plan) Preservation() (policy.Equivalence, bool) {
	if p == nil || p.preservation == nil {
		return policy.Equivalence{}, false
	}
	return *p.preservation, true
}

// Preserve creates a renderable lifecycle plan whose full future policy and
// logging are equivalent. It shares authorization/readback/deploy contracts
// with access-request plans; it never authorizes deleting from usage alone.
func (p Planner) Preserve(ctx context.Context, before, after *fm.Firewall, changes []Change, from time.Time) (*Plan, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if before == nil || after == nil || p.Renderer != nil && dependency.Nil(p.Renderer) {
		return nil, ErrInvalid
	}
	if err := ValidateChanges(ctx, before, after, changes); err != nil {
		return nil, err
	}
	proof, err := p.Engine.Equivalent(ctx, before, after, from)
	if err != nil {
		return nil, err
	}
	result := &Plan{before: before, after: after, changes: changes, preservation: &proof, engine: p.Engine,
		proof: Proof{BaseDigest: before.SemanticDigest(), ResultDigest: after.SemanticDigest(), OutsidePreserved: true, NATUnchanged: true}}
	result.changes = result.Changes()
	if len(changes) > 0 {
		if p.Renderer == nil {
			return nil, ErrInvalid
		}
		result.commands, err = p.renderChanges(ctx, before, after, result.changes)
		if err != nil {
			return nil, err
		}
		if len(result.commands) == 0 {
			return nil, ErrUnsafe
		}
		result.cost.ModifiedRules = len(changes)
	}
	if err := result.seal(); err != nil {
		return nil, err
	}
	return result, nil
}
