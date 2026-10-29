package plan

import (
	"context"
	"slices"

	fm "github.com/gatework/firemon"
)

// renderChanges isolates the plan's delta from renderer-owned arguments and
// output. A renderer finishing after cancellation cannot authorize a plan.
func (p Planner) renderChanges(ctx context.Context, before, after *fm.Firewall, changes []Change) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	commands, err := p.Renderer.Render(ctx, before, after, cloneChanges(changes))
	if canceled := ctx.Err(); canceled != nil {
		return nil, canceled
	}
	if err != nil {
		return nil, err
	}
	return slices.Clone(commands), nil
}
