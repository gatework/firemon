package plan

import (
	"context"

	fm "github.com/gatework/firemon"
)

// preflightReadback checks minimum capacity for the normal baseline and result
// captures. It does not spend the current operation's visits or guarantee that
// a different observed graph or the later traffic proof will fit the budget.
func (p Planner) preflightReadback(ctx context.Context, before, after *fm.Firewall) error {
	baseline := visitBudget(p.Engine.Limits.WithDefaults().MaxVisits)
	if err := baseline.takeGraphs(ctx, before, before); err != nil {
		return err
	}
	result := visitBudget(p.Engine.Limits.WithDefaults().MaxVisits)
	return result.takeGraphs(ctx, before, after, after)
}

func (b *visitBudget) takeGraphs(ctx context.Context, graphs ...*fm.Firewall) error {
	for _, graph := range graphs {
		if err := b.take(ctx, graph.RecordCount()); err != nil {
			return err
		}
	}
	return nil
}
