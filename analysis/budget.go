package analysis

import (
	"context"

	"github.com/gatework/firemon/policy"
)

// visitBudget belongs to one analysis call and is shared by its private helpers.
// Delegated policy queries and proofs retain their own independent limits.
type visitBudget int

func (b *visitBudget) take(ctx context.Context, count int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if count < 0 || count > int(*b) {
		return policy.ErrBudget
	}
	*b -= visitBudget(count)
	return nil
}
