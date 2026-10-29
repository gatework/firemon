package plan

import (
	"context"

	"github.com/gatework/firemon/policy"
)

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
