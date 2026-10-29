package policy

import "context"

// chargeVisits accumulates private proof preparation without changing the
// independent limits of delegated public queries.
func chargeVisits(ctx context.Context, remaining *int, counts ...int) error {
	for _, count := range counts {
		if err := ctx.Err(); err != nil {
			return err
		}
		if count < 0 || count > *remaining {
			return ErrBudget
		}
		*remaining -= count
	}
	return nil
}
