package operations

import (
	"context"
	"errors"
	"sync"
)

var ErrDuplicateDevice = errors.New("duplicate device in collection batch")

type CollectBatchOptions struct {
	// Workers defaults to four. Each worker owns one Collect call at a time.
	Workers int `json:"workers,omitempty"`
}

type CollectOutcome struct {
	Request CollectRequest `json:"request"`
	Result  CollectResult  `json:"result"`
	// Err is retained for errors.Is; it is not serialized because transport
	// errors may contain credentials. Status contains only a fixed category.
	Err    error  `json:"-"`
	Status string `json:"status"`
}

// CollectBatch returns outcomes in input order. All occurrences of a duplicate
// device are excluded. A local failure never cancels siblings. Cancellation
// stops new work and waits for each active Collect to close and archive evidence.
// Sessions, Parser and Store must support independent concurrent calls.
// Batches are bounded at 100 items; each Collect retains its own timeout and CAS.
func (c Collector) CollectBatch(ctx context.Context, requests []CollectRequest, options CollectBatchOptions) ([]CollectOutcome, error) {
	if len(requests) == 0 || len(requests) > 100 || options.Workers < 0 || options.Workers > 100 {
		return nil, ErrInvalid
	}
	workers := options.Workers
	if workers == 0 {
		workers = 4
	}
	workers = min(workers, len(requests))
	counts := make(map[string]int, len(requests))
	for _, r := range requests {
		counts[r.Device]++
	}
	rows := make([]CollectOutcome, len(requests))
	for i, r := range requests {
		rows[i].Request = r
		if counts[r.Device] > 1 {
			rows[i].Err = ErrDuplicateDevice
			rows[i].Status = "duplicate_device"
		}
	}
	jobs := make(chan int)
	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			for i := range jobs {
				if err := ctx.Err(); err != nil {
					rows[i].Err = err
					rows[i].Status = "cancelled"
					continue
				}
				rows[i].Result, rows[i].Err = c.Collect(ctx, rows[i].Request)
				rows[i].Status = "failed"
				if rows[i].Result.Published() {
					rows[i].Status = "complete"
					if !rows[i].Result.Complete {
						rows[i].Status = "incomplete"
					}
				}
			}
		})
	}
	for i := range rows {
		if rows[i].Err != nil {
			continue
		}
		if err := ctx.Err(); err != nil {
			rows[i].Err = err
			rows[i].Status = "cancelled"
			continue
		}
		select {
		case jobs <- i:
		case <-ctx.Done():
			rows[i].Err = ctx.Err()
			rows[i].Status = "cancelled"
		}
	}
	close(jobs)
	wg.Wait()
	return rows, ctx.Err()
}
