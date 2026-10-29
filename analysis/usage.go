package analysis

import (
	"context"
	"slices"
	"strings"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/policy"
)

func (r ReclamationRequest) validate() (bool, error) {
	hasWindow := !r.Window.Start.IsZero() || !r.Window.End.IsZero()
	if hasWindow && (!r.Window.Start.Before(r.Window.End) || r.At.IsZero() || r.Window.End.After(r.At) || strings.TrimSpace(r.Revision) == "") {
		return false, ErrInvalid
	}
	if !hasWindow && (len(r.Observations) > 0 || len(r.MemberObservations) > 0) {
		return false, ErrInvalid
	}
	return hasWindow, nil
}

type usageBudget int

func (r Reclaimer) usageBudget() usageBudget {
	limit := r.Planner.Engine.Limits.Rules
	if limit <= 0 {
		limit = 100000
	}
	return usageBudget(limit)
}
func (b *usageBudget) take(ctx context.Context, count int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if count > int(*b) {
		return policy.ErrBudget
	}
	*b -= usageBudget(count)
	return nil
}

// usageEvidence owns only the intervals for one identity in this request.
// A localized positive count overrides uncertain zero-counter observations.
type usageEvidence struct {
	digest         string
	covered        []fm.TimeWindow
	hit, uncertain bool
}

type usageIndex[K comparable] map[K]*usageEvidence

func (index usageIndex[K]) observe(key K, o UsageObservation, request ReclamationRequest) {
	e := index[key]
	if e == nil || o.Revision != request.Revision || o.RuleDigest != e.digest || strings.TrimSpace(o.Source) == "" || e.hit {
		return
	}
	window := request.Window
	if !o.Start.Before(o.End) {
		e.uncertain = true
		return
	}
	if !o.Start.Before(window.End) || !o.End.After(window.Start) {
		return
	}
	if o.Hits > 0 {
		if !o.Start.Before(window.Start) && !o.End.After(window.End) {
			e.hit = true
			e.covered = nil
		} else {
			e.uncertain = true
		}
		return
	}
	if !o.Complete || o.CounterReset {
		e.uncertain = true
		return
	}
	e.covered = append(e.covered, fm.TimeWindow{Start: o.Start, End: o.End})
}

func (e *usageEvidence) unused(ctx context.Context, window fm.TimeWindow) (Truth, error) {
	if err := ctx.Err(); err != nil {
		return Unknown, err
	}
	if e.hit {
		return False, nil
	}
	if e.uncertain {
		return Unknown, nil
	}
	if err := sortUsageWindows(ctx, e.covered); err != nil {
		return Unknown, err
	}
	end := window.Start
	for _, w := range e.covered {
		if err := ctx.Err(); err != nil {
			return Unknown, err
		}
		if w.Start.After(end) {
			return Unknown, nil
		}
		if w.End.After(end) {
			end = w.End
		}
		if !end.Before(window.End) {
			return True, nil
		}
	}
	return Unknown, nil
}

// Sorting small chunks then merging bounds uninterrupted work during cancellation.
func sortUsageWindows(ctx context.Context, windows []fm.TimeWindow) error {
	const chunk = 64
	for start := 0; start < len(windows); start += chunk {
		if err := ctx.Err(); err != nil {
			return err
		}
		slices.SortFunc(windows[start:min(start+chunk, len(windows))], func(a, b fm.TimeWindow) int { return a.Start.Compare(b.Start) })
	}
	if len(windows) <= chunk {
		return ctx.Err()
	}
	buffer := make([]fm.TimeWindow, len(windows))
	source, target := windows, buffer
	original := true
	for width := chunk; width < len(windows); width *= 2 {
		for start := 0; start < len(windows); start += 2 * width {
			middle, end := min(start+width, len(windows)), min(start+2*width, len(windows))
			left, right := start, middle
			for out := start; out < end; out++ {
				if out%chunk == 0 {
					if err := ctx.Err(); err != nil {
						return err
					}
				}
				if left < middle && (right >= end || !source[left].Start.After(source[right].Start)) {
					target[out] = source[left]
					left++
				} else {
					target[out] = source[right]
					right++
				}
			}
		}
		source, target = target, source
		original = !original
	}
	if !original {
		copy(windows, source)
	}
	return ctx.Err()
}
