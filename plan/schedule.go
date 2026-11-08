package plan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/policy"
	"time"
)

// ScheduleIntent grants policy admission only in Window, using one exact native
// absolute schedule. Clock is trusted evidence bound to the original baseline;
// readback must establish its own clock from the new capture. Existing sessions
// are outside this stateless proof. No recurring schedule is synthesized.
type ScheduleIntent struct {
	Schedule fm.ID
	Window   fm.TimeWindow
	Clock    fm.ScheduleClock
}

// ScheduleName distinguishes same-day expiries and clocks deterministically and
// fits the smallest supported native name limit (StoneOS: 31 characters).
func ScheduleName(window fm.TimeWindow, timezone string) string {
	b, _ := json.Marshal(struct {
		Window   fm.TimeWindow
		Timezone string
	}{window, timezone})
	sum := sha256.Sum256(b)
	return "fm-time-" + hex.EncodeToString(sum[:10])
}

// One nanosecond after time.Time's zero is an explicit finite representative of
// the complete pre-start interval. No device command is generated for this time.
var proofEpoch = time.Date(1, 1, 1, 0, 0, 0, 1, time.UTC)

func scheduleRequest(input NativeRequest) policy.Request {
	q := normalizedRequest(input.Request)
	if input.Lifetime != nil {
		q.At = input.Lifetime.Window.Start
	}
	return q
}
func nativeClock(inputs []NativeRequest) (*fm.ScheduleClock, error) {
	var out *fm.ScheduleClock
	for _, r := range inputs {
		if r.Lifetime != nil {
			c := r.Lifetime.Clock
			if out != nil && *out != c {
				return nil, fmt.Errorf("%w: inconsistent capture clocks", ErrInvalid)
			}
			out = &c
		}
	}
	return out, nil
}
func validScheduleRecord(r fm.ScheduleRecord, i ScheduleIntent) bool {
	return r.ID == i.Schedule && !r.Inline && r.Validate() == nil && !r.HasRecurrence() && len(r.Windows) == 1 && r.Timezone == i.Clock.Timezone && r.Windows[0].Start.Equal(i.Window.Start) && r.Windows[0].End.Equal(i.Window.End)
}
func validateScheduleInput(before *fm.Firewall, input NativeRequest) error {
	if input.Lifetime == nil {
		if len(input.Additions.Schedules) > 0 {
			return ErrInvalid
		}
		for _, r := range input.Additions.Rules {
			if r.Match.Schedule != "" {
				return ErrInvalid
			}
		}
		for _, n := range input.NAT {
			if n.Window != nil {
				return ErrInvalid
			}
		}
		return nil
	}
	i := *input.Lifetime
	if i.Schedule == "" || i.Clock.Validate(before.Metadata()) != nil || i.Window.Start.Before(proofEpoch) {
		return ErrInvalid
	}
	if _, _, err := i.Clock.NativeWindow(i.Window, time.Minute); err != nil {
		return err
	}
	var record *fm.ScheduleRecord
	if s := before.Schedule(i.Schedule); s != nil {
		r := s.Record()
		record = &r
	}
	for _, s := range input.Additions.Schedules {
		if s.ID != i.Schedule {
			return ErrInvalid
		}
		record = &s
	}
	if record == nil || !validScheduleRecord(*record, i) {
		return fmt.Errorf("%w: finite schedule does not match intent", ErrInvalid)
	}
	for _, r := range input.Additions.Rules {
		if r.Match.Schedule != i.Schedule {
			return ErrInvalid
		}
	}
	for _, n := range input.NAT {
		if n.Window != nil && (!n.Window.Start.Equal(i.Window.Start) || !n.Window.End.Equal(i.Window.End)) {
			return ErrInvalid
		}
	}
	return nil
}

func validateScheduleChanges(before, after *fm.Firewall, c NativeChanges) error {
	used := map[fm.ID]bool{}
	for _, r := range c.Additions.Rules {
		if r.Match.Schedule != "" {
			used[r.Match.Schedule] = true
		}
	}
	if len(used) == 0 && len(c.Additions.Schedules) == 0 {
		return nil
	}
	if c.Clock == nil || c.Clock.Validate(before.Metadata()) != nil {
		return ErrInvalid
	}
	for id := range used {
		s := after.Schedule(id)
		if s == nil {
			return ErrInvalid
		}
		r := s.Record()
		if r.Timezone != c.Clock.Timezone || r.Validate() != nil || r.Inline {
			return ErrInvalid
		}
		for _, window := range r.Windows {
			if _, _, err := c.Clock.NativeWindow(window, time.Second); err != nil {
				return err
			}
		}
		if r.HasRecurrence() && r.Calendar != c.Clock.Calendar {
			return ErrInvalid
		}
		for _, period := range r.Weekly {
			if _, err := c.Clock.NativeBound(period.Start, false, time.Second); err != nil {
				return err
			}
			if _, err := c.Clock.NativeBound(period.End, true, time.Second); err != nil {
				return err
			}
			for _, window := range period.Windows {
				if _, _, err := c.Clock.NativeWeekly(window, time.Second); err != nil {
					return err
				}
			}
		}
	}
	for _, s := range c.Additions.Schedules {
		if !used[s.ID] {
			return fmt.Errorf("%w: unowned schedule", ErrInvalid)
		}
	}
	return nil
}

func (p Planner) proveScheduledPacket(ctx context.Context, before, after *fm.Firewall, input NativeRequest) error {
	if input.Lifetime == nil {
		return p.proveNativePacket(ctx, after, input)
	}
	contexts, err := p.Engine.Contexts(ctx, proofEpoch, before, after)
	if err != nil {
		return err
	}
	seen := map[time.Time]bool{}
	w := input.Lifetime.Window
	for _, q := range contexts {
		if seen[q.At] || q.At.Before(w.Start) || !q.At.Before(w.End) {
			continue
		}
		seen[q.At] = true
		v := *input.Packet
		v.At = q.At
		input.Packet = &v
		if err := p.proveNativePacket(ctx, after, input); err != nil {
			return err
		}
	}
	return nil
}
