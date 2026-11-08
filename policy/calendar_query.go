package policy

import (
	"context"
	"slices"
	"time"

	fm "github.com/gatework/firemon"
)

// Windows partitions a finite query interval into contiguous half-open windows.
// Every known schedule has a constant admission state within each window. Unknown
// calendars remain unknown to Query and QueryPacket; they are never made active
// by this partition. Unlike Contexts, Windows retains every chronological repeat.
func (e Engine) Windows(ctx context.Context, fw *fm.Firewall, window fm.TimeWindow) ([]fm.TimeWindow, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if fw == nil || window.Start.IsZero() || window.End.IsZero() || !window.Start.Before(window.End) {
		return nil, ErrInvalid
	}
	window.Start = window.Start.Round(0).UTC()
	window.End = window.End.Round(0).UTC()
	for _, at := range []time.Time{window.Start, window.End} {
		if at.Year() < 0 || at.Year() > 9999 {
			return nil, ErrInvalid
		}
	}
	limits := e.Limits.WithDefaults()
	c := calendar{
		window: window, limit: min(limits.MaxRegions, limits.MaxCombinations),
		remaining: limits.MaxVisits,
		cuts:      map[time.Time]struct{}{window.Start: {}, window.End: {}},
	}
	// Charge nested declarations before schedule accessors copy recurring windows
	// or ActiveAt examines their values. This also bounds the schedule view itself.
	if err := chargeVisits(ctx, &c.remaining, fw.DeclarationSize()); err != nil {
		return nil, err
	}
	for _, schedule := range fw.Schedules() {
		if err := c.add(ctx, schedule); err != nil {
			return nil, err
		}
	}
	if err := chargeVisits(ctx, &c.remaining, len(c.cuts)); err != nil {
		return nil, err
	}
	cuts := make([]time.Time, 0, len(c.cuts))
	for at := range c.cuts {
		cuts = append(cuts, at)
	}
	slices.SortFunc(cuts, time.Time.Compare)
	windows := make([]fm.TimeWindow, 0, len(cuts)-1)
	for i := 1; i < len(cuts); i++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		windows = append(windows, fm.TimeWindow{Start: cuts[i-1], End: cuts[i]})
	}
	return windows, nil
}

// calendar owns one bounded timeline, independent of policy and NAT outcomes.
type calendar struct {
	window    fm.TimeWindow
	limit     int
	remaining int
	cuts      map[time.Time]struct{}
}

func (c *calendar) cut(ctx context.Context, at time.Time) error {
	if err := chargeVisits(ctx, &c.remaining, 1); err != nil {
		return err
	}
	if !at.After(c.window.Start) || !at.Before(c.window.End) {
		return nil
	}
	at = at.Round(0).UTC()
	if _, exists := c.cuts[at]; exists {
		return nil
	}
	if len(c.cuts)-1 >= c.limit {
		return ErrBudget
	}
	c.cuts[at] = struct{}{}
	return nil
}

func (c *calendar) add(ctx context.Context, schedule *fm.Schedule) error {
	if err := chargeVisits(ctx, &c.remaining, 1); err != nil {
		return err
	}
	if _, known := schedule.ActiveAt(c.window.Start); !known {
		return nil
	}
	for window := range schedule.Windows() {
		if err := c.cut(ctx, window.Start); err != nil {
			return err
		}
		if err := c.cut(ctx, window.End); err != nil {
			return err
		}
	}
	if !schedule.HasRecurrence() {
		return nil
	}
	loc, err := time.LoadLocation(schedule.Timezone())
	if err != nil {
		return fm.ErrScheduleTime
	}
	for period := range schedule.Weekly() {
		if err := c.weekly(ctx, period, loc); err != nil {
			return err
		}
	}
	return nil
}

func (c *calendar) weekly(ctx context.Context, period fm.WeeklyPeriod, loc *time.Location) error {
	if err := chargeVisits(ctx, &c.remaining, 1); err != nil {
		return err
	}
	window := c.window
	if period.Start.After(window.Start) {
		window.Start = period.Start
	}
	if !period.End.IsZero() && period.End.Before(window.End) {
		window.End = period.End
	}
	if !window.Start.Before(window.End) {
		return nil
	}
	if err := c.cut(ctx, window.Start); err != nil {
		return err
	}
	if err := c.cut(ctx, window.End); err != nil {
		return err
	}
	phases := make(map[time.Duration]struct{})
	for _, w := range period.Windows {
		day := time.Duration(w.Day) * 24 * time.Hour
		for _, boundary := range []time.Duration{day + w.Start, day + w.End} {
			if err := chargeVisits(ctx, &c.remaining, 1); err != nil {
				return err
			}
			boundary %= civilWeek
			if _, exists := phases[boundary]; exists {
				continue
			}
			phases[boundary] = struct{}{}
		}
	}
	// Civil time advances linearly inside one UTC-offset segment. Enumerating
	// weekly boundaries there finds both fold occurrences and no gap occurrences.
	for at := window.Start; at.Before(window.End); {
		if err := chargeVisits(ctx, &c.remaining, 1); err != nil {
			return err
		}
		local := at.In(loc)
		next, err := calendarZoneEnd(local)
		if err != nil {
			return err
		}
		if next.IsZero() || next.After(window.End) {
			next = window.End
		}
		phase := weeklyPhase(local)
		for boundary := range phases {
			if err := chargeVisits(ctx, &c.remaining, 1); err != nil {
				return err
			}
			distance := (boundary - phase + civilWeek) % civilWeek
			for hit := at.Add(distance); hit.Before(next); hit = hit.Add(civilWeek) {
				if err := c.cut(ctx, hit); err != nil {
					return err
				}
			}
		}
		// A jump across a civil boundary can change admission without observing
		// that wall time; a backward jump can reactivate an earlier interval.
		if err := c.cut(ctx, next); err != nil {
			return err
		}
		at = next
	}
	return nil
}

func calendarZoneEnd(at time.Time) (time.Time, error) {
	_, end := at.ZoneBounds()
	if end.IsZero() || end.After(at) {
		return end, nil
	}
	// Go's POSIX timezone extension uses a 365-day year-end sentinel after the
	// final transition. In a leap year it may already be behind the lookup time.
	// Only that exact sentinel can extend to the actual UTC year boundary.
	year := time.Date(at.UTC().Year(), time.January, 1, 0, 0, 0, 0, time.UTC)
	next := year.AddDate(1, 0, 0)
	sentinel := year.Add(365 * 24 * time.Hour)
	if end.Equal(sentinel) && sentinel.Before(next) && at.Before(next) {
		return next, nil
	}
	return time.Time{}, fm.ErrScheduleTime
}
