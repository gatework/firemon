package firemon

import (
	"errors"
	"strconv"
	"strings"
	"time"
)

var ErrScheduleTime = errors.New("schedule clock or native time is not established")

// ScheduleClock is trusted, capture-bound evidence supplied by the integration
// which observed the device clock and verified native schedule endpoint semantics.
// It is not inferred from the host, a default timezone, or a renderer's intent.
// Reference identifies that evidence; SourceDigest binds the exact native capture.
// Inclusive endpoints add TickSeconds to obtain the graph's half-open UTC end.
// This describes policy admission, not termination of established sessions.
type ScheduleClock struct {
	CapturedAt                                      time.Time
	Device, Vendor, Software, Context, SourceDigest string
	Timezone, Reference, EndBoundary                string
	TickSeconds                                     int
	Calendar                                        CalendarMode
}

func (c ScheduleClock) location() (*time.Location, error) {
	if c.Reference == "" || len(c.Reference) > 1024 || c.EndBoundary != "exclusive" && c.EndBoundary != "inclusive" || c.TickSeconds != 1 && c.TickSeconds != 60 || c.Calendar > CalendarCivil {
		return nil, ErrScheduleTime
	}
	return scheduleLocation(c.Timezone)
}

// Validate checks identity against metadata of the independently captured source.
// Calling this method does not turn an untrusted assertion into verified evidence.
func (c ScheduleClock) Validate(m Metadata) error {
	if c.CapturedAt.IsZero() || !c.CapturedAt.Equal(m.CapturedAt) || c.Device == "" || c.Vendor == "" || c.Software == "" || len(c.SourceDigest) != 64 || c.Device != m.Device || c.Vendor != m.Vendor || c.Software != m.Software || c.Context != m.Context || c.SourceDigest != m.SourceDigest {
		return ErrScheduleTime
	}
	for _, v := range c.SourceDigest {
		if !(v >= '0' && v <= '9' || v >= 'a' && v <= 'f') {
			return ErrScheduleTime
		}
	}
	_, err := c.location()
	return err
}

// civilTime rejects both nonexistent wall times and repeated wall times. Testing
// every offset present around the civil date avoids time.ParseInLocation's
// arbitrary choice during a DST fold. ZoneBounds also covers non-hour changes.
func civilTime(layout, value string, loc *time.Location) (time.Time, error) {
	wall, err := time.Parse(layout, value)
	if err != nil {
		return time.Time{}, ErrScheduleTime
	}
	offsets := map[int]bool{}
	stop := wall.Add(48 * time.Hour)
	for at, n := wall.Add(-48*time.Hour), 0; at.Before(stop); n++ {
		if n >= 16 {
			return time.Time{}, ErrScheduleTime
		}
		local := at.In(loc)
		_, offset := local.Zone()
		offsets[offset] = true
		_, end := local.ZoneBounds()
		if end.IsZero() || !end.After(at) {
			break
		}
		at = end
	}
	var result time.Time
	count := 0
	for offset := range offsets {
		candidate := wall.Add(-time.Duration(offset) * time.Second)
		local := candidate.In(loc)
		if local.Year() == wall.Year() && local.Month() == wall.Month() && local.Day() == wall.Day() && local.Hour() == wall.Hour() && local.Minute() == wall.Minute() && local.Second() == wall.Second() && local.Nanosecond() == wall.Nanosecond() {
			result = candidate
			count++
		}
	}
	if count != 1 {
		return time.Time{}, ErrScheduleTime
	}
	return result.UTC(), nil
}

// ParseWindow converts independently captured native civil times without rounding.
func (c ScheduleClock) ParseWindow(layout, start, end string) (TimeWindow, error) {
	a, err := c.ParseBound(layout, start, false)
	if err != nil {
		return TimeWindow{}, err
	}
	b, err := c.ParseBound(layout, end, true)
	if err != nil {
		return TimeWindow{}, err
	}
	if a.IsZero() || b.IsZero() || !a.Before(b) {
		return TimeWindow{}, ErrScheduleTime
	}
	return TimeWindow{Start: a, End: b}, nil
}

// NativeWindow returns exact civil endpoints at the supported native precision.
// The inverse parse must recover precisely the supplied half-open UTC window.
func (c ScheduleClock) NativeWindow(w TimeWindow, precision time.Duration) (time.Time, time.Time, error) {
	if w.Start.IsZero() || w.End.IsZero() || !w.Start.Before(w.End) {
		return time.Time{}, time.Time{}, ErrScheduleTime
	}
	a, err := c.NativeBound(w.Start, false, precision)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	b, err := c.NativeBound(w.End, true, precision)
	if err == nil && (b.Before(a) || b.Equal(a) && c.EndBoundary == "exclusive") {
		err = ErrScheduleTime
	}
	return a, b, err
}

// ParseBound interprets an optional civil date bound. Empty means unbounded.
// End bounds receive the verified inclusive-to-exclusive tick adjustment.
func (c ScheduleClock) ParseBound(layout, value string, end bool) (time.Time, error) {
	loc, err := c.location()
	if err != nil || value == "" {
		return time.Time{}, err
	}
	at, err := civilTime(layout, value, loc)
	if err != nil {
		return time.Time{}, err
	}
	if end && c.EndBoundary == "inclusive" {
		at = at.Add(time.Duration(c.TickSeconds) * time.Second)
	}
	return at, nil
}

// NativeBound returns an exactly representable optional native civil endpoint.
func (c ScheduleClock) NativeBound(at time.Time, end bool, precision time.Duration) (time.Time, error) {
	loc, err := c.location()
	if err != nil {
		return time.Time{}, err
	}
	if precision != time.Minute && precision != time.Second {
		return time.Time{}, ErrScheduleTime
	}
	if at.IsZero() {
		return time.Time{}, nil
	}
	native := at
	if end && c.EndBoundary == "inclusive" {
		native = native.Add(-time.Duration(c.TickSeconds) * time.Second)
	}
	native = native.In(loc)
	if native.Year() < 1970 || native.Year() > 2099 || native.Nanosecond() != 0 || precision == time.Minute && native.Second() != 0 {
		return time.Time{}, ErrScheduleTime
	}
	const layout = "2006-01-02 15:04:05"
	round, err := c.ParseBound(layout, native.Format(layout), end)
	if err != nil || !round.Equal(at) {
		return time.Time{}, ErrScheduleTime
	}
	return native, nil
}

func wallClock(value string, end bool) (time.Duration, error) {
	parts := strings.Split(value, ":")
	if len(parts) != 2 && len(parts) != 3 {
		return 0, ErrScheduleTime
	}
	var values [3]int
	for i, part := range parts {
		if len(part) != 2 {
			return 0, ErrScheduleTime
		}
		for _, digit := range part {
			if digit < '0' || digit > '9' {
				return 0, ErrScheduleTime
			}
		}
		v, err := strconv.Atoi(part)
		if err != nil || v < 0 || v > 59 {
			return 0, ErrScheduleTime
		}
		values[i] = v
	}
	if values[0] > 23 && !(end && values[0] == 24 && values[1] == 0 && values[2] == 0) {
		return 0, ErrScheduleTime
	}
	return time.Duration(values[0])*time.Hour + time.Duration(values[1])*time.Minute + time.Duration(values[2])*time.Second, nil
}

func (c ScheduleClock) weeklyClocks(start, end string) (time.Duration, time.Duration, error) {
	if _, err := c.location(); err != nil || c.Calendar != CalendarCivil {
		return 0, 0, ErrScheduleTime
	}
	a, err := wallClock(start, false)
	if err != nil {
		return 0, 0, err
	}
	b, err := wallClock(end, true)
	if err != nil {
		return 0, 0, err
	}
	return a, b, nil
}

func splitWeeklySpan(day time.Weekday, start, end time.Duration) []WeeklyWindow {
	var windows []WeeklyWindow
	for start < end {
		finish := min(end, civilDay)
		windows = append(windows, WeeklyWindow{Day: day, Start: start, End: finish})
		start, end = 0, end-civilDay
		day = (day + 1) % 7
	}
	return windows
}

// ParseWeekly applies one native daily interval to each named weekday. Native
// cross-midnight windows are split, including Saturday-to-Sunday wrapping.
func (c ScheduleClock) ParseWeekly(days []time.Weekday, start, end string) ([]WeeklyWindow, error) {
	if len(days) == 0 || len(days) > 7 {
		return nil, ErrScheduleTime
	}
	a, b, err := c.weeklyClocks(start, end)
	if err != nil || a == b && c.EndBoundary == "exclusive" {
		return nil, ErrScheduleTime
	}
	if b < a {
		b += civilDay
	}
	if c.EndBoundary == "inclusive" {
		b += time.Duration(c.TickSeconds) * time.Second
	}
	var windows []WeeklyWindow
	for _, day := range days {
		if day < time.Sunday || day > time.Saturday {
			return nil, ErrScheduleTime
		}
		windows = append(windows, splitWeeklySpan(day, a, b)...)
	}
	return normalizeWeekly(windows), nil
}

// ParseWeeklySpan interprets a continuous interval from one named weekday to
// another, moving forward across the week boundary when necessary. Equal-day
// spans must end later that day; use ParseWeekly for daily overnight intervals.
func (c ScheduleClock) ParseWeeklySpan(startDay, endDay time.Weekday, start, end string) ([]WeeklyWindow, error) {
	if startDay < time.Sunday || startDay > time.Saturday || endDay < time.Sunday || endDay > time.Saturday {
		return nil, ErrScheduleTime
	}
	a, b, err := c.weeklyClocks(start, end)
	if err != nil {
		return nil, err
	}
	b += time.Duration((endDay-startDay+7)%7) * civilDay
	if c.EndBoundary == "inclusive" {
		b += time.Duration(c.TickSeconds) * time.Second
	}
	if b <= a || b-a > 7*civilDay {
		return nil, ErrScheduleTime
	}
	return normalizeWeekly(splitWeeklySpan(startDay, a, b)), nil
}

// NativeWeekly returns native daily offsets without rounding. An exclusive
// end of 24 hours must be representable by the selected vendor's grammar.
func (c ScheduleClock) NativeWeekly(w WeeklyWindow, precision time.Duration) (time.Duration, time.Duration, error) {
	if _, err := c.location(); err != nil || c.Calendar != CalendarCivil || precision != time.Minute && precision != time.Second || w.Day < time.Sunday || w.Day > time.Saturday || w.Start < 0 || w.Start >= w.End || w.End > civilDay {
		return 0, 0, ErrScheduleTime
	}
	end := w.End
	if c.EndBoundary == "inclusive" {
		end -= time.Duration(c.TickSeconds) * time.Second
	}
	if end < w.Start || w.Start%precision != 0 || end%precision != 0 {
		return 0, 0, ErrScheduleTime
	}
	return w.Start, end, nil
}
