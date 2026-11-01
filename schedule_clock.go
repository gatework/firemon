package firemon

import (
	"errors"
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
}

func (c ScheduleClock) location() (*time.Location, error) {
	if c.Timezone == "" || c.Timezone == "Local" || len(c.Timezone) > 128 || strings.HasPrefix(c.Timezone, "/") || strings.Contains(c.Timezone, "..") || c.Reference == "" || len(c.Reference) > 1024 || c.EndBoundary != "exclusive" && c.EndBoundary != "inclusive" || c.TickSeconds != 1 && c.TickSeconds != 60 {
		return nil, ErrScheduleTime
	}
	loc, err := time.LoadLocation(c.Timezone)
	if err != nil {
		return nil, ErrScheduleTime
	}
	return loc, nil
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
	loc, err := c.location()
	if err != nil {
		return TimeWindow{}, err
	}
	a, err := civilTime(layout, start, loc)
	if err != nil {
		return TimeWindow{}, err
	}
	b, err := civilTime(layout, end, loc)
	if err != nil {
		return TimeWindow{}, err
	}
	if c.EndBoundary == "inclusive" {
		b = b.Add(time.Duration(c.TickSeconds) * time.Second)
	}
	if a.IsZero() || !a.Before(b) {
		return TimeWindow{}, ErrScheduleTime
	}
	return TimeWindow{Start: a, End: b}, nil
}

// NativeWindow returns exact civil endpoints at the supported native precision.
// The inverse parse must recover precisely the supplied half-open UTC window.
func (c ScheduleClock) NativeWindow(w TimeWindow, precision time.Duration) (time.Time, time.Time, error) {
	loc, err := c.location()
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	if w.Start.IsZero() || !w.Start.Before(w.End) || precision != time.Minute && precision != time.Second {
		return time.Time{}, time.Time{}, ErrScheduleTime
	}
	end := w.End
	if c.EndBoundary == "inclusive" {
		end = end.Add(-time.Duration(c.TickSeconds) * time.Second)
	}
	a, b := w.Start.In(loc), end.In(loc)
	if a.Year() < 1970 || b.Year() > 2099 || !a.Before(b) || a.Nanosecond() != 0 || b.Nanosecond() != 0 || precision == time.Minute && (a.Second() != 0 || b.Second() != 0) {
		return time.Time{}, time.Time{}, ErrScheduleTime
	}
	layout := "2006-01-02 15:04:05"
	round, err := c.ParseWindow(layout, a.Format(layout), b.Format(layout))
	if err != nil || !round.Start.Equal(w.Start) || !round.End.Equal(w.End) {
		return time.Time{}, time.Time{}, ErrScheduleTime
	}
	return a, b, nil
}
