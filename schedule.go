package firemon

import (
	"iter"
	"slices"
	"strings"
	"time"
)

const civilDay = 24 * time.Hour

// Windows visits absolute windows by value in declaration order.
func (s *Schedule) Windows() iter.Seq[TimeWindow] {
	return func(yield func(TimeWindow) bool) {
		for _, window := range s.record.Windows {
			if !yield(window) {
				return
			}
		}
	}
}

// Weekly visits independent copies of recurring periods.
func (s *Schedule) Weekly() iter.Seq[WeeklyPeriod] {
	return func(yield func(WeeklyPeriod) bool) {
		for _, period := range s.record.Weekly {
			period.Windows = slices.Clone(period.Windows)
			if !yield(period) {
				return
			}
		}
	}
}

func (r ScheduleRecord) HasRecurrence() bool { return len(r.Weekly) != 0 }
func (s *Schedule) HasRecurrence() bool      { return s.record.HasRecurrence() }

func (s *Schedule) Timezone() string       { return s.record.Timezone }
func (s *Schedule) WeeklyCount() int       { return len(s.record.Weekly) }
func (s *Schedule) WeeklyWindowCount() int { return s.weeklyWindows }

// Validate requires both well-formed intervals and sufficient time evidence.
// Unsupported declarations cannot become a known schedule through validation.
func (r ScheduleRecord) Validate() error {
	if err := r.validateShape(); err != nil {
		return err
	}
	if len(r.Unsupported) != 0 || len(r.Windows)+len(r.Weekly) == 0 {
		return ErrScheduleTime
	}
	if r.HasRecurrence() {
		if r.Calendar != CalendarCivil {
			return ErrScheduleTime
		}
		if _, err := scheduleLocation(r.Timezone); err != nil {
			return err
		}
	}
	return nil
}

func (r ScheduleRecord) validateShape() error {
	for _, w := range r.Windows {
		if w.Start.IsZero() || w.End.IsZero() || !w.Start.Before(w.End) {
			return ErrScheduleTime
		}
	}
	for _, p := range r.Weekly {
		if len(p.Windows) == 0 || !p.Start.IsZero() && !p.End.IsZero() && !p.Start.Before(p.End) {
			return ErrScheduleTime
		}
		for _, w := range p.Windows {
			if w.Day < time.Sunday || w.Day > time.Saturday || w.Start < 0 || w.Start >= w.End || w.End > civilDay {
				return ErrScheduleTime
			}
		}
	}
	return nil
}

func scheduleLocation(name string) (*time.Location, error) {
	if name == "" || name == "Local" || len(name) > 128 || strings.HasPrefix(name, "/") || strings.Contains(name, "..") {
		return nil, ErrScheduleTime
	}
	loc, err := time.LoadLocation(name)
	if err != nil {
		return nil, ErrScheduleTime
	}
	return loc, nil
}

// normalizeWeekly merges overlapping or adjacent windows within each weekday.
// The caller owns the slice. It never joins across a midnight boundary.
func normalizeWeekly(windows []WeeklyWindow) []WeeklyWindow {
	slices.SortFunc(windows, func(a, b WeeklyWindow) int {
		if a.Day != b.Day {
			return int(a.Day - b.Day)
		}
		if a.Start < b.Start {
			return -1
		}
		if a.Start > b.Start {
			return 1
		}
		return 0
	})
	result := windows[:0]
	for _, w := range windows {
		if n := len(result); n != 0 && result[n-1].Day == w.Day && w.Start <= result[n-1].End {
			result[n-1].End = max(result[n-1].End, w.End)
		} else {
			result = append(result, w)
		}
	}
	return result
}

func normalizeWeeklyPeriods(periods []WeeklyPeriod) []WeeklyPeriod {
	for i := range periods {
		periods[i].Start = periods[i].Start.UTC()
		periods[i].End = periods[i].End.UTC()
	}
	slices.SortFunc(periods, func(a, b WeeklyPeriod) int {
		if c := a.Start.Compare(b.Start); c != 0 {
			return c
		}
		return a.End.Compare(b.End)
	})
	result := periods[:0]
	for _, period := range periods {
		if n := len(result); n > 0 && result[n-1].Start.Equal(period.Start) && result[n-1].End.Equal(period.End) {
			result[n-1].Windows = append(result[n-1].Windows, period.Windows...)
		} else {
			result = append(result, period)
		}
	}
	for i := range result {
		result[i].Windows = normalizeWeekly(result[i].Windows)
	}
	return result
}

// ActiveAt evaluates the union of absolute and recurring half-open intervals.
// Unknown evidence remains possibly active; the second value is false.
func (s *Schedule) ActiveAt(at time.Time) (active, known bool) {
	if !s.knownAt(at) {
		return true, false
	}
	for _, window := range s.record.Windows {
		if !at.Before(window.Start) && at.Before(window.End) {
			return true, true
		}
	}
	if s.HasRecurrence() {
		local := at.In(s.location)
		clock := time.Duration(local.Hour())*time.Hour + time.Duration(local.Minute())*time.Minute + time.Duration(local.Second())*time.Second + time.Duration(local.Nanosecond())
		for _, period := range s.record.Weekly {
			if !period.Start.IsZero() && at.Before(period.Start) || !period.End.IsZero() && !at.Before(period.End) {
				continue
			}
			for _, window := range period.Windows {
				if local.Weekday() == window.Day && clock >= window.Start && clock < window.End {
					return true, true
				}
			}
		}
	}
	return false, true
}

// ExpiredAt establishes expiry only after all declared periods have ended.
// An unbounded recurrence never expires; an inactive or future interval is not
// expired. Unknown declarations cannot establish expiry.
func (s *Schedule) ExpiredAt(at time.Time) (expired, known bool) {
	if !s.knownAt(at) {
		return false, false
	}
	for _, window := range s.record.Windows {
		if window.End.After(at) {
			return false, true
		}
	}
	for _, period := range s.record.Weekly {
		if period.End.IsZero() || period.End.After(at) {
			return false, true
		}
	}
	return true, true
}

func (s *Schedule) knownAt(at time.Time) bool {
	return s != nil && !at.IsZero() && s.known
}
