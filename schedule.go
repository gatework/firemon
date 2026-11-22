package firemon

import (
	"slices"
	"time"
)

// TimeWindow is an absolute interval [Start, End). A zero Start or End is
// unbounded on that side.
type TimeWindow struct {
	Start time.Time `json:"start,omitzero"`
	End   time.Time `json:"end,omitzero"`
}

// Contains reports whether t falls inside the window.
func (w TimeWindow) Contains(t time.Time) bool {
	return (w.Start.IsZero() || !t.Before(w.Start)) && (w.End.IsZero() || t.Before(w.End))
}

// Recurrence is a daily time-of-day interval on selected weekdays or days
// of the month. Start and End are offsets from local midnight and End is
// exclusive; End before Start wraps past midnight, and End equal to Start
// covers the whole day.
type Recurrence struct {
	// Days lists the weekdays the interval starts on; empty means every day.
	Days []time.Weekday `json:"days,omitempty"`
	// MonthDays lists the days of the month (1-31) the interval starts on;
	// empty means every day. With Days as well, a day must be in both.
	MonthDays []int         `json:"month_days,omitempty"`
	Start     time.Duration `json:"start"`
	End       time.Duration `json:"end"`
}

// Contains reports whether the wall-clock time of t falls inside the
// recurrence. t must already be in the device time zone.
func (r Recurrence) Contains(t time.Time) bool {
	offset := time.Duration(t.Hour())*time.Hour + time.Duration(t.Minute())*time.Minute + time.Duration(t.Second())*time.Second
	onDay := func(d time.Time) bool {
		return (len(r.Days) == 0 || slices.Contains(r.Days, d.Weekday())) &&
			(len(r.MonthDays) == 0 || slices.Contains(r.MonthDays, d.Day()))
	}
	if r.Start == r.End {
		return onDay(t)
	}
	if r.Start < r.End {
		return onDay(t) && offset >= r.Start && offset < r.End
	}
	// Wrapping interval: the evening part belongs to today, the morning part
	// to the interval that started yesterday.
	return (onDay(t) && offset >= r.Start) || (onDay(t.AddDate(0, 0, -1)) && offset < r.End)
}

// Schedule is a named time restriction. A schedule is active when any
// absolute window or any recurrence contains the instant.
type Schedule struct {
	Name        string       `json:"name"`
	Description string       `json:"description,omitempty"`
	Windows     []TimeWindow `json:"windows,omitempty"`
	Recurrences []Recurrence `json:"recurrences,omitempty"`
	// Unsupported describes a period the parser could not model; rules using
	// the schedule are undecidable.
	Unsupported string `json:"unsupported,omitempty"`
}

// ActiveAt reports whether the schedule is active at t, which must already
// be in the device time zone.
func (s Schedule) ActiveAt(t time.Time) bool {
	for _, w := range s.Windows {
		if w.Contains(t) {
			return true
		}
	}
	for _, r := range s.Recurrences {
		if r.Contains(t) {
			return true
		}
	}
	return false
}

// ExpiredAt reports whether the schedule has only absolute windows and all
// of them ended at or before t: the schedule can never be active again.
func (s Schedule) ExpiredAt(t time.Time) bool {
	if len(s.Recurrences) > 0 || len(s.Windows) == 0 {
		return false
	}
	for _, w := range s.Windows {
		if w.End.IsZero() || t.Before(w.End) {
			return false
		}
	}
	return true
}
