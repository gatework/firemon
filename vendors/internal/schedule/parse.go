// Package schedule contains shared native schedule grammar primitives. Vendor
// parsers retain responsibility for native combinations and overriding fields.
package schedule

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
)

// Clock accepts the one- or two-digit components printed by native CLIs and
// returns the canonical civil spelling required by the domain clock.
func Clock(value string) (string, error) {
	parts := strings.Split(value, ":")
	if len(parts) != 2 && len(parts) != 3 {
		return "", fm.ErrScheduleTime
	}
	for i, part := range parts {
		if len(part) < 1 || len(part) > 2 {
			return "", fm.ErrScheduleTime
		}
		for _, r := range part {
			if r < '0' || r > '9' {
				return "", fm.ErrScheduleTime
			}
		}
		v, err := strconv.Atoi(part)
		if err != nil || v > 59 || i == 0 && v > 24 {
			return "", fm.ErrScheduleTime
		}
		parts[i] = fmt.Sprintf("%02d", v)
	}
	return strings.Join(parts, ":"), nil
}

func Weekly(s *config.Builder, days []time.Weekday, start, end string) ([]fm.WeeklyWindow, string, error) {
	a, err := Clock(start)
	if err != nil {
		return nil, "", err
	}
	b, err := Clock(end)
	if err != nil {
		return nil, "", err
	}
	return s.ScheduleWeekly(days, a, b)
}

// SameDay is used by grammars which require separate day entries at midnight.
// FortiOS is deliberately different: its stop-before-start form means overnight.
func SameDay(s *config.Builder, days []time.Weekday, start, end string) ([]fm.WeeklyWindow, string, error) {
	a, e := Clock(start)
	b, e2 := Clock(end)
	if e != nil || e2 != nil || strings.HasPrefix(a, "24:") || strings.HasPrefix(b, "24:") {
		return nil, "", fm.ErrScheduleTime
	}
	parse := func(v string) (time.Time, error) {
		if len(v) == 5 {
			return time.Parse("15:04", v)
		}
		return time.Parse("15:04:05", v)
	}
	x, e := parse(a)
	y, e2 := parse(b)
	if e != nil || e2 != nil || y.Before(x) {
		return nil, "", fm.ErrScheduleTime
	}
	return s.ScheduleWeekly(days, a, b)
}

// Days resolves explicit weekday names. Aliases are supplied by the native
// parser; an unrecognized selector never becomes every day.
func Days(words []string, aliases map[string][]time.Weekday) ([]time.Weekday, error) {
	var days []time.Weekday
	for _, word := range words {
		word = strings.ToLower(word)
		if group, ok := aliases[word]; ok {
			days = append(days, group...)
			continue
		}
		found := false
		for day := time.Sunday; day <= time.Saturday; day++ {
			if word == strings.ToLower(day.String()) {
				days = append(days, day)
				found = true
				break
			}
		}
		if !found {
			return nil, fm.ErrScheduleTime
		}
	}
	if len(days) == 0 {
		return nil, fm.ErrScheduleTime
	}
	slices.Sort(days)
	return slices.Compact(days), nil
}

func EveryDay() []time.Weekday {
	return []time.Weekday{time.Sunday, time.Monday, time.Tuesday, time.Wednesday, time.Thursday, time.Friday, time.Saturday}
}

// FullDays handles native all-day/equal-endpoint forms. Calendar evidence is
// still required; their 24-hour civil meaning does not add an endpoint tick.
func FullDays(s *config.Builder, days []time.Weekday, start string) ([]fm.WeeklyWindow, string, error) {
	_, zone, err := s.ScheduleWeekly(days, "00:00", "00:01")
	if err != nil {
		return nil, "", err
	}
	start, err = Clock(start)
	if err != nil {
		return nil, "", err
	}
	at, err := time.Parse("15:04", start)
	if err != nil {
		return nil, "", fm.ErrScheduleTime
	}
	offset := time.Duration(at.Hour())*time.Hour + time.Duration(at.Minute())*time.Minute
	var windows []fm.WeeklyWindow
	for _, day := range days {
		windows = append(windows, fm.WeeklyWindow{Day: day, Start: offset, End: 24 * time.Hour})
		if offset > 0 {
			windows = append(windows, fm.WeeklyWindow{Day: (day + 1) % 7, End: offset})
		}
	}
	return windows, zone, nil
}

// Periodic parses the weekday-list / time / to / optional-weekday / time
// grammar shared by StoneOS and ASA, including continuous multi-day spans.
func Periodic(s *config.Builder, words []string) ([]fm.WeeklyWindow, string, error) {
	i := slices.Index(words, "to")
	if i < 2 || i+1 >= len(words) {
		return nil, "", fm.ErrScheduleTime
	}
	days, err := Days(words[:i-1], map[string][]time.Weekday{
		"daily":    EveryDay(),
		"weekdays": {time.Monday, time.Tuesday, time.Wednesday, time.Thursday, time.Friday},
		"weekend":  {time.Saturday, time.Sunday},
	})
	if err != nil {
		return nil, "", err
	}
	if len(words) == i+2 {
		return SameDay(s, days, words[i-1], words[i+1])
	}
	if len(days) == 1 && len(words) == i+3 {
		end, err := Days(words[i+1:i+2], nil)
		if err == nil {
			a, e := Clock(words[i-1])
			b, e2 := Clock(words[i+2])
			if e == nil && e2 == nil {
				return s.ScheduleWeeklySpan(days[0], end[0], a, b)
			}
		}
	}
	return nil, "", fm.ErrScheduleTime
}

func AddWeekly(r *fm.ScheduleRecord, windows []fm.WeeklyWindow, zone string) {
	if len(r.Weekly) == 0 {
		r.Weekly = []fm.WeeklyPeriod{{}}
	}
	r.Weekly[0].Windows = append(r.Weekly[0].Windows, windows...)
	r.Timezone, r.Calendar = zone, fm.CalendarCivil
}

// Restrict applies native date AND weekly semantics. Dates are never left as
// independent union members, which would permit traffic outside weekly hours.
func Restrict(r *fm.ScheduleRecord) {
	if len(r.Windows) == 0 || len(r.Weekly) == 0 {
		return
	}
	var periods []fm.WeeklyPeriod
	for _, absolute := range r.Windows {
		for _, weekly := range r.Weekly {
			weekly.Start, weekly.End = absolute.Start, absolute.End
			periods = append(periods, weekly)
		}
	}
	r.Windows, r.Weekly = nil, periods
}
