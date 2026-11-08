package srx

import (
	"context"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/vendors/internal/schedule"
)

type scheduleDay struct {
	windows     []fm.WeeklyWindow
	set, closed bool
}
type scheduleDraft struct {
	record     fm.ScheduleRecord
	start, end string
	daily      scheduleDay
	days       [7]scheduleDay
}

func (p *parser) schedules(ctx context.Context, s *config.Builder) error {
	tx := s.Begin()
	defer tx.Rollback()
	var drafts catalog[scheduleDraft]
	for _, row := range p.rows {
		if err := ctx.Err(); err != nil {
			return err
		}
		w := row.Words
		if len(w) < 5 || !begins(w, "set", "schedulers", "scheduler") {
			continue
		}
		d := drafts.get(w[3])
		r := &d.record
		r.ID, r.Name = fm.ID(w[3]), w[3]
		touch(&r.Object, row)
		rest, ok := w[4:], false
		if rest[0] == "start-date" || rest[0] == "stop-date" {
			ok = len(rest)%2 == 0
			for i := 0; ok && i < len(rest); i += 2 {
				switch rest[i] {
				case "start-date":
					if d.start != "" {
						ok = false
					}
					d.start = rest[i+1]
				case "stop-date":
					if d.end != "" {
						ok = false
					}
					d.end = rest[i+1]
				default:
					ok = false
				}
			}
		} else {
			days, e := schedule.Days(rest[:1], map[string][]time.Weekday{"daily": schedule.EveryDay()})
			if e == nil && len(rest) >= 2 {
				target := &d.daily
				if rest[0] != "daily" {
					target = &d.days[days[0]]
				}
				if !target.closed {
					var windows []fm.WeeklyWindow
					zone := ""
					switch {
					case len(rest) == 2 && rest[1] == "exclude":
						_, zone, e = schedule.SameDay(s, days, "00:00", "00:01")
						ok = e == nil && !target.set
						target.closed = true
					case len(rest) == 2 && rest[1] == "all-day":
						windows, zone, e = schedule.FullDays(s, days, "00:00")
						ok = e == nil && !target.set
						target.closed = true
					case len(rest) == 5 && rest[1] == "start-time" && rest[3] == "stop-time":
						windows, zone, e = schedule.SameDay(s, days, rest[2], rest[4])
						ok = e == nil && len(windows) == len(days)
					}
					if ok {
						target.set = true
						target.windows = append(target.windows, windows...)
						r.Timezone = zone
						r.Calendar = fm.CalendarCivil
					}
				}
			}
		}
		if ok {
			tx.Parse(row.Lines()...)
		} else {
			r.Unsupported = append(r.Unsupported, "unsupported scheduler field or missing schedule clock")
		}
	}
	var data fm.Data
	for _, name := range drafts.names {
		d := drafts.entries[name]
		r := &d.record
		var weekly []fm.WeeklyWindow
		hasWeekly := d.daily.set
		for day := time.Sunday; day <= time.Saturday; day++ {
			chosen := d.daily
			if d.days[day].set {
				chosen = d.days[day]
				hasWeekly = true
			}
			// Specific weekday values override daily values for that civil day.
			for _, w := range chosen.windows {
				if w.Day == day {
					weekly = append(weekly, w)
				}
			}
		}
		if hasWeekly && len(weekly) > 0 {
			if len(weekly) == 0 {
				r.Unsupported = append(r.Unsupported, "scheduler excludes every day")
			}
			start, zone, a := s.ScheduleBound("2006-01-02.15:04", d.start, false)
			end, _, b := s.ScheduleBound("2006-01-02.15:04", d.end, true)
			if a != nil || b != nil || !start.IsZero() && !end.IsZero() && !start.Before(end) {
				r.Unsupported = append(r.Unsupported, "invalid scheduler date bounds")
			} else {
				r.Weekly = []fm.WeeklyPeriod{{Start: start, End: end, Windows: weekly}}
				r.Timezone = zone
			}
		} else if d.start != "" && d.end != "" {
			w, zone, e := s.ScheduleWindow("2006-01-02.15:04", d.start, d.end)
			if e != nil {
				r.Unsupported = append(r.Unsupported, "invalid scheduler clock or dates")
			} else {
				r.Windows = []fm.TimeWindow{w}
				r.Timezone = zone
			}
		} else {
			r.Unsupported = append(r.Unsupported, "empty or unbounded scheduler")
		}
		data.Schedules = append(data.Schedules, *r)
	}
	tx.Emit(data)
	return s.Commit(tx)
}
