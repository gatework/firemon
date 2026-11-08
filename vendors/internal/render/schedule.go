package render

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/plan"
)

// SupportsSchedule is the single version gate used by registry capabilities and
// native rendering. It establishes syntax support, never clock evidence.
func SupportsSchedule(vendor, software string) bool {
	switch vendor {
	case "hillstone":
		v := strings.TrimPrefix(software, "StoneOS ")
		return v == "5.5R8" || strings.HasPrefix(v, "5.5R8P")
	case "paloalto":
		return strings.HasPrefix(strings.TrimPrefix(software, "PAN-OS "), "10.2.")
	case "asa":
		return strings.HasPrefix(strings.TrimPrefix(software, "ASA Version "), "9.16")
	case "srx":
		return strings.HasPrefix(strings.TrimPrefix(software, "JUNOS "), "21.4R3")
	case "fortinet":
		return strings.HasPrefix(software, "7.2.")
	case "huawei":
		return strings.HasPrefix(software, "V500R005")
	case "netscreen":
		return strings.HasPrefix(software, "6.3.")
	}
	return false
}

// ScheduleCommands emits only schedules whose complete meaning has a native
// representation. Capture-bound clock, endpoint and calendar evidence is checked
// independently from the vendor grammar and release gate.
func ScheduleCommands(before, after *fm.Firewall, c plan.NativeChanges) ([]string, error) {
	if len(c.Additions.Schedules) == 0 {
		return nil, nil
	}
	if c.Clock == nil {
		return nil, plan.ErrRender
	}
	if err := c.Clock.Validate(before.Metadata()); err != nil {
		return nil, err
	}
	var out []string
	for _, r := range c.Additions.Schedules {
		commands, err := scheduleCommands(before.Metadata(), *c.Clock, r)
		if err != nil {
			return nil, err
		}
		out = append(out, commands...)
	}
	return out, nil
}

func scheduleCommands(m fm.Metadata, clock fm.ScheduleClock, r fm.ScheduleRecord) ([]string, error) {
	name, e := Token(r.Name)
	if e != nil || len(name) > 31 || r.ID != fm.ID(name) || r.Scope != "" || !PlainObject(r.Object) || r.Validate() != nil || r.Timezone != clock.Timezone || !SupportsSchedule(m.Vendor, m.Software) {
		return nil, plan.ErrRender
	}
	precision := time.Minute
	if m.Vendor == "huawei" {
		precision = time.Second
	}
	quoted := strconv.Quote(name)
	if len(r.Windows) > 0 {
		if len(r.Weekly) > 0 || len(r.Windows) != 1 && m.Vendor != "paloalto" && m.Vendor != "huawei" {
			return nil, plan.ErrRender
		}
		var out []string
		for _, w := range r.Windows {
			start, end, err := clock.NativeWindow(w, precision)
			if err != nil {
				return nil, err
			}
			switch m.Vendor {
			case "hillstone":
				out = append(out, "schedule "+quoted, "absolute start "+start.Format("01/02/2006 15:04")+" end "+end.Format("01/02/2006 15:04"), "exit")
			case "asa":
				out = append(out, "time-range "+name, "absolute start "+start.Format("15:04 2 January 2006")+" end "+end.Format("15:04 2 January 2006"), "exit")
			case "srx":
				out = append(out, "set schedulers scheduler "+name+" start-date "+start.Format("2006-01-02.15:04")+" stop-date "+end.Format("2006-01-02.15:04"))
			case "paloalto":
				out = append(out, "set schedule "+quoted+" schedule-type non-recurring "+start.Format("2006/01/02@15:04")+"-"+end.Format("2006/01/02@15:04"))
			case "fortinet":
				out = append(out, "config firewall schedule onetime", "edit "+quoted, "set start "+start.Format("15:04 2006/01/02"), "set end "+end.Format("15:04 2006/01/02"), "next", "end")
			case "huawei":
				out = append(out, "time-range "+name, "absolute-range "+start.Format("15:04:05 2006/01/02")+" to "+end.Format("15:04:05 2006/01/02"), "quit")
			case "netscreen":
				out = append(out, "set scheduler "+quoted+" once start "+start.Format("1/2/2006 15:04")+" stop "+end.Format("1/2/2006 15:04"))
			}
		}
		return out, nil
	}
	if len(r.Weekly) != 1 || clock.Calendar != fm.CalendarCivil {
		return nil, plan.ErrRender
	}
	period := r.Weekly[0]
	period.Windows = slices.Clone(period.Windows)
	slices.SortFunc(period.Windows, func(a, b fm.WeeklyWindow) int {
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
	bounded := !period.Start.IsZero() || !period.End.IsZero()
	if bounded && m.Vendor != "hillstone" && m.Vendor != "asa" && m.Vendor != "srx" {
		return nil, plan.ErrRender
	}
	var out []string
	switch m.Vendor {
	case "hillstone":
		out = append(out, "schedule "+quoted)
	case "asa":
		out = append(out, "time-range "+name)
	case "huawei":
		out = append(out, "time-range "+name)
	}
	if bounded {
		start, end, e := nativeBounds(clock, period, precision)
		if e != nil {
			return nil, e
		}
		if m.Vendor == "srx" {
			line := "set schedulers scheduler " + name
			if !start.IsZero() {
				line += " start-date " + start.Format("2006-01-02.15:04")
			}
			if !end.IsZero() {
				line += " stop-date " + end.Format("2006-01-02.15:04")
			}
			out = append(out, line)
		} else {
			// These native grammars interpret an omitted start as creation
			// time, so an unbounded-start graph cannot be emitted exactly.
			if start.IsZero() {
				return nil, plan.ErrRender
			}
			layout := "01/02/2006 15:04"
			if m.Vendor == "asa" {
				layout = "15:04 2 January 2006"
			}
			line := "absolute start " + start.Format(layout)
			if !end.IsZero() {
				line += " end " + end.Format(layout)
			}
			out = append(out, line)
		}
	}
	if m.Vendor == "fortinet" {
		return fortinetWeekly(clock, name, period.Windows)
	}
	counts := [7]int{}
	for _, w := range period.Windows {
		counts[w.Day]++
		if m.Vendor == "srx" && w.Start == 0 && w.End == 24*time.Hour {
			out = append(out, "set schedulers scheduler "+name+" "+strings.ToLower(w.Day.String())+" all-day")
			continue
		}
		start, end, e := clock.NativeWeekly(w, precision)
		if e != nil {
			return nil, e
		}
		day := strings.ToLower(w.Day.String())
		a, b := wallTime(start, precision), wallTime(end, precision)
		if end == 24*time.Hour && m.Vendor != "hillstone" && m.Vendor != "asa" && m.Vendor != "srx" {
			return nil, plan.ErrRender
		}
		switch m.Vendor {
		case "hillstone", "asa":
			last := ""
			if end == 24*time.Hour {
				last = strings.ToLower(((w.Day + 1) % 7).String()) + " "
				b = "00:00"
			}
			out = append(out, "periodic "+day+" "+a+" to "+last+b)
		case "srx":
			prefix := "set schedulers scheduler " + name + " " + day
			if end == 24*time.Hour {
				return nil, plan.ErrRender
			}
			out = append(out, prefix+" start-time "+a+" stop-time "+b)
		case "paloalto":
			out = append(out, "set schedule "+quoted+" schedule-type recurring weekly "+day+" "+a+"-"+b)
		case "huawei":
			out = append(out, "period-range "+a+" to "+b+" "+day)
		case "netscreen":
			if counts[w.Day] > 2 {
				return nil, plan.ErrRender
			}
			if counts[w.Day] == 1 {
				out = append(out, "set scheduler "+quoted+" recurrent "+day)
			}
			out[len(out)-1] += " start " + a + " stop " + b
		}
	}
	switch m.Vendor {
	case "hillstone", "asa":
		out = append(out, "exit")
	case "huawei":
		out = append(out, "quit")
	}
	return out, nil
}

func nativeBounds(c fm.ScheduleClock, p fm.WeeklyPeriod, precision time.Duration) (time.Time, time.Time, error) {
	a, e := c.NativeBound(p.Start, false, precision)
	if e != nil {
		return time.Time{}, time.Time{}, e
	}
	b, e := c.NativeBound(p.End, true, precision)
	return a, b, e
}
func wallTime(at, precision time.Duration) string {
	h := at / time.Hour
	m := at % time.Hour / time.Minute
	if precision == time.Second {
		return fmt.Sprintf("%02d:%02d:%02d", h, m, at%time.Minute/time.Second)
	}
	return fmt.Sprintf("%02d:%02d", h, m)
}

// FortiOS recurring objects have one daily interval shared by their selected
// weekdays. Refuse heterogeneous windows rather than widening the object.
func fortinetWeekly(clock fm.ScheduleClock, name string, windows []fm.WeeklyWindow) ([]string, error) {
	if len(windows) == 0 || len(windows) > 14 {
		return nil, plan.ErrRender
	}
	starts, ends := []time.Duration{}, []time.Duration{}
	for _, w := range windows {
		if w.Start%time.Minute == 0 {
			starts = append(starts, w.Start)
			ends = append(ends, w.Start)
		}
		end := w.End
		if clock.EndBoundary == "inclusive" {
			end -= time.Duration(clock.TickSeconds) * time.Second
		}
		if end >= 0 && end < 24*time.Hour && end%time.Minute == 0 {
			ends = append(ends, end)
		}
		if w.End == 24*time.Hour {
			ends = append(ends, 0)
		}
	}
	slices.Sort(starts)
	starts = slices.Compact(starts)
	slices.Sort(ends)
	ends = slices.Compact(ends)
	for _, start := range starts {
		for _, end := range ends {
			var days []string
			var covered []fm.WeeklyWindow
			for day := time.Sunday; day <= time.Saturday; day++ {
				var parts []fm.WeeklyWindow
				if start == end {
					parts = []fm.WeeklyWindow{{Day: day, Start: start, End: 24 * time.Hour}}
					if start > 0 {
						parts = append(parts, fm.WeeklyWindow{Day: (day + 1) % 7, End: start})
					}
				} else {
					var err error
					parts, err = clock.ParseWeekly([]time.Weekday{day}, wallTime(start, time.Minute), wallTime(end, time.Minute))
					if err != nil {
						continue
					}
				}
				if weeklyContains(windows, parts) {
					days = append(days, strings.ToLower(day.String()))
					covered = append(covered, parts...)
				}
			}
			if len(days) > 0 && weeklyContains(covered, windows) {
				return []string{"config firewall schedule recurring", "edit " + strconv.Quote(name), "set start " + wallTime(start, time.Minute), "set end " + wallTime(end, time.Minute), "set day " + strings.Join(days, " "), "next", "end"}, nil
			}
		}
	}
	return nil, plan.ErrRender
}

func weeklyContains(have, want []fm.WeeklyWindow) bool {
	// Each candidate contains at most one interval per originating weekday.
	// Sorting/merging also handles overlaps introduced by adjacent selected days.
	have = slices.Clone(have)
	slices.SortFunc(have, func(a, b fm.WeeklyWindow) int {
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
	for _, w := range want {
		at := w.Start
		for _, v := range have {
			if v.Day != w.Day || v.End <= at {
				continue
			}
			if v.Start > at {
				break
			}
			at = max(at, v.End)
			if at >= w.End {
				break
			}
		}
		if at < w.End {
			return false
		}
	}
	return true
}

func (b Batch) ScheduleReference(after *fm.Firewall, id fm.ID) (string, error) {
	if id == "" {
		return "", nil
	}
	if b.clock == nil {
		return "", plan.ErrRender
	}
	s := after.Schedule(id)
	if s == nil {
		return "", plan.ErrRender
	}
	r := s.Record()
	if _, err := scheduleCommands(after.Metadata(), *b.clock, r); err != nil {
		return "", err
	}
	return r.Name, nil
}
