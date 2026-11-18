package hillstone

import (
	"strings"
	"time"

	"github.com/gatework/firemon"
)

// schedule parses: schedule "NAME"
//
//	absolute [start M/D/YYYY HH:MM:SS] end M/D/YYYY HH:MM:SS
//	periodic daily|weekdays|weekend|DAY... HH:MM:SS to HH:MM:SS
//	description "TEXT"
//
// Periodic forms spanning days ("monday 08:00 to friday 18:00"), day-in-month
// and day-range are reported as diagnostics; a schedule with an unparsed
// period makes the rules using it undecidable.
func (s *state) schedule(b block, head *words) {
	name := head.next()
	sch := s.schedules.upsert(name, func() firemon.Schedule { return firemon.Schedule{Name: name} })
	for _, l := range b.body {
		w := newWords(l.Text)
		switch w.next() {
		case "absolute":
			win, ok := s.absolute(w)
			if !ok {
				s.diagnose(l, "invalid absolute schedule")
				sch.Unsupported = "absolute: " + strings.TrimSpace(l.Text)
				continue
			}
			sch.Windows = append(sch.Windows, win)
		case "periodic":
			r, ok := periodic(w)
			if !ok {
				s.diagnose(l, "unsupported periodic schedule")
				sch.Unsupported = strings.TrimSpace(l.Text)
				continue
			}
			sch.Recurrences = append(sch.Recurrences, r)
		case "description":
			sch.Description = w.next()
		default:
			continue
		}
		s.mark(l)
	}
}

func (s *state) absolute(w *words) (firemon.TimeWindow, bool) {
	var win firemon.TimeWindow
	for !w.done() {
		var target *time.Time
		switch w.next() {
		case "start":
			target = &win.Start
		case "end":
			target = &win.End
		default:
			return firemon.TimeWindow{}, false
		}
		t, ok := s.dateTime(w)
		if !ok {
			return firemon.TimeWindow{}, false
		}
		*target = t
	}
	return win, !win.End.IsZero()
}

// dateTime parses "M/D/YYYY [HH:MM[:SS]]" in the device time zone.
func (s *state) dateTime(w *words) (time.Time, bool) {
	date := w.next()
	clock := "00:00:00"
	if strings.Contains(w.peek(), ":") {
		clock = w.next()
		if strings.Count(clock, ":") == 1 {
			clock += ":00"
		}
	}
	t, err := time.ParseInLocation("1/2/2006 15:4:5", date+" "+clock, s.loc)
	return t, err == nil
}

func periodic(w *words) (firemon.Recurrence, bool) {
	var r firemon.Recurrence
	switch kw := w.peek(); kw {
	case "daily":
		w.next()
	case "weekdays":
		w.next()
		r.Days = []time.Weekday{time.Monday, time.Tuesday, time.Wednesday, time.Thursday, time.Friday}
	case "weekend":
		w.next()
		r.Days = []time.Weekday{time.Saturday, time.Sunday}
	default:
		for {
			d, ok := weekday(w.peek())
			if !ok {
				break
			}
			w.next()
			r.Days = append(r.Days, d)
		}
		if len(r.Days) == 0 {
			return firemon.Recurrence{}, false
		}
	}
	start, ok := clockOffset(w.next())
	if !ok || w.next() != "to" {
		return firemon.Recurrence{}, false
	}
	end, ok := clockOffset(w.next())
	if !ok || !w.done() {
		return firemon.Recurrence{}, false
	}
	r.Start, r.End = start, end
	return r, true
}

func weekday(text string) (time.Weekday, bool) {
	for d := time.Sunday; d <= time.Saturday; d++ {
		if strings.EqualFold(text, d.String()) {
			return d, true
		}
	}
	return 0, false
}

func clockOffset(text string) (time.Duration, bool) {
	if strings.Count(text, ":") == 1 {
		text += ":00"
	}
	t, err := time.Parse("15:4:5", text)
	if err != nil {
		return 0, false
	}
	return time.Duration(t.Hour())*time.Hour + time.Duration(t.Minute())*time.Minute + time.Duration(t.Second())*time.Second, true
}
