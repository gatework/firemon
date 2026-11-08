package asa

import (
	"context"
	"strings"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/vendors/internal/schedule"
)

func (p *parser) schedules(ctx context.Context, s *config.Builder) error {
	tx := s.Begin()
	defer tx.Rollback()
	var data fm.Data
	for _, b := range p.blocks {
		if b.kind != "time-range" {
			continue
		}
		r := fm.ScheduleRecord{Object: object(b)}
		tx.Parse(b.header.Lines()...)
		var start, end time.Time
		hasAbsolute := false
		for _, line := range b.members {
			if err := ctx.Err(); err != nil {
				return err
			}
			w, ok := line.Words, false
			r.Spans = append(r.Spans, line.Span)
			if len(w) > 1 && w[0] == "absolute" {
				if hasAbsolute {
					r.Unsupported = append(r.Unsupported, "repeated absolute time-range")
				}
				hasAbsolute = true
				var a, z string
				valid := true
				for rest := w[1:]; len(rest) > 0; {
					if len(rest) < 5 {
						valid = false
						break
					}
					value := strings.Join(rest[1:5], " ")
					if rest[0] == "start" && a == "" {
						a = value
					} else if rest[0] == "end" && z == "" {
						z = value
					} else {
						valid = false
						break
					}
					rest = rest[5:]
				}
				// Omitted native start means creation time, which a later
				// running-config capture does not establish.
				if valid && a != "" {
					var err, errEnd error
					start, r.Timezone, err = s.ScheduleBound("15:04 2 January 2006", a, false)
					end, _, errEnd = s.ScheduleBound("15:04 2 January 2006", z, true)
					ok = err == nil && errEnd == nil && (end.IsZero() || start.Before(end))
				}
			} else if len(w) > 1 && w[0] == "periodic" {
				windows, zone, err := schedule.Periodic(s, w[1:])
				if err == nil {
					schedule.AddWeekly(&r, windows, zone)
					ok = true
				}
			}
			if ok {
				tx.Parse(line.Lines()...)
			} else {
				r.Unsupported = append(r.Unsupported, "unsupported time-range or missing schedule clock")
			}
		}
		if hasAbsolute && !start.IsZero() {
			if len(r.Weekly) > 0 {
				r.Weekly[0].Start, r.Weekly[0].End = start, end
			} else if !end.IsZero() {
				r.Windows = []fm.TimeWindow{{Start: start, End: end}}
			} else {
				r.Unsupported = append(r.Unsupported, "unbounded absolute time-range")
			}
		}
		if len(r.Windows) == 0 && len(r.Weekly) == 0 {
			r.Unsupported = append(r.Unsupported, "empty or unresolved time-range")
		}
		data.Schedules = append(data.Schedules, r)
	}
	tx.Emit(data)
	return s.Commit(tx)
}
