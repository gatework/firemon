package netscreen

import (
	"context"
	"slices"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/vendors/internal/schedule"
)

func (p *parser) schedules(ctx context.Context, s *config.Builder) error {
	tx := s.Begin()
	defer tx.Rollback()
	var schedules catalog[fm.ScheduleRecord]
	seen := make(map[string]bool)
	for _, line := range p.rows {
		if err := ctx.Err(); err != nil {
			return err
		}
		w := line.Words
		if line.scope != "root" || !begins(w, "set", "scheduler") || len(w) < 3 {
			continue
		}
		r := schedules.get(w[2])
		r.ID, r.Name = fm.ID(w[2]), w[2]
		touch(&r.Object, line)
		if i := slices.Index(w[3:], "comment"); i >= 0 && i+5 == len(w) {
			w = w[:i+3]
		}
		ok := false
		if len(w) == 10 && w[3] == "once" && w[4] == "start" && w[7] == "stop" && len(r.Windows) == 0 && len(r.Weekly) == 0 {
			window, zone, err := s.ScheduleWindow("1/2/2006 15:04", w[5]+" "+w[6], w[8]+" "+w[9])
			if err == nil {
				r.Windows = []fm.TimeWindow{window}
				r.Timezone = zone
				ok = true
			}
		} else if len(w) >= 9 && w[3] == "recurrent" && len(r.Windows) == 0 {
			days, err := schedule.Days(w[4:5], nil)
			key := w[2] + "/" + w[4]
			if err == nil && !seen[key] && (len(w)-5)%4 == 0 && len(w) <= 13 {
				var windows []fm.WeeklyWindow
				zone := ""
				ok = true
				for i := 5; i < len(w); i += 4 {
					if w[i] != "start" || w[i+2] != "stop" {
						ok = false
						break
					}
					part, z, e := schedule.SameDay(s, days, w[i+1], w[i+3])
					if e != nil {
						ok = false
						break
					}
					windows = append(windows, part...)
					zone = z
				}
				if ok {
					schedule.AddWeekly(r, windows, zone)
					seen[key] = true
				}
			}
		}
		if ok {
			tx.Parse(line.Lines()...)
		} else {
			r.Unsupported = append(r.Unsupported, "unsupported scheduler or missing schedule clock")
		}
	}
	var d fm.Data
	for _, name := range schedules.names {
		d.Schedules = append(d.Schedules, *schedules.entries[name])
	}
	tx.Emit(d)
	return s.Commit(tx)
}
