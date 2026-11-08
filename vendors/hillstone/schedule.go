package hillstone

import (
	"context"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/vendors/internal/schedule"
)

func parseSchedule(ctx context.Context, s *config.Builder, d definition) error {
	r := fm.ScheduleRecord{Object: d.object()}
	tx := s.Begin()
	defer tx.Rollback()
	absolute := false
	var openStart time.Time
	if err := d.walk(ctx, tx, &r.Object, func(w []string) bool {
		ok := ancillary(w)
		if len(w) == 4 && w[0] == "absolute" && w[1] == "start" {
			if absolute {
				r.Unsupported = append(r.Unsupported, "repeated absolute schedule")
			}
			absolute = true
			var err error
			openStart, r.Timezone, err = s.ScheduleBound("01/02/2006 15:04", w[2]+" "+w[3], false)
			ok = err == nil
		}
		if len(w) == 7 && w[0] == "absolute" && w[1] == "start" && w[4] == "end" {
			if absolute {
				r.Unsupported = append(r.Unsupported, "repeated absolute schedule")
			}
			absolute = true
			for _, layout := range []string{"01/02/2006 15:04", "01/02/2006 15:04:05"} {
				window, zone, err := s.ScheduleWindow(layout, w[2]+" "+w[3], w[5]+" "+w[6])
				if err == nil {
					r.Windows = append(r.Windows, window)
					r.Timezone = zone
					ok = true
					break
				}
			}
			if !ok {
				r.Unsupported = append(r.Unsupported, "native schedule clock or window not established")
			}
		}
		if len(w) > 1 && w[0] == "periodic" {
			windows, zone, err := schedule.Periodic(s, w[1:])
			if err == nil {
				schedule.AddWeekly(&r, windows, zone)
				ok = true
			}
		}
		return ok
	}); err != nil {
		return err
	}
	schedule.Restrict(&r)
	if !openStart.IsZero() {
		if len(r.Weekly) > 0 {
			r.Weekly[0].Start = openStart
		} else {
			r.Unsupported = append(r.Unsupported, "unbounded absolute schedule")
		}
	}
	if len(r.Windows) == 0 && len(r.Weekly) == 0 {
		r.Unsupported = append(r.Unsupported, "native schedule clock or window not established")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	tx.Emit(fm.Data{Schedules: []fm.ScheduleRecord{r}})
	return s.Commit(tx)
}
