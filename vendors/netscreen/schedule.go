package netscreen

import (
	"context"
	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
)

func (p *parser) schedules(ctx context.Context, s *config.Builder) error {
	tx := s.Begin()
	defer tx.Rollback()
	var schedules catalog[fm.ScheduleRecord]
	for _, line := range p.rows {
		if err := ctx.Err(); err != nil {
			return err
		}
		w := line.Words
		if line.scope != "root" || !begins(w, "set", "scheduler") || len(w) < 3 {
			continue
		}
		r := schedules.get(w[2])
		if r.ID != "" {
			r.Unsupported = append(r.Unsupported, "repeated scheduler declaration")
		}
		r.ID, r.Name = fm.ID(w[2]), w[2]
		ok := false
		if len(w) == 10 && w[3] == "once" && w[4] == "start" && w[7] == "stop" {
			window, zone, err := s.ScheduleWindow("1/2/2006 15:04", w[5]+" "+w[6], w[8]+" "+w[9])
			if err == nil {
				r.Windows = append(r.Windows, window)
				r.Timezone = zone
				ok = true
			}
		}
		if ok {
			touch(&r.Object, line)
			tx.Parse(line.Lines()...)
		} else {
			r.Unsupported = append(r.Unsupported, "native schedule clock or window not established")
		}
	}
	var d fm.Data
	for _, name := range schedules.names {
		d.Schedules = append(d.Schedules, *schedules.entries[name])
	}
	return p.commit(s, tx, d)
}
