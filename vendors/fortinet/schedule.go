package fortinet

import (
	"context"
	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
)

func (p *parser) schedules(ctx context.Context, s *config.Builder) error {
	tx := s.Begin()
	defer tx.Rollback()
	var d fm.Data
	if err := p.each(ctx, tx, "firewall schedule onetime", func(b *config.Block) {
		name := b.Header.Words[1]
		r := fm.ScheduleRecord{Object: object(name, name, "")}
		f := readFields(tx, b, &r.Object)
		start, end := f.list("start"), f.list("end")
		if len(start) == 2 && len(end) == 2 {
			w, zone, err := s.ScheduleWindow("15:04 2006/01/02", start[0]+" "+start[1], end[0]+" "+end[1])
			if err == nil {
				r.Windows = []fm.TimeWindow{w}
				r.Timezone = zone
			} else {
				f.invalid("schedule clock or window")
			}
		} else {
			f.invalid("one-time endpoints")
		}
		f.finish()
		d.Schedules = append(d.Schedules, r)
	}); err != nil {
		return err
	}
	return p.commit(s, tx, d)
}
