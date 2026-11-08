package paloalto

import (
	"strings"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/vendors/internal/schedule"
)

func parseSchedule(s *config.Builder, r *fm.ScheduleRecord, words []string) error {
	if len(words) < 2 {
		return fm.ErrScheduleTime
	}
	switch words[0] {
	case "non-recurring":
		if len(r.Weekly) > 0 {
			return fm.ErrScheduleTime
		}
		var windows []fm.TimeWindow
		zone := ""
		for _, value := range words[1:] {
			a, b, ok := strings.Cut(value, "-")
			if !ok {
				return fm.ErrScheduleTime
			}
			w, z, err := s.ScheduleWindow("2006/01/02@15:04", a, b)
			if err != nil {
				return err
			}
			windows = append(windows, w)
			zone = z
		}
		r.Windows = append(r.Windows, windows...)
		r.Timezone = zone
		return nil
	case "recurring":
		if len(r.Windows) > 0 || len(words) < 3 {
			return fm.ErrScheduleTime
		}
		days := schedule.EveryDay()
		values := words[2:]
		switch words[1] {
		case "daily":
		case "weekly":
			if len(words) < 4 {
				return fm.ErrScheduleTime
			}
			var err error
			days, err = schedule.Days(words[2:3], nil)
			if err != nil {
				return err
			}
			values = words[3:]
		default:
			return fm.ErrScheduleTime
		}
		var windows []fm.WeeklyWindow
		zone := ""
		for _, value := range values {
			a, b, ok := strings.Cut(value, "-")
			if !ok {
				return fm.ErrScheduleTime
			}
			w, z, err := schedule.SameDay(s, days, a, b)
			if err != nil {
				return err
			}
			windows = append(windows, w...)
			zone = z
		}
		schedule.AddWeekly(r, windows, zone)
		return nil
	}
	return fm.ErrScheduleTime
}
