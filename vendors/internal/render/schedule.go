package render

import (
	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/plan"
	"strconv"
	"strings"
	"time"
)

// ScheduleCommands emits the conservative minute-aligned creation subset. The
// caller supplies verified endpoint semantics; these syntax/version gates alone
// do not establish a clock or a device's endpoint behavior.
func ScheduleCommands(before, after *fm.Firewall, c plan.NativeChanges) ([]string, error) {
	if c.Clock == nil {
		if len(c.Additions.Schedules) > 0 {
			return nil, plan.ErrRender
		}
		return nil, nil
	}
	if err := c.Clock.Validate(before.Metadata()); err != nil {
		return nil, err
	}
	m := before.Metadata()
	version := strings.TrimPrefix(m.Software, "StoneOS ")
	supported := m.Vendor == "hillstone" && (version == "5.5R8" || strings.HasPrefix(version, "5.5R8P")) || m.Vendor == "fortinet" && strings.HasPrefix(m.Software, "7.2.") || m.Vendor == "huawei" && strings.HasPrefix(m.Software, "V500R005") || m.Vendor == "netscreen" && strings.HasPrefix(m.Software, "6.3.")
	if !supported {
		return nil, plan.ErrRender
	}
	var out []string
	for _, r := range c.Additions.Schedules {
		name, e := Token(r.Name)
		if e != nil || len(name) > 31 || r.ID != fm.ID(name) || r.Scope != "" || !PlainObject(r.Object) || len(r.Windows) != 1 || len(r.Recurring) != 0 || r.Timezone != c.Clock.Timezone {
			return nil, plan.ErrRender
		}
		start, end, e := c.Clock.NativeWindow(r.Windows[0], time.Minute)
		if e != nil || end.Sub(start) < time.Minute {
			return nil, plan.ErrRender
		}
		switch m.Vendor {
		case "hillstone":
			out = append(out, "schedule "+strconv.Quote(name), "absolute start "+start.Format("01/02/2006 15:04")+" end "+end.Format("01/02/2006 15:04"), "exit")
		case "fortinet":
			out = append(out, "config firewall schedule onetime", "edit "+strconv.Quote(name), "set start "+start.Format("15:04 2006/01/02"), "set end "+end.Format("15:04 2006/01/02"), "next", "end")
		case "huawei":
			out = append(out, "time-range "+name, "absolute-range "+start.Format("15:04:05 2006/01/02")+" to "+end.Format("15:04:05 2006/01/02"), "quit")
		case "netscreen":
			out = append(out, "set scheduler "+strconv.Quote(name)+" once start "+start.Format("1/2/2006 15:04")+" stop "+end.Format("1/2/2006 15:04"))
		}
	}
	return out, nil
}

func ScheduleReference(after *fm.Firewall, id fm.ID, native ...Native) (string, error) {
	if id == "" {
		return "", nil
	}
	if len(native) != 1 || native[0].Changes.Clock == nil {
		return "", plan.ErrRender
	}
	s := after.Schedule(id)
	if s == nil || s.HasUnsupported() || s.HasRecurrence() {
		return "", plan.ErrRender
	}
	r := s.Record()
	if r.Scope != "" || r.ID != fm.ID(r.Name) || r.Timezone != native[0].Changes.Clock.Timezone || len(r.Windows) != 1 {
		return "", plan.ErrRender
	}
	name, err := Token(r.Name)
	if err != nil || len(name) > 31 {
		return "", plan.ErrRender
	}
	return strconv.Quote(name), nil
}
