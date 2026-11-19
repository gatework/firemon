package paloalto

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/design"
)

// renderCleanup writes deletions, reductions, schedules and static
// mappings. A deletion's rollback recreates what it removed, a rule in its
// former place.
func renderCleanup(ch design.Change) (do, undo []string, ok bool, err error) {
	ok = true
	switch c := ch.(type) {
	case design.DeleteRule:
		do = []string{"delete rulebase security rules " + name(c.Rule.ID)}
		undo, err = renderRule(design.AddRule{Rule: c.Rule, Before: c.Next})
	case design.DeleteAddress:
		do = []string{"delete address " + name(c.Address.Name)}
		undo, err = renderAddress(c.Address)
	case design.DeleteAddressGroup:
		do = []string{"delete address-group " + name(c.Group.Name)}
		undo, err = renderAddressGroup(c.Group)
	case design.DeleteService:
		do = []string{"delete service " + name(c.Service.Name)}
		undo, err = renderService(c.Service)
	case design.DeleteServiceGroup:
		do = []string{"delete service-group " + name(c.Group.Name)}
		undo = []string{"set service-group " + name(c.Group.Name) + " members " + bracket(c.Group.Members)}
	case design.DeleteSchedule:
		do = []string{"delete schedule " + name(c.Schedule.Name)}
		undo, err = renderSchedule(c.Schedule)
	case design.AddSchedule:
		do, err = renderSchedule(c.Schedule)
		undo = []string{"delete schedule " + name(c.Schedule.Name)}
	case design.ReduceRule:
		undo, do, err = renderExtend(design.ExtendRule(c))
	case design.AddStaticNAT:
		err = fmt.Errorf("paloalto: static NAT %s: PAN-OS writes it as a bi-directional static-ip NAT rule", c.Mapping.ID)
	default:
		ok = false
	}
	return do, undo, ok, err
}

func renderAddressGroup(g firemon.AddressGroup) ([]string, error) {
	switch {
	case len(g.Entries) > 0:
		return nil, fmt.Errorf("paloalto: address group %q has inline entries", g.Name)
	case g.Filter != "":
		return []string{"set address-group " + name(g.Name) + " dynamic filter " + quoteFilter(g.Filter)}, nil
	}
	return []string{"set address-group " + name(g.Name) + " static " + bracket(g.Members)}, nil
}

// quoteFilter quotes a dynamic group filter expression.
func quoteFilter(s string) string {
	if strings.ContainsAny(s, " '\"") {
		return "'" + strings.ReplaceAll(s, "'", "") + "'"
	}
	return s
}

// renderSchedule writes non-recurring windows or recurring daily/weekly
// periods. PAN-OS end times are inclusive to the minute; a schedule mixes
// no kinds, and weekly periods share one time list per day.
func renderSchedule(s firemon.Schedule) ([]string, error) {
	if s.Unsupported != "" {
		return nil, fmt.Errorf("paloalto: schedule %q has an unsupported period", s.Name)
	}
	p := "set schedule " + name(s.Name) + " schedule-type "
	switch {
	case len(s.Windows) > 0 && len(s.Recurrences) > 0:
		return nil, fmt.Errorf("paloalto: schedule %q mixes windows and recurrences", s.Name)
	case len(s.Windows) > 0:
		var ws []string
		for _, w := range s.Windows {
			if w.Start.IsZero() || w.End.IsZero() {
				return nil, fmt.Errorf("paloalto: schedule %q: a window needs a start and an end", s.Name)
			}
			ws = append(ws, w.Start.Format("2006/01/02@15:04")+"-"+w.End.Add(-time.Minute).Format("2006/01/02@15:04"))
		}
		return []string{p + "non-recurring " + bracket(ws)}, nil
	}
	var out []string
	daily := []string{}
	weekly := map[time.Weekday][]string{}
	for _, r := range s.Recurrences {
		if r.Start%time.Minute != 0 || r.End%time.Minute != 0 {
			return nil, fmt.Errorf("paloalto: schedule %q: periods are in minutes", s.Name)
		}
		span := hhmm(r.Start) + "-" + hhmm(r.End-time.Minute)
		if len(r.Days) == 0 {
			daily = append(daily, span)
			continue
		}
		for _, d := range r.Days {
			weekly[d] = append(weekly[d], span)
		}
	}
	if len(daily) > 0 && len(weekly) > 0 {
		return nil, fmt.Errorf("paloalto: schedule %q mixes daily and weekly periods", s.Name)
	}
	if len(daily) > 0 {
		return []string{p + "recurring daily " + bracket(daily)}, nil
	}
	for _, d := range slices.Sorted(maps.Keys(weekly)) {
		out = append(out, p+"recurring weekly "+strings.ToLower(d.String())+" "+bracket(weekly[d]))
	}
	return out, nil
}

func hhmm(d time.Duration) string {
	return fmt.Sprintf("%02d:%02d", int(d/time.Hour), int(d%time.Hour/time.Minute))
}
