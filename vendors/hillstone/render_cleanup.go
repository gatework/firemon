package hillstone

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/design"
)

// renderCleanup writes deletions, reductions and schedules. A deletion's
// rollback recreates what it removed, a rule in its former place.
func renderCleanup(ch design.Change) (do, undo []string, ok bool, err error) {
	ok = true
	switch c := ch.(type) {
	case design.DeleteRule:
		do = []string{"no rule id " + c.Rule.ID}
		undo, err = renderRule(design.AddRule{Rule: c.Rule, Before: c.Next})
	case design.DeleteAddress:
		do = []string{"no address " + q(c.Address.Name)}
		undo, err = renderAddress(c.Address)
	case design.DeleteAddressGroup:
		do = []string{"no address " + q(c.Group.Name)}
		undo, err = renderAddressBody(c.Group.Name, c.Group.Description, c.Group.Entries, c.Group.Members)
	case design.DeleteService:
		do = []string{"no service " + q(c.Service.Name)}
		undo, err = renderService(c.Service)
	case design.DeleteServiceGroup:
		do = []string{"no servgroup " + q(c.Group.Name)}
		undo = renderServiceGroup(c.Group)
	case design.DeleteSchedule:
		do = []string{"no schedule " + q(c.Schedule.Name)}
		undo, err = renderSchedule(c.Schedule)
	case design.AddSchedule:
		do, err = renderSchedule(c.Schedule)
		undo = []string{"no schedule " + q(c.Schedule.Name)}
	case design.ReduceRule:
		// Removing names is the inverse of extending with them.
		undo, do, err = renderExtend(design.ExtendRule(c))
	default:
		ok = false
	}
	return do, undo, ok, err
}

func renderServiceGroup(g firemon.ServiceGroup) []string {
	out := []string{"servgroup " + q(g.Name)}
	if g.Description != "" {
		out = append(out, "  description "+q(g.Description))
	}
	for _, m := range g.Members {
		out = append(out, "  service "+q(m))
	}
	return append(out, "exit")
}

// renderSchedule writes absolute windows and periodic recurrences. End
// times are inclusive to the second on StoneOS.
func renderSchedule(s firemon.Schedule) ([]string, error) {
	if s.Unsupported != "" {
		return nil, fmt.Errorf("hillstone: schedule %q has an unsupported period", s.Name)
	}
	out := []string{"schedule " + q(s.Name)}
	if s.Description != "" {
		out = append(out, "  description "+q(s.Description))
	}
	for _, w := range s.Windows {
		line := "  absolute"
		if !w.Start.IsZero() {
			line += " start " + stoneTime(w.Start)
		}
		out = append(out, line+" end "+stoneTime(w.End))
	}
	for _, r := range s.Recurrences {
		days := "daily"
		if len(r.Days) > 0 {
			names := make([]string, len(r.Days))
			for i, d := range slices.Sorted(slices.Values(r.Days)) {
				names[i] = strings.ToLower(d.String())
			}
			days = strings.Join(names, " ")
		}
		out = append(out, "  periodic "+days+" "+clockText(r.Start)+" to "+clockText(r.End-time.Second))
	}
	return append(out, "exit"), nil
}

func clockText(d time.Duration) string {
	h, m, sec := int(d/time.Hour), int(d%time.Hour/time.Minute), int(d%time.Minute/time.Second)
	return fmt.Sprintf("%02d:%02d:%02d", h, m, sec)
}
