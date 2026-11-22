package firemon

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// ErrScheduleProof reports that the instants a proof needs cannot be
// enumerated: the requested schedule is unknown, unmodelled, never active
// again, or the enumeration exceeds its bound.
var ErrScheduleProof = errors.New("firemon: schedule cannot be proved")

// maxPolicyInstants bounds the candidate instants PolicyTimes examines.
const maxPolicyInstants = 1 << 17

// recurrencePeriod is how long weekly recurrences take to produce every
// combination: one week, plus a day for intervals that wrap past midnight.
const recurrencePeriod = 8 * 24 * time.Hour

// PolicyTimes returns instants, from at on, that together take every
// combination of activity the timed rules will have from at on: evaluating
// the policy at each of them covers every future instant. With schedule
// set, only instants at which that named schedule of fw is active count,
// and at least one must exist. The first instant is the earliest.
//
// The rules may belong to other firewalls (a proof compares two
// configurations): each is read through its own schedule, validity window
// and time zone. Rules whose schedule the compiler could not model are
// undecidable at every instant and do not split time.
func (fw *Firewall) PolicyTimes(at time.Time, schedule string, timed []*Rule) ([]time.Time, error) {
	loc := cmpLoc(fw.loc)
	var want *Schedule
	if schedule != "" {
		i := slices.IndexFunc(fw.cfg.Schedules, func(s Schedule) bool { return s.Name == schedule })
		if i < 0 {
			return nil, fmt.Errorf("%w: schedule %q is not defined", ErrScheduleProof, schedule)
		}
		if s := fw.cfg.Schedules[i]; s.Unsupported != "" {
			return nil, fmt.Errorf("%w: schedule %q: %s", ErrScheduleProof, schedule, s.Unsupported)
		}
		want = &fw.cfg.Schedules[i]
	}
	candidates, err := policyBoundaries(at, loc, want, timed)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []time.Time
	var sig strings.Builder
	for _, t := range candidates {
		if want != nil && !want.ActiveAt(t.In(loc)) {
			continue
		}
		sig.Reset()
		for _, r := range timed {
			if r.ActiveAt(t) {
				sig.WriteByte('1')
			} else {
				sig.WriteByte('0')
			}
		}
		if key := sig.String(); !seen[key] {
			seen[key] = true
			out = append(out, t)
		}
	}
	if want != nil && len(out) == 0 {
		return nil, fmt.Errorf("%w: schedule %q is not active again after %s", ErrScheduleProof, schedule, at.Format(time.RFC3339))
	}
	return out, nil
}

// timeSource is one schedule or validity window and the zone it is read in.
type timeSource struct {
	loc      *time.Location
	windows  []TimeWindow
	schedule *Schedule
}

// timeSources returns the schedules and windows that decide activity: the
// requested schedule and each timed rule's own. Unmodelled schedules are
// undecidable at every instant and contribute no boundary.
func timeSources(loc *time.Location, want *Schedule, timed []*Rule) []timeSource {
	var out []timeSource
	if want != nil {
		out = append(out, timeSource{loc: loc, schedule: want})
	}
	for _, r := range timed {
		src := timeSource{loc: cmpLoc(r.loc), schedule: r.schedule}
		if r.spec.Window != (TimeWindow{}) {
			src.windows = []TimeWindow{r.spec.Window}
		}
		if src.schedule != nil {
			if src.schedule.Unsupported != "" {
				src.schedule = nil
			} else {
				src.windows = append(src.windows, src.schedule.Windows...)
			}
		}
		out = append(out, src)
	}
	return out
}

// instants collects candidate instants after a start, within a bound.
type instants struct {
	after time.Time
	out   []time.Time
}

func (in *instants) add(t time.Time) error {
	if !t.After(in.after) {
		return nil
	}
	if len(in.out) >= maxPolicyInstants {
		return fmt.Errorf("%w: more than %d candidate instants", ErrScheduleProof, maxPolicyInstants)
	}
	in.out = append(in.out, t)
	return nil
}

// policyBoundaries returns at and every later instant at which a schedule
// or window involved may change state, sorted and without duplicates.
// Activity is constant between consecutive boundaries, so they are the
// only instants worth evaluating.
func policyBoundaries(at time.Time, loc *time.Location, want *Schedule, timed []*Rule) ([]time.Time, error) {
	sources := timeSources(loc, want, timed)
	in := &instants{after: at, out: []time.Time{at}}
	// Absolute window edges split time into segments in which only the
	// weekly recurrences change; one period after the start of each
	// segment repeats every combination the segment can hold.
	anchors := []time.Time{at}
	for _, src := range sources {
		for _, w := range src.windows {
			for _, t := range []time.Time{w.Start, w.End} {
				if t.IsZero() || !t.After(at) {
					continue
				}
				if err := in.add(t); err != nil {
					return nil, err
				}
				anchors = append(anchors, t)
			}
		}
	}
	for _, src := range sources {
		if src.schedule == nil || len(src.schedule.Recurrences) == 0 {
			continue
		}
		for _, anchor := range anchors {
			if err := in.recurrences(src, anchor); err != nil {
				return nil, err
			}
		}
	}
	slices.SortFunc(in.out, func(a, b time.Time) int { return a.Compare(b) })
	return slices.CompactFunc(in.out, func(a, b time.Time) bool { return a.Equal(b) }), nil
}

// recurrences adds the midnights and recurrence edges of src for one
// period from anchor, starting the day before: an interval that wraps past
// midnight may have begun yesterday.
func (in *instants) recurrences(src timeSource, anchor time.Time) error {
	local := anchor.In(src.loc)
	end := anchor.Add(recurrencePeriod)
	for day := time.Date(local.Year(), local.Month(), local.Day()-1, 0, 0, 0, 0, src.loc); !day.After(end); day = time.Date(day.Year(), day.Month(), day.Day()+1, 0, 0, 0, 0, src.loc) {
		if err := in.add(day); err != nil {
			return err
		}
		for _, rec := range src.schedule.Recurrences {
			for _, off := range []time.Duration{rec.Start, rec.End} {
				if err := in.add(wallClock(day, off)); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// cmpLoc is loc, or UTC when nil.
func cmpLoc(loc *time.Location) *time.Location {
	if loc == nil {
		return time.UTC
	}
	return loc
}

// wallClock returns the instant at offset past midnight of day by the wall
// clock of day's zone, so that daylight saving days keep the time of day.
func wallClock(day time.Time, offset time.Duration) time.Time {
	h := int(offset / time.Hour)
	m := int(offset % time.Hour / time.Minute)
	s := int(offset % time.Minute / time.Second)
	return time.Date(day.Year(), day.Month(), day.Day(), h, m, s, 0, day.Location())
}
