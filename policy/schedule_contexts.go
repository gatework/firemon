package policy

import (
	"slices"
	"sort"
	"time"

	fm "github.com/gatework/firemon"
)

const civilWeek = 7 * 24 * time.Hour

// schedulePartition separates absolute/date-bound transitions from recurring
// civil-week phases. Within each resulting cell, every schedule predicate is
// constant. All recurrences must share one civil timezone; a few sampled dates
// cannot establish equivalence between calendars with different transitions.
type schedulePartition struct {
	from     time.Time
	limit    int
	charge   func(int) error
	cuts     map[time.Time]struct{}
	phases   map[time.Duration]struct{}
	timezone string
	location *time.Location
}

func newSchedulePartition(from time.Time, limit int, charge func(int) error) *schedulePartition {
	from = from.UTC()
	return &schedulePartition{from: from, limit: limit, charge: charge, cuts: map[time.Time]struct{}{from: {}}}
}

func (p *schedulePartition) cut(at time.Time) error {
	if at.IsZero() || at.Before(p.from) {
		return nil
	}
	at = at.UTC()
	if _, ok := p.cuts[at]; !ok {
		if len(p.cuts) >= p.limit {
			return ErrBudget
		}
		p.cuts[at] = struct{}{}
	}
	return nil
}

func (p *schedulePartition) phase(at time.Duration) error {
	at %= civilWeek
	if _, ok := p.phases[at]; !ok {
		if len(p.phases) >= p.limit {
			return ErrBudget
		}
		p.phases[at] = struct{}{}
	}
	return nil
}

func (p *schedulePartition) add(s *fm.Schedule) error {
	if p.from.IsZero() {
		return ErrNotEquivalent
	}
	if s.HasUnsupported() {
		return ErrNotEquivalent
	}
	for w := range s.Windows() {
		if err := p.charge(1); err != nil {
			return err
		}
		if err := p.cut(w.Start); err != nil {
			return err
		}
		if err := p.cut(w.End); err != nil {
			return err
		}
	}
	if !s.HasRecurrence() {
		return nil
	}
	// Charge every nested interval before the immutable accessor copies it.
	for _, count := range []int{s.WeeklyCount(), s.WeeklyWindowCount()} {
		if err := p.charge(count); err != nil {
			return err
		}
	}
	if p.location == nil {
		p.timezone = s.Timezone()
		var err error
		p.location, err = time.LoadLocation(p.timezone)
		if err != nil {
			return ErrNotEquivalent
		}
		p.phases = map[time.Duration]struct{}{0: {}}
	} else if p.timezone != s.Timezone() {
		return ErrNotEquivalent
	}
	for period := range s.Weekly() {
		if err := p.cut(period.Start); err != nil {
			return err
		}
		if err := p.cut(period.End); err != nil {
			return err
		}
		for _, window := range period.Windows {
			day := time.Duration(window.Day) * 24 * time.Hour
			if err := p.phase(day + window.Start); err != nil {
				return err
			}
			if err := p.phase(day + window.End); err != nil {
				return err
			}
		}
	}
	return nil
}

func weeklyPhase(at time.Time) time.Duration {
	return time.Duration(at.Weekday())*24*time.Hour + time.Duration(at.Hour())*time.Hour + time.Duration(at.Minute())*time.Minute + time.Duration(at.Second())*time.Second + time.Duration(at.Nanosecond())
}

func (p *schedulePartition) times() ([]time.Time, error) {
	cuts := make([]time.Time, 0, len(p.cuts))
	for at := range p.cuts {
		cuts = append(cuts, at)
	}
	slices.SortFunc(cuts, time.Time.Compare)
	if p.location == nil {
		return cuts, nil
	}
	phases := make([]time.Duration, 0, len(p.phases))
	for phase := range p.phases {
		phases = append(phases, phase)
	}
	slices.Sort(phases)
	var out []time.Time
	for i, start := range cuts {
		var end time.Time
		if i+1 < len(cuts) {
			end = cuts[i+1]
		}
		rows, err := p.interval(start, end, phases, p.limit-len(out))
		if err != nil {
			return nil, err
		}
		out = append(out, rows...)
	}
	slices.SortFunc(out, time.Time.Compare)
	return out, nil
}

// interval visits actual UTC offset segments, not a fixed sample horizon. Inside
// one segment civil phase advances linearly; one week covers every phase cell.
// Once all cells have witnesses, further timezone transitions cannot introduce
// a new schedule outcome. A short bounded interval retains only reachable cells,
// including DST gaps, folds and non-hour offset changes.
func (p *schedulePartition) interval(start, end time.Time, phases []time.Duration, limit int) ([]time.Time, error) {
	seen := make([]bool, len(phases))
	left := len(phases)
	var out []time.Time
	add := func(at time.Time, cell int) error {
		if seen[cell] {
			return nil
		}
		if err := p.charge(1); err != nil {
			return err
		}
		if len(out) >= limit {
			return ErrBudget
		}
		seen[cell], left = true, left-1
		out = append(out, at.UTC())
		return nil
	}
	for at := start; end.IsZero() || at.Before(end); {
		if err := p.charge(1); err != nil {
			return nil, err
		}
		local := at.In(p.location)
		_, next := local.ZoneBounds()
		if !next.IsZero() && !next.After(at) {
			return nil, ErrNotEquivalent
		}
		if !end.IsZero() && (next.IsZero() || end.Before(next)) {
			next = end
		}
		phase := weeklyPhase(local)
		cell := sort.Search(len(phases), func(i int) bool { return phases[i] > phase }) - 1
		if err := add(at, cell); err != nil {
			return nil, err
		}
		for i, boundary := range phases {
			if err := p.charge(1); err != nil {
				return nil, err
			}
			distance := (boundary - phase + civilWeek) % civilWeek
			witness := at.Add(distance)
			if !next.IsZero() && !witness.Before(next) {
				continue
			}
			if err := add(witness, i); err != nil {
				return nil, err
			}
		}
		if left == 0 {
			return out, nil
		}
		if next.IsZero() {
			// An unbounded constant-offset segment necessarily covers every cell.
			return nil, ErrNotEquivalent
		}
		at = next
	}
	return out, nil
}
