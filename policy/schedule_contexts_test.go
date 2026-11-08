package policy_test

import (
	"context"
	"errors"
	"testing"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/policy"
)

func recurringGraph(t *testing.T, records ...fm.ScheduleRecord) *fm.Firewall {
	t.Helper()
	fw, err := fm.Seal(fm.Data{Metadata: fm.Metadata{Device: "synthetic", Vendor: "asa"}, Schedules: records})
	if err != nil || !fw.Complete() {
		t.Fatalf("invalid fixture: %v, %v", err, fw)
	}
	return fw
}

func TestContextsCoverEveryReachableCivilPhaseAcrossDST(t *testing.T) {
	from := time.Date(2026, 3, 8, 6, 0, 0, 0, time.UTC)
	end := from.Add(3 * time.Hour)
	gapWindow := fm.WeeklyWindow{Day: time.Sunday, Start: 2*time.Hour + 15*time.Minute, End: 2*time.Hour + 45*time.Minute}
	r := fm.ScheduleRecord{Object: fm.Object{ID: "weekly"}, Timezone: "America/New_York", Calendar: fm.CalendarCivil, Weekly: []fm.WeeklyPeriod{{Windows: []fm.WeeklyWindow{gapWindow}}}}
	bounded := r
	bounded.ID = "bounded"
	bounded.Weekly = []fm.WeeklyPeriod{{End: end, Windows: []fm.WeeklyWindow{gapWindow}}}
	fw := recurringGraph(t, r, bounded)
	contexts, err := (policy.Engine{}).Contexts(t.Context(), from, fw)
	if err != nil {
		t.Fatal(err)
	}
	activeFound := false
	for _, q := range contexts {
		if q.At.Before(from) {
			t.Fatal("proof included a time before its boundary", q.At)
		}
		active, known := fw.Schedule("weekly").ActiveAt(q.At)
		if !known {
			t.Fatal("lost calendar evidence")
		}
		if active {
			activeFound = true
			if q.At.Before(from.AddDate(0, 0, 7)) {
				t.Fatal("nonexistent first-week wall time was invented", q.At)
			}
		}
		if active, _ := fw.Schedule("bounded").ActiveAt(q.At); active {
			t.Fatal("short DST gap interval acquired an unreachable phase", q.At)
		}
	}
	if !activeFound {
		t.Fatal("fixed-date sampling missed a future recurring phase")
	}
	// NAT admission must use the same complete temporal representatives.
	native, err := (policy.Engine{}).NATContexts(t.Context(), from, fw)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range contexts {
		found := false
		for _, n := range native {
			found = found || n.At.Equal(q.At)
		}
		if !found {
			t.Fatal("NAT proof dropped a recurring context", q.At)
		}
	}
}

func TestContextsPartitionFarFutureDateBoundsAndAbsoluteUnion(t *testing.T) {
	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	start := time.Date(2084, 5, 1, 0, 0, 0, 0, time.UTC)
	end := start.AddDate(0, 0, 30)
	r := fm.ScheduleRecord{Object: fm.Object{ID: "bounded"}, Timezone: "UTC", Calendar: fm.CalendarCivil,
		Windows: []fm.TimeWindow{{Start: end.Add(time.Hour), End: end.Add(2 * time.Hour)}},
		Weekly:  []fm.WeeklyPeriod{{Start: start, End: end, Windows: []fm.WeeklyWindow{{Day: time.Monday, Start: 9 * time.Hour, End: 10 * time.Hour}}}},
	}
	fw := recurringGraph(t, r)
	contexts, err := (policy.Engine{}).Contexts(t.Context(), from, fw)
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, q := range contexts {
		active, _ := fw.Schedule("bounded").ActiveAt(q.At)
		switch {
		case q.At.Before(start):
			if active {
				t.Fatal("weekly bound widened before start")
			}
			found["before"] = true
		case q.At.Before(end):
			if active {
				found["weekly"] = true
			} else {
				found["weekly-gap"] = true
			}
		case active:
			found["absolute"] = true
		default:
			found["after"] = true
		}
	}
	for _, key := range []string{"before", "weekly", "weekly-gap", "absolute", "after"} {
		if !found[key] {
			t.Fatal("future temporal partition missing", key)
		}
	}
}

func TestContextsRejectUnprovableCalendarsAndBoundWork(t *testing.T) {
	from := time.Date(2026, 11, 7, 0, 0, 0, 0, time.UTC)
	r := fm.ScheduleRecord{Object: fm.Object{ID: "weekly"}, Timezone: "UTC", Calendar: fm.CalendarCivil, Weekly: []fm.WeeklyPeriod{{Windows: []fm.WeeklyWindow{{Day: time.Monday, Start: 9 * time.Hour, End: 17 * time.Hour}}}}}
	fw := recurringGraph(t, r)
	other := r
	other.ID, other.Timezone = "different-zone", "America/New_York"
	if rows, err := (policy.Engine{}).Contexts(t.Context(), from, fw, recurringGraph(t, other)); rows != nil || !errors.Is(err, policy.ErrNotEquivalent) {
		t.Fatal("cross-timezone sampling endorsed a proof", rows, err)
	}
	for _, limits := range []policy.Limits{{MaxVisits: 2}, {MaxCombinations: 2}} {
		if rows, err := (policy.Engine{Limits: limits}).Contexts(t.Context(), from, fw); rows != nil || !errors.Is(err, policy.ErrBudget) {
			t.Fatal("recurring proof escaped budget", rows, err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if rows, err := (policy.Engine{}).Contexts(ctx, from, fw); rows != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("canceled recurring expansion returned success", rows, err)
	}
}

func TestWeeklyEquivalenceChecksRecurringFirstMatchOutcomes(t *testing.T) {
	from := time.Date(2026, 11, 7, 0, 0, 0, 0, time.UTC)
	a := fm.ScheduleRecord{Object: fm.Object{ID: "morning"}, Timezone: "UTC", Calendar: fm.CalendarCivil, Weekly: []fm.WeeklyPeriod{{Windows: []fm.WeeklyWindow{{Day: time.Monday, Start: 9 * time.Hour, End: 10 * time.Hour}}}}}
	b := a
	b.ID = "afternoon"
	b.Weekly = []fm.WeeklyPeriod{{Windows: []fm.WeeklyWindow{{Day: time.Monday, Start: 13 * time.Hour, End: 14 * time.Hour}}}}
	data := recurringGraph(t, a, b).Export()
	match := anyMatch()
	match.Schedule = a.ID
	data.Rules = []fm.RuleRecord{{Object: fm.Object{ID: "permit"}, RuleSet: "security", Match: match, Action: fm.Permit}}
	before, err := fm.Seal(data)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (policy.Engine{}).Equivalent(t.Context(), before, before, from); err != nil {
		t.Fatal("identical recurring policy was not proved", err)
	}
	data.Rules[0].Match.Schedule = b.ID
	after, err := fm.Seal(data)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (policy.Engine{}).Equivalent(t.Context(), before, after, from); !errors.Is(err, policy.ErrNotEquivalent) {
		t.Fatal("different weekly admission was treated as equivalent", err)
	}
}
