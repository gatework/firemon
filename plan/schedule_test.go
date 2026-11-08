package plan_test

import (
	"errors"
	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/policy"
	"testing"
	"time"
)

func TestScheduleNameAndIngressBounds(t *testing.T) {
	w := fm.TimeWindow{Start: time.Date(2026, 10, 31, 1, 0, 0, 0, time.UTC), End: time.Date(2026, 10, 31, 2, 0, 0, 0, time.UTC)}
	a := plan.ScheduleName(w, "UTC")
	w.End = w.End.Add(time.Hour)
	b := plan.ScheduleName(w, "UTC")
	if a == b || len(a) > 31 || b != plan.ScheduleName(w, "UTC") || b == plan.ScheduleName(w, "Asia/Hong_Kong") {
		t.Fatal(a, b)
	}
	for _, s := range []fm.ScheduleRecord{{Windows: make([]fm.TimeWindow, 1000)}, {Weekly: make([]fm.WeeklyPeriod, 1000)}, {Weekly: []fm.WeeklyPeriod{{Windows: make([]fm.WeeklyWindow, 1000)}}}} {
		err := plan.PreflightNativeRequests(t.Context(), []plan.NativeRequest{{Additions: plan.NativeAdditions{Schedules: []fm.ScheduleRecord{s}}}}, policy.Limits{MaxVisits: 10})
		if !errors.Is(err, policy.ErrBudget) {
			t.Fatal(err)
		}
	}
}

func TestNativeChangesValidateGeneralTypedSchedulesWithoutFiniteLifetime(t *testing.T) {
	at := time.Date(2026, 11, 7, 0, 0, 0, 0, time.UTC)
	before, err := fm.Seal(fm.Data{Metadata: fm.Metadata{Device: "synthetic", Vendor: "asa", Software: "test", CapturedAt: at}, Raw: "synthetic capture"})
	if err != nil {
		t.Fatal(err)
	}
	metadata := before.Metadata()
	clock := fm.ScheduleClock{CapturedAt: at, Device: metadata.Device, Vendor: metadata.Vendor, Software: metadata.Software, SourceDigest: metadata.SourceDigest, Timezone: "UTC", Reference: "independent clock evidence", EndBoundary: "exclusive", TickSeconds: 60, Calendar: fm.CalendarCivil}
	schedule := fm.ScheduleRecord{Object: fm.Object{ID: "calendar", Name: "calendar"}, Timezone: "UTC", Calendar: fm.CalendarCivil,
		Windows: []fm.TimeWindow{{Start: at, End: at.Add(time.Hour)}, {Start: at.Add(2 * time.Hour), End: at.Add(3 * time.Hour)}},
		Weekly:  []fm.WeeklyPeriod{{Start: at.AddDate(0, 0, 1), Windows: []fm.WeeklyWindow{{Day: time.Monday, Start: 9 * time.Hour, End: 17 * time.Hour}}}},
	}
	rule := fm.RuleRecord{Object: fm.Object{ID: "scheduled", Name: "scheduled"}, RuleSet: "security", Action: fm.Permit, Match: fm.Match{AnySource: true, AnyDestination: true, AnyService: true, AnyFromZone: true, AnyToZone: true, Schedule: schedule.ID}}
	changes := plan.NativeChanges{Clock: &clock, Rules: []plan.Change{{Kind: plan.CreateRule, Rule: rule.ID}}, Additions: plan.NativeAdditions{Rules: []fm.RuleRecord{rule}, Schedules: []fm.ScheduleRecord{schedule}}}
	data := before.Export()
	data.Rules, data.Schedules = changes.Additions.Rules, changes.Additions.Schedules
	after, err := fm.Seal(data)
	if err != nil {
		t.Fatal(err)
	}
	if err := plan.ValidateNativeChanges(t.Context(), before, after, changes); err != nil {
		t.Fatal("typed calendar additions require no invented finite lifetime", err)
	}
	for _, mutate := range []func(*plan.NativeChanges){
		func(c *plan.NativeChanges) { c.Clock = nil },
		func(c *plan.NativeChanges) {
			changed := *c.Clock
			changed.Calendar = fm.CalendarUnknown
			c.Clock = &changed
		},
		func(c *plan.NativeChanges) { changed := *c.Clock; changed.SourceDigest = "wrong"; c.Clock = &changed },
		func(c *plan.NativeChanges) { c.Additions.Rules = nil; c.Rules = nil },
	} {
		invalid := changes
		mutate(&invalid)
		if err := plan.ValidateNativeChanges(t.Context(), before, after, invalid); err == nil {
			t.Fatal("unowned or unverified calendar addition was accepted")
		}
	}
}
