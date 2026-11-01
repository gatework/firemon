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
	for _, s := range []fm.ScheduleRecord{{Windows: make([]fm.TimeWindow, 1000)}, {Recurring: make([]string, 1000)}} {
		err := plan.PreflightNativeRequests(t.Context(), []plan.NativeRequest{{Additions: plan.NativeAdditions{Schedules: []fm.ScheduleRecord{s}}}}, policy.Limits{MaxVisits: 10})
		if !errors.Is(err, policy.ErrBudget) {
			t.Fatal(err)
		}
	}
}
