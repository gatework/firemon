package firemon_test

import (
	"slices"
	"testing"
	"time"

	fm "github.com/gatework/firemon"
)

func calendarGraph(t *testing.T, record fm.ScheduleRecord) *fm.Firewall {
	t.Helper()
	record.ID = "schedule"
	fw, err := fm.Seal(fm.Data{Metadata: fm.Metadata{Device: "synthetic", Vendor: "asa"}, Schedules: []fm.ScheduleRecord{record}})
	if err != nil {
		t.Fatal(err)
	}
	return fw
}

func TestScheduleCombinesAbsoluteUnionAndBoundedWeeklyIntersection(t *testing.T) {
	monday := time.Date(2026, 11, 9, 0, 0, 0, 0, time.UTC)
	r := fm.ScheduleRecord{Timezone: "UTC", Calendar: fm.CalendarCivil,
		Windows: []fm.TimeWindow{{Start: monday.Add(25 * time.Hour), End: monday.Add(26 * time.Hour)}},
		Weekly: []fm.WeeklyPeriod{{Start: monday.Add(10 * time.Hour), End: monday.Add(12 * time.Hour),
			Windows: []fm.WeeklyWindow{{Day: time.Monday, Start: 9 * time.Hour, End: 17 * time.Hour}}}},
	}
	s := calendarGraph(t, r).Schedule("schedule")
	for _, tc := range []struct {
		offset time.Duration
		active bool
	}{{8 * time.Hour, false}, {10 * time.Hour, true}, {12*time.Hour - time.Nanosecond, true}, {12 * time.Hour, false}, {25 * time.Hour, true}, {26 * time.Hour, false}, {7*24*time.Hour + 11*time.Hour, false}} {
		if active, known := s.ActiveAt(monday.Add(tc.offset)); !known || active != tc.active {
			t.Fatalf("offset %v: active=%v known=%v", tc.offset, active, known)
		}
	}
	for _, tc := range []struct {
		offset  time.Duration
		expired bool
	}{{-time.Hour, false}, {13 * time.Hour, false}, {26 * time.Hour, true}} {
		if expired, known := s.ExpiredAt(monday.Add(tc.offset)); !known || expired != tc.expired {
			t.Fatalf("offset %v: expired=%v known=%v", tc.offset, expired, known)
		}
	}
}

func TestWeeklyClockNormalizesCrossMidnightAndNativeEndpoints(t *testing.T) {
	clock := fm.ScheduleClock{Timezone: "UTC", Reference: "synthetic clock", EndBoundary: "exclusive", TickSeconds: 60, Calendar: fm.CalendarCivil}
	windows, err := clock.ParseWeekly([]time.Weekday{time.Saturday}, "23:00", "01:00")
	want := []fm.WeeklyWindow{{Day: time.Sunday, End: time.Hour}, {Day: time.Saturday, Start: 23 * time.Hour, End: 24 * time.Hour}}
	if err != nil || !slices.Equal(windows, want) {
		t.Fatal(windows, err)
	}
	s := calendarGraph(t, fm.ScheduleRecord{Timezone: "UTC", Calendar: fm.CalendarCivil, Weekly: []fm.WeeklyPeriod{{Windows: windows}}}).Schedule("schedule")
	for _, tc := range []struct {
		at     string
		active bool
	}{{"2026-11-07T22:59:59Z", false}, {"2026-11-07T23:00:00Z", true}, {"2026-11-08T00:00:00Z", true}, {"2026-11-08T01:00:00Z", false}} {
		at, _ := time.Parse(time.RFC3339, tc.at)
		if active, known := s.ActiveAt(at); !known || active != tc.active {
			t.Fatalf("%s: active=%v known=%v", tc.at, active, known)
		}
	}
	clock.EndBoundary = "inclusive"
	full, err := clock.ParseWeekly([]time.Weekday{time.Monday}, "00:00", "23:59")
	if err != nil || len(full) != 1 || full[0].End != 24*time.Hour {
		t.Fatal(full, err)
	}
	a, b, err := clock.NativeWeekly(full[0], time.Minute)
	if err != nil || a != 0 || b != 23*time.Hour+59*time.Minute {
		t.Fatal(a, b, err)
	}
	span, err := clock.ParseWeeklySpan(time.Friday, time.Monday, "20:00", "08:00")
	if err != nil || len(span) != 4 || span[0].Day != time.Sunday || span[1].Day != time.Monday || span[1].End != 8*time.Hour+time.Minute {
		t.Fatal(span, err)
	}
}

func TestCivilRecurringDSTAndUnknownCalendar(t *testing.T) {
	r := fm.ScheduleRecord{Timezone: "America/New_York", Calendar: fm.CalendarCivil, Weekly: []fm.WeeklyPeriod{{Windows: []fm.WeeklyWindow{{Day: time.Sunday, Start: time.Hour, End: 2 * time.Hour}, {Day: time.Sunday, Start: 2*time.Hour + 15*time.Minute, End: 2*time.Hour + 45*time.Minute}}}}}
	s := calendarGraph(t, r).Schedule("schedule")
	for _, stamp := range []string{"2026-11-01T05:30:00Z", "2026-11-01T06:30:00Z"} {
		at, _ := time.Parse(time.RFC3339, stamp)
		if active, known := s.ActiveAt(at); !known || !active {
			t.Fatalf("fold %s: %v %v", stamp, active, known)
		}
	}
	gap := time.Date(2026, 3, 8, 7, 30, 0, 0, time.UTC)
	if active, known := s.ActiveAt(gap); !known || active {
		t.Fatal("gap was silently shifted", active, known)
	}
	if expired, known := s.ExpiredAt(gap.AddDate(100, 0, 0)); !known || expired {
		t.Fatal("unbounded recurrence expired", expired, known)
	}
	r.Calendar = fm.CalendarUnknown
	fw := calendarGraph(t, r)
	if fw.Complete() {
		t.Fatal("unobserved civil-calendar semantics marked complete")
	}
	if active, known := fw.Schedule("schedule").ActiveAt(gap); !active || known {
		t.Fatal("unknown DST behavior widened or disappeared", active, known)
	}
	clock := fm.ScheduleClock{Timezone: r.Timezone, Reference: "clock without recurrence evidence", EndBoundary: "exclusive", TickSeconds: 60}
	if _, err := clock.ParseWeekly([]time.Weekday{time.Sunday}, "01:00", "02:00"); err == nil {
		t.Fatal("clock without calendar evidence admitted recurrence")
	}
}

func TestWeeklyStorageIsImmutableAndNormalizesEquivalentDeclarations(t *testing.T) {
	first := fm.WeeklyWindow{Day: time.Monday, Start: 9 * time.Hour, End: 12 * time.Hour}
	second := fm.WeeklyWindow{Day: time.Monday, Start: 12 * time.Hour, End: 17 * time.Hour}
	r := fm.ScheduleRecord{Timezone: "UTC", Calendar: fm.CalendarCivil, Weekly: []fm.WeeklyPeriod{{Windows: []fm.WeeklyWindow{second}}, {Windows: []fm.WeeklyWindow{first}}}}
	fw := calendarGraph(t, r)
	s := fw.Schedule("schedule")
	r.Weekly[0].Windows[0].End = time.Hour
	record := s.Record()
	if len(record.Weekly) != 1 || len(record.Weekly[0].Windows) != 1 || record.Weekly[0].Windows[0].End != 17*time.Hour {
		t.Fatal("weekly union was not normalized", record)
	}
	record.Weekly[0].Windows[0].End = time.Hour
	for period := range s.Weekly() {
		period.Windows[0].End = time.Hour
		break
	}
	exported := fw.Export()
	exported.Schedules[0].Weekly[0].Windows[0].End = time.Hour
	if s.Record().Weekly[0].Windows[0].End != 17*time.Hour || s.WeeklyCount() != 1 || s.WeeklyWindowCount() != 1 {
		t.Fatal("nested mutable storage escaped")
	}
	canonical := fm.ScheduleRecord{Timezone: "UTC", Calendar: fm.CalendarCivil, Weekly: []fm.WeeklyPeriod{{Windows: []fm.WeeklyWindow{{Day: time.Monday, Start: 9 * time.Hour, End: 17 * time.Hour}}}}}
	if fw.SemanticDigest() != calendarGraph(t, canonical).SemanticDigest() {
		t.Fatal("equivalent weekly declarations have different semantic identities")
	}
}

func TestScheduleRejectsMalformedWeeklyIntervals(t *testing.T) {
	for _, w := range []fm.WeeklyWindow{{Day: 7, End: time.Hour}, {Day: time.Monday, Start: -1, End: time.Hour}, {Day: time.Monday, Start: time.Hour, End: time.Hour}, {Day: time.Monday, End: 25 * time.Hour}} {
		_, err := fm.Seal(fm.Data{Metadata: fm.Metadata{Device: "synthetic", Vendor: "asa"}, Schedules: []fm.ScheduleRecord{{Object: fm.Object{ID: "s"}, Timezone: "UTC", Calendar: fm.CalendarCivil, Weekly: []fm.WeeklyPeriod{{Windows: []fm.WeeklyWindow{w}}}}}})
		if err == nil {
			t.Fatal("malformed window accepted", w)
		}
	}
}
