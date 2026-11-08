package policy_test

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/policy"
)

func calendarTime(t testing.TB, value string) time.Time {
	t.Helper()
	at, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		t.Fatal(err)
	}
	return at
}

func queryCalendar(t testing.TB, schedules ...fm.ScheduleRecord) *fm.Firewall {
	t.Helper()
	fw, err := fm.Seal(fm.Data{
		Metadata:  fm.Metadata{Device: "calendar", Vendor: "hillstone"},
		Schedules: schedules,
		Rules: []fm.RuleRecord{
			{Object: fm.Object{ID: "scheduled"}, RuleSet: "security", Action: fm.Deny,
				Match: fm.Match{Schedule: schedules[0].ID, AnySource: true, AnyDestination: true, AnyService: true, AnyFromZone: true, AnyToZone: true}},
			{Object: fm.Object{ID: "fallback"}, RuleSet: "security", Position: 1, Action: fm.Permit,
				Match: fm.Match{AnySource: true, AnyDestination: true, AnyService: true, AnyFromZone: true, AnyToZone: true}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return fw
}

func checkCalendar(t *testing.T, fw *fm.Firewall, start, end string, cuts []string) []fm.TimeWindow {
	t.Helper()
	span := fm.TimeWindow{Start: calendarTime(t, start), End: calendarTime(t, end)}
	windows, err := (policy.Engine{}).Windows(t.Context(), fw, span)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for i, w := range windows {
		if !w.Start.Before(w.End) || i > 0 && !windows[i-1].End.Equal(w.Start) {
			t.Fatal("noncontiguous or empty time partition", windows)
		}
		got = append(got, w.Start.Format(time.RFC3339Nano))
		for _, schedule := range fw.Schedules() {
			active, known := schedule.ActiveAt(w.Start)
			for _, at := range []time.Time{w.Start.Add(w.End.Sub(w.Start) / 2), w.End.Add(-time.Nanosecond)} {
				other, certain := schedule.ActiveAt(at)
				if active != other || known != certain {
					t.Fatalf("schedule %s changes inside %v: %v", schedule.ID(), w, at)
				}
			}
		}
	}
	if len(windows) == 0 || !windows[len(windows)-1].End.Equal(span.End) {
		t.Fatal("timeline dropped the final interval", windows)
	}
	got = append(got, windows[len(windows)-1].End.Format(time.RFC3339Nano))
	if !slices.Equal(got, cuts) {
		t.Fatalf("cuts = %v, want %v", got, cuts)
	}
	return windows
}

func TestWindowsPreserveAbsoluteAdmissionAndExpiry(t *testing.T) {
	start := calendarTime(t, "2026-11-09T00:00:00Z")
	fw := queryCalendar(t, fm.ScheduleRecord{Object: fm.Object{ID: "finite"}, Windows: []fm.TimeWindow{
		{Start: start.Add(time.Hour), End: start.Add(2 * time.Hour)},
		{Start: start.Add(3 * time.Hour), End: start.Add(4 * time.Hour)},
	}})
	windows := checkCalendar(t, fw, "2026-11-09T00:00:00Z", "2026-11-09T05:00:00Z", []string{
		"2026-11-09T00:00:00Z", "2026-11-09T01:00:00Z", "2026-11-09T02:00:00Z",
		"2026-11-09T03:00:00Z", "2026-11-09T04:00:00Z", "2026-11-09T05:00:00Z",
	})
	traffic, err := flow.AllTraffic(8)
	if err != nil {
		t.Fatal(err)
	}
	for i, w := range windows {
		result, err := (policy.Engine{}).Query(t.Context(), fw, policy.Request{Traffic: traffic, At: w.Start})
		if err != nil || !result.Complete || len(result.Decisions) != 1 {
			t.Fatal(result, err)
		}
		want := fm.Permit
		if i == 1 || i == 3 {
			want = fm.Deny
		}
		if result.Decisions[0].Action != want {
			t.Fatalf("interval %v: action %v, want %v", w, result.Decisions[0].Action, want)
		}
	}
}

func TestWindowsFollowActualDSTTransitions(t *testing.T) {
	for _, tc := range []struct {
		name, start, end string
		from, to         time.Duration
		cuts             []string
	}{
		{"gap", "2026-03-08T06:00:00Z", "2026-03-08T09:00:00Z", 2*time.Hour + 15*time.Minute, 2*time.Hour + 45*time.Minute,
			[]string{"2026-03-08T06:00:00Z", "2026-03-08T07:00:00Z", "2026-03-08T09:00:00Z"}},
		{"across gap", "2026-03-08T06:00:00Z", "2026-03-08T09:00:00Z", time.Hour + 30*time.Minute, 3*time.Hour + 30*time.Minute,
			[]string{"2026-03-08T06:00:00Z", "2026-03-08T06:30:00Z", "2026-03-08T07:00:00Z", "2026-03-08T07:30:00Z", "2026-03-08T09:00:00Z"}},
		{"fold", "2026-11-01T04:00:00Z", "2026-11-01T08:00:00Z", time.Hour + 15*time.Minute, time.Hour + 45*time.Minute,
			[]string{"2026-11-01T04:00:00Z", "2026-11-01T05:15:00Z", "2026-11-01T05:45:00Z", "2026-11-01T06:00:00Z", "2026-11-01T06:15:00Z", "2026-11-01T06:45:00Z", "2026-11-01T08:00:00Z"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fw := queryCalendar(t, fm.ScheduleRecord{Object: fm.Object{ID: "weekly"}, Timezone: "America/New_York", Calendar: fm.CalendarCivil,
				Weekly: []fm.WeeklyPeriod{{Windows: []fm.WeeklyWindow{{Day: time.Sunday, Start: tc.from, End: tc.to}}}}})
			checkCalendar(t, fw, tc.start, tc.end, tc.cuts)
		})
	}
}

func TestWindowsRespectPeriodBoundsMidnightAndTimezones(t *testing.T) {
	start := calendarTime(t, "2026-11-09T00:00:00Z")
	fw := queryCalendar(t,
		fm.ScheduleRecord{Object: fm.Object{ID: "hongkong", Scope: "east"}, Timezone: "Asia/Hong_Kong", Calendar: fm.CalendarCivil,
			Weekly: []fm.WeeklyPeriod{{Windows: []fm.WeeklyWindow{{Day: time.Monday, Start: 9 * time.Hour, End: 10 * time.Hour}}}}},
		fm.ScheduleRecord{Object: fm.Object{ID: "utc", Scope: "west"}, Timezone: "UTC", Calendar: fm.CalendarCivil,
			Weekly: []fm.WeeklyPeriod{{Start: start.Add(9*time.Hour + 15*time.Minute), End: start.Add(9*time.Hour + 45*time.Minute),
				Windows: []fm.WeeklyWindow{{Day: time.Monday, Start: 9 * time.Hour, End: 10 * time.Hour}}}}},
	)
	checkCalendar(t, fw, "2026-11-09T00:00:00Z", "2026-11-09T12:00:00Z", []string{
		"2026-11-09T00:00:00Z", "2026-11-09T01:00:00Z", "2026-11-09T02:00:00Z", "2026-11-09T09:15:00Z", "2026-11-09T09:45:00Z", "2026-11-09T12:00:00Z",
	})
	fw = queryCalendar(t, fm.ScheduleRecord{Object: fm.Object{ID: "midnight"}, Timezone: "UTC", Calendar: fm.CalendarCivil,
		Weekly: []fm.WeeklyPeriod{{Windows: []fm.WeeklyWindow{
			{Day: time.Saturday, Start: 23 * time.Hour, End: 24 * time.Hour},
			{Day: time.Sunday, End: time.Hour},
		}}}})
	checkCalendar(t, fw, "2026-11-07T22:00:00Z", "2026-11-08T02:00:00Z", []string{
		"2026-11-07T22:00:00Z", "2026-11-07T23:00:00Z", "2026-11-08T00:00:00Z", "2026-11-08T01:00:00Z", "2026-11-08T02:00:00Z",
	})
}

func TestWindowsKeepUnknownCalendarEvidence(t *testing.T) {
	start := calendarTime(t, "2026-11-09T00:00:00Z")
	fw := queryCalendar(t,
		fm.ScheduleRecord{Object: fm.Object{ID: "unknown"}, Weekly: []fm.WeeklyPeriod{{Windows: []fm.WeeklyWindow{{Day: time.Monday, End: time.Hour}}}}},
		fm.ScheduleRecord{Object: fm.Object{ID: "known"}, Windows: []fm.TimeWindow{{Start: start.Add(time.Hour), End: start.Add(2 * time.Hour)}}},
	)
	checkCalendar(t, fw, "2026-11-09T00:00:00Z", "2026-11-09T03:00:00Z", []string{
		"2026-11-09T00:00:00Z", "2026-11-09T01:00:00Z", "2026-11-09T02:00:00Z", "2026-11-09T03:00:00Z",
	})
	traffic, _ := flow.AllTraffic(8)
	result, err := (policy.Engine{}).Query(t.Context(), fw, policy.Request{Traffic: traffic, At: start})
	if err != nil || result.Unknown.Empty() || !result.Allowed.Empty() || result.Complete {
		t.Fatal("unknown calendar became an established decision", result, err)
	}
}

func TestWindowsIncludeNATOnlyScheduleTransitions(t *testing.T) {
	start := calendarTime(t, "2026-11-09T00:00:00Z")
	d := queryCalendar(t, fm.ScheduleRecord{Object: fm.Object{ID: "policy"}, Windows: []fm.TimeWindow{{Start: start.Add(time.Hour), End: start.Add(2 * time.Hour)}}}).Export()
	d.Schedules = append(d.Schedules, fm.ScheduleRecord{Object: fm.Object{ID: "nat"}, Windows: []fm.TimeWindow{{Start: start.Add(3 * time.Hour), End: start.Add(4 * time.Hour)}}})
	match := anyMatch()
	match.Schedule = "nat"
	d.StaticNATs = []fm.StaticNATRecord{{Object: fm.Object{ID: "mapping"}, Match: match,
		Source: []fm.Mapping{{Original: rangeOf("192.0.2.0/24"), Translated: rangeOf("203.0.113.0/24"), Mode: fm.Offset}}}}
	fw, err := fm.Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	windows := checkCalendar(t, fw, "2026-11-09T00:00:00Z", "2026-11-09T05:00:00Z", []string{
		"2026-11-09T00:00:00Z", "2026-11-09T01:00:00Z", "2026-11-09T02:00:00Z",
		"2026-11-09T03:00:00Z", "2026-11-09T04:00:00Z", "2026-11-09T05:00:00Z",
	})
	input := traffic(t, "192.0.2.10/32", "198.51.100.20/32")
	for i, w := range windows {
		result, err := (policy.Engine{}).QueryNAT(t.Context(), fw, policy.Request{Traffic: input, At: w.Start})
		if err != nil || !result.Complete || (len(result.Relations) != 0) != (i == 3) {
			t.Fatal("NAT admission changed outside its schedule", w, result, err)
		}
	}
}

func TestWindowsRetainEveryWeeklyOccurrence(t *testing.T) {
	fw := queryCalendar(t, fm.ScheduleRecord{Object: fm.Object{ID: "weekly"}, Timezone: "UTC", Calendar: fm.CalendarCivil,
		Weekly: []fm.WeeklyPeriod{{Windows: []fm.WeeklyWindow{{Day: time.Monday, Start: 9 * time.Hour, End: 10 * time.Hour}}}}})
	checkCalendar(t, fw, "2026-11-09T08:00:00Z", "2026-11-23T08:00:00Z", []string{
		"2026-11-09T08:00:00Z", "2026-11-09T09:00:00Z", "2026-11-09T10:00:00Z",
		"2026-11-16T09:00:00Z", "2026-11-16T10:00:00Z", "2026-11-23T08:00:00Z",
	})
	short := fm.TimeWindow{Start: calendarTime(t, "2026-11-09T06:00:00Z"), End: calendarTime(t, "2026-11-09T07:00:00Z")}
	windows, err := (policy.Engine{Limits: policy.Limits{MaxRegions: 1}}).Windows(t.Context(), fw, short)
	if err != nil || len(windows) != 1 || windows[0] != short {
		t.Fatal("unreachable weekly phases exhausted the output limit", windows, err)
	}
}

func TestWindowsCoverFutureTimezoneSegments(t *testing.T) {
	fw := queryCalendar(t, fm.ScheduleRecord{Object: fm.Object{ID: "future"}, Timezone: "America/New_York", Calendar: fm.CalendarCivil,
		Weekly: []fm.WeeklyPeriod{{Windows: []fm.WeeklyWindow{{Day: time.Sunday, Start: time.Hour + 15*time.Minute, End: 3*time.Hour + 45*time.Minute}}}}})
	span := fm.TimeWindow{Start: calendarTime(t, "2084-01-01T00:00:00Z"), End: calendarTime(t, "2085-01-01T00:00:00Z")}
	windows, err := (policy.Engine{}).Windows(t.Context(), fw, span)
	if err != nil {
		t.Fatal(err)
	}
	index := 0
	for at := span.Start; at.Before(span.End); at = at.Add(15 * time.Minute) {
		for index < len(windows) && !at.Before(windows[index].End) {
			index++
		}
		if index == len(windows) || at.Before(windows[index].Start) {
			t.Fatal("missing chronological coverage", at)
		}
		want, known := fw.Schedule("future").ActiveAt(at)
		got, certain := fw.Schedule("future").ActiveAt(windows[index].Start)
		if !known || !certain || got != want {
			t.Fatal("calendar phase changed inside a future interval", at, windows[index])
		}
	}
}

func TestContextsRemainCompleteAtFutureLeapYearEnd(t *testing.T) {
	fw := queryCalendar(t, fm.ScheduleRecord{Object: fm.Object{ID: "future"}, Timezone: "America/New_York", Calendar: fm.CalendarCivil,
		Weekly: []fm.WeeklyPeriod{{Windows: []fm.WeeklyWindow{{Day: time.Monday, Start: 9 * time.Hour, End: 10 * time.Hour}}}}})
	from := calendarTime(t, "2084-12-31T00:00:00Z")
	contexts, err := (policy.Engine{}).Contexts(t.Context(), from, fw)
	if err != nil {
		t.Fatal(err)
	}
	var foundActive, foundInactive bool
	for _, q := range contexts {
		active, known := fw.Schedule("future").ActiveAt(q.At)
		if !known || q.At.Before(from) {
			t.Fatal("invalid future context", q)
		}
		foundActive = foundActive || active
		foundInactive = foundInactive || !active
	}
	if !foundActive || !foundInactive {
		t.Fatal("future weekly outcomes were lost at year end", contexts)
	}
}

func TestWindowsBoundWorkAndReturnNoPartialTimeline(t *testing.T) {
	start := calendarTime(t, "2026-11-09T00:00:00Z")
	fw := queryCalendar(t, fm.ScheduleRecord{Object: fm.Object{ID: "weekly"}, Timezone: "UTC", Calendar: fm.CalendarCivil,
		Weekly: []fm.WeeklyPeriod{{Windows: []fm.WeeklyWindow{{Day: time.Monday, Start: 9 * time.Hour, End: 10 * time.Hour}}}}})
	span := fm.TimeWindow{Start: start, End: start.AddDate(100, 0, 0)}
	for _, limits := range []policy.Limits{{MaxRegions: 1}, {MaxCombinations: 1}, {MaxVisits: 1}, {MaxVisits: 100}} {
		windows, err := (policy.Engine{Limits: limits}).Windows(t.Context(), fw, span)
		if !errors.Is(err, policy.ErrBudget) || windows != nil {
			t.Fatal("expected bounded failure without partial timeline", limits, windows, err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if windows, err := (policy.Engine{}).Windows(ctx, nil, fm.TimeWindow{}); !errors.Is(err, context.Canceled) || windows != nil {
		t.Fatal(windows, err)
	}
	for _, invalid := range []fm.TimeWindow{{}, {Start: start, End: start}, {Start: start.Add(time.Hour), End: start}} {
		if windows, err := (policy.Engine{}).Windows(t.Context(), fw, invalid); !errors.Is(err, policy.ErrInvalid) || windows != nil {
			t.Fatal(windows, err)
		}
	}
}

func BenchmarkQueryWindows(b *testing.B) {
	fw := queryCalendar(b, fm.ScheduleRecord{Object: fm.Object{ID: "weekly"}, Timezone: "America/New_York", Calendar: fm.CalendarCivil,
		Weekly: []fm.WeeklyPeriod{{Windows: []fm.WeeklyWindow{{Day: time.Monday, Start: 9 * time.Hour, End: 17 * time.Hour}}}}})
	start := calendarTime(b, "2026-01-01T00:00:00Z")
	for _, tc := range []struct {
		name string
		days int
	}{{"week", 7}, {"month", 31}, {"year", 365}} {
		b.Run(tc.name, func(b *testing.B) {
			span := fm.TimeWindow{Start: start, End: start.AddDate(0, 0, tc.days)}
			b.ReportAllocs()
			for b.Loop() {
				windows, err := (policy.Engine{}).Windows(b.Context(), fw, span)
				if err != nil || len(windows) == 0 {
					b.Fatal(windows, err)
				}
			}
		})
	}
}
