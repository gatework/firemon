package firemon_test

import (
	"errors"
	"testing"
	"time"

	"github.com/gatework/firemon"
)

func timedFirewall(t *testing.T) *firemon.Firewall {
	t.Helper()
	cfg := sampleConfig()
	weekdays := []time.Weekday{time.Monday, time.Tuesday, time.Wednesday, time.Thursday, time.Friday}
	cfg.Schedules = append(cfg.Schedules,
		firemon.Schedule{Name: "work", Recurrences: []firemon.Recurrence{{Days: weekdays, Start: 9 * time.Hour, End: 18 * time.Hour}}},
		firemon.Schedule{Name: "night", Recurrences: []firemon.Recurrence{{Start: 22 * time.Hour, End: 6 * time.Hour}}},
		firemon.Schedule{Name: "odd", Unsupported: "monthly on the last weekday"},
	)
	cfg.Rules = append(cfg.Rules,
		firemon.SecurityRule{ID: "work", Schedule: "work", Action: firemon.ActionPermit},
		firemon.SecurityRule{ID: "night", Schedule: "night", Action: firemon.ActionDeny},
		firemon.SecurityRule{ID: "future", Action: firemon.ActionPermit,
			Window: firemon.TimeWindow{Start: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)}},
		firemon.SecurityRule{ID: "odd", Schedule: "odd", Action: firemon.ActionPermit},
	)
	fw, err := firemon.Compile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return fw
}

func rules(t *testing.T, fw *firemon.Firewall, ids ...string) []*firemon.Rule {
	t.Helper()
	out := make([]*firemon.Rule, len(ids))
	for i, id := range ids {
		r, ok := fw.Rule(id)
		if !ok {
			t.Fatalf("rule %s", id)
		}
		out[i] = r
	}
	return out
}

// states lists, for each instant, which rules are active.
func states(times []time.Time, rs []*firemon.Rule) map[string]bool {
	out := map[string]bool{}
	for _, at := range times {
		key := ""
		for _, r := range rs {
			if r.ActiveAt(at) {
				key += "1"
			} else {
				key += "0"
			}
		}
		out[key] = true
	}
	return out
}

func TestFirewall_PolicyTimes(t *testing.T) {
	t.Parallel()
	fw := timedFirewall(t)
	at := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC) // a Friday, inside working hours
	tests := []struct {
		name     string
		schedule string
		timed    []string
		want     []string // every activity combination, in rule order
	}{
		{"permanent policy needs one instant", "", nil, []string{""}},
		{"one schedule on and off", "", []string{"work"}, []string{"1", "0"}},
		{"disjoint schedules", "", []string{"work", "night"}, []string{"10", "00", "01"}},
		{"only during the requested schedule", "work", []string{"night"}, []string{"0"}},
		{"far validity window", "", []string{"future"}, []string{"0", "1"}},
		{"unmodelled schedule does not split time", "", []string{"odd"}, []string{"0"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rs := rules(t, fw, tt.timed...)
			times, err := fw.PolicyTimes(at, tt.schedule, rs)
			if err != nil {
				t.Fatal(err)
			}
			if !times[0].Equal(at) && tt.schedule == "" {
				t.Errorf("first instant %s, want %s", times[0], at)
			}
			got := states(times, rs)
			if len(got) != len(tt.want) || len(times) != len(tt.want) {
				t.Fatalf("instants %v cover %v, want exactly %v", times, got, tt.want)
			}
			for _, w := range tt.want {
				if !got[w] {
					t.Errorf("combination %q missing from %v", w, got)
				}
			}
		})
	}
}

func TestFirewall_PolicyTimes_errors(t *testing.T) {
	t.Parallel()
	fw := timedFirewall(t)
	after := time.Date(2027, 2, 1, 0, 0, 0, 0, time.UTC)
	for name, schedule := range map[string]string{"unknown": "nope", "unmodelled": "odd", "expired": "q4"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := fw.PolicyTimes(after, schedule, nil); !errors.Is(err, firemon.ErrScheduleProof) {
				t.Errorf("err = %v", err)
			}
		})
	}
}

func TestRecurrence_Contains_monthDays(t *testing.T) {
	t.Parallel()
	first := firemon.Recurrence{MonthDays: []int{1}, Start: 22 * time.Hour, End: 2 * time.Hour}
	tests := []struct {
		at   time.Time
		want bool
	}{
		{time.Date(2026, 12, 1, 23, 0, 0, 0, time.UTC), true},  // evening of the 1st
		{time.Date(2026, 12, 2, 1, 0, 0, 0, time.UTC), true},   // past midnight, started on the 1st
		{time.Date(2026, 12, 2, 23, 0, 0, 0, time.UTC), false}, // the 2nd
		{time.Date(2026, 12, 1, 1, 0, 0, 0, time.UTC), false},  // morning of the 1st: started on the 30th
	}
	for _, tt := range tests {
		if got := first.Contains(tt.at); got != tt.want {
			t.Errorf("%s: got %v", tt.at, got)
		}
	}
}
