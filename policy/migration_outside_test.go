package policy_test

import (
	"context"
	"errors"
	"testing"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/policy"
)

func outsideNATFixture(t *testing.T, scheduled bool) (*fm.Firewall, *fm.Firewall, *fm.Firewall, time.Time, []policy.Request) {
	t.Helper()
	from := time.Date(2026, 11, 8, 0, 0, 0, 0, time.UTC)
	calendar := fm.ScheduleRecord{Object: fm.Object{ID: "monday"}, Timezone: "UTC", Calendar: fm.CalendarCivil, Weekly: []fm.WeeklyPeriod{{Windows: []fm.WeeklyWindow{{Day: time.Monday, Start: 9 * time.Hour, End: 10 * time.Hour}}}}}
	timeSource := recurringGraph(t, calendar)
	data := migrationData("paloalto")
	nat := data.StaticNATs[0]
	nat.Match.AnyFromZone, nat.Match.AnyToZone = false, false
	nat.Match.FromZones, nat.Match.ToZones = []fm.ID{"inside"}, []fm.ID{"outside"}
	data.StaticNATs = nil
	before := migrationGraph(t, data)
	data.StaticNATs = []fm.StaticNATRecord{nat}
	if scheduled {
		data.Schedules = []fm.ScheduleRecord{calendar}
		data.StaticNATs[0].Match.Schedule = calendar.ID
	}
	after := migrationGraph(t, data)
	contexts, err := (policy.Engine{}).Contexts(t.Context(), from, timeSource, before, after)
	if err != nil {
		t.Fatal(err)
	}
	all, err := flow.AllTraffic(4096)
	if err != nil {
		t.Fatal(err)
	}
	box := all.Regions()[0]
	box.Source = rangeOf("192.0.2.0/31")
	selected, err := flow.NewTraffic(4096, box)
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[time.Time]bool)
	var domains []policy.Request
	for _, q := range contexts {
		active, _ := timeSource.Schedule("monday").ActiveAt(q.At)
		if active && !seen[q.At] {
			seen[q.At] = true
			domains = append(domains, policy.Request{Scope: "", RuleSet: "security", FromZone: "inside", ToZone: "outside", At: q.At, Traffic: selected})
		}
	}
	if len(domains) == 0 {
		t.Fatal("fixture has no active temporal cell")
	}
	return before, after, timeSource, from, domains
}

func TestPreserveNATOutsideRetainsExactTemporalAuthorization(t *testing.T) {
	for _, scheduled := range []bool{true, false} {
		before, after, source, from, domains := outsideNATFixture(t, scheduled)
		proof, err := (policy.Engine{}).PreserveNATOutside(t.Context(), before, after, from, domains, source)
		if scheduled {
			if err != nil || !proof.OutsidePreserved || proof.IntentSatisfied || proof.Contexts == 0 {
				t.Fatal("scheduled native outside proof failed or endorsed an unproved intent", proof, err)
			}
		} else if !errors.Is(err, policy.ErrNotEquivalent) {
			t.Fatal("weekly authorization widened into permanent source NAT", proof, err)
		}
	}
}

func TestPreserveNATOutsideRejectsNonrepresentativeTimesAndBudgets(t *testing.T) {
	before, after, source, from, domains := outsideNATFixture(t, true)
	wrong := append([]policy.Request(nil), domains...)
	wrong[0].At = wrong[0].At.Add(time.Minute)
	if _, err := (policy.Engine{}).PreserveNATOutside(t.Context(), before, after, from, wrong, source); !errors.Is(err, policy.ErrInvalid) {
		t.Fatal("arbitrary sampled date authorized a temporal cell", err)
	}
	for _, limits := range []policy.Limits{{MaxVisits: 2}, {MaxCombinations: 2}} {
		if _, err := (policy.Engine{Limits: limits}).PreserveNATOutside(t.Context(), before, after, from, domains, source); !errors.Is(err, policy.ErrBudget) {
			t.Fatal("outside expansion escaped its budget", err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := (policy.Engine{}).PreserveNATOutside(ctx, before, after, from, domains, source); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled outside proof continued", err)
	}
}

func TestPreserveNATOutsideKeepsExistingDeclarationsAndTargetAxes(t *testing.T) {
	before, _, source, from, _ := outsideNATFixture(t, true)
	proof, err := (policy.Engine{}).PreserveNATOutside(t.Context(), before, before, from, nil, source)
	if err != nil || !proof.OutsidePreserved || proof.IntentSatisfied {
		t.Fatal("unchanged target proof failed", proof, err)
	}
	// Source-only zones must affect time coverage, not invent target axes.
	data := source.Export()
	data.Zones = []fm.ZoneRecord{{Object: fm.Object{ID: "source-only"}}}
	sourceWithZone := migrationGraph(t, data)
	second, err := (policy.Engine{}).PreserveNATOutside(t.Context(), before, before, from, nil, sourceWithZone)
	if err != nil || second.Contexts != proof.Contexts {
		t.Fatal("source topology leaked into target native outside contexts", second, err)
	}
	data = before.Export()
	data.StaticNATs = migrationData("paloalto").StaticNATs
	existing := migrationGraph(t, data)
	data.StaticNATs[0].Source[0].Translated = rangeOf("203.0.113.2/31")
	changed := migrationGraph(t, data)
	all, _ := flow.AllTraffic(4096)
	if _, err := (policy.Engine{}).PreserveNATOutside(t.Context(), existing, changed, from, []policy.Request{{Traffic: all, At: from}}); !errors.Is(err, policy.ErrNotEquivalent) {
		t.Fatal("authorization allowed editing an existing mapping", err)
	}
}
