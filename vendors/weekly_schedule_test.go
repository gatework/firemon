package vendors_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/snapshot"
	"github.com/gatework/firemon/vendors"
)

type weeklyCase struct{ vendor, version, raw, command string }

func weeklyCases() []weeklyCase {
	return []weeklyCase{
		{"hillstone", "5.5R8", "schedule office\nperiodic monday 09:00 to 17:00\nexit\n", "periodic monday 09:00 to 17:00"},
		{"asa", "9.16(4)", "time-range office\n periodic Monday 09:00 to 17:00\n!\n", "periodic monday 09:00 to 17:00"},
		{"srx", "21.4R3", "set schedulers scheduler office monday start-time 09:00 stop-time 17:00\n", "set schedulers scheduler office monday start-time 09:00 stop-time 17:00"},
		{"paloalto", "10.2.7", "set schedule office schedule-type recurring weekly monday 09:00-17:00\n", "set schedule \"office\" schedule-type recurring weekly monday 09:00-17:00"},
		{"fortinet", "7.2.8", "config firewall schedule recurring\nedit office\nset day monday\nset start 09:00\nset end 17:00\nnext\nend\n", "set day monday"},
		{"huawei", "V500R005", "time-range office\n period-range 09:00:00 to 17:00:00 monday\n#\n", "period-range 09:00:00 to 17:00:00 monday"},
		{"netscreen", "6.3.0", "set scheduler office recurrent monday start 09:00 stop 17:00\n", "set scheduler \"office\" recurrent monday start 09:00 stop 17:00"},
	}
}

func TestSevenNativeRecurringSchedules(t *testing.T) {
	monday := time.Date(2026, 11, 2, 1, 0, 0, 0, time.UTC) // 09:00 Hong Kong.
	for _, tc := range weeklyCases() {
		t.Run(tc.vendor, func(t *testing.T) {
			fw, _ := scheduleCapture(t, tc.vendor, tc.version, tc.raw, true)
			s := fw.Schedule("office")
			if !fw.Complete() || s == nil || s.HasUnsupported() || !s.HasRecurrence() {
				t.Fatalf("unresolved recurring capture: %v", fw.Diagnostics())
			}
			var data bytes.Buffer
			if err := snapshot.Encode(&data, fw); err != nil {
				t.Fatal(err)
			}
			restored, err := snapshot.Decode(&data, snapshot.DefaultMaxBytes)
			if err != nil {
				t.Fatal(err)
			}
			for _, graph := range []*fm.Firewall{fw, restored} {
				for _, at := range []time.Time{monday.Add(-time.Nanosecond), monday, monday.Add(8*time.Hour - time.Nanosecond), monday.Add(8 * time.Hour), monday.Add(24 * time.Hour), monday.AddDate(100, 0, 0)} {
					local := at.In(time.FixedZone("fixture", 8*60*60))
					want := local.Weekday() == time.Monday && local.Hour() >= 9 && local.Hour() < 17
					active, known := graph.Schedule("office").ActiveAt(at)
					if !known || active != want {
						t.Fatalf("%v: active=%v known=%v want=%v", at, active, known, want)
					}
				}
			}
			// The independently captured after configuration is the input. Renderer
			// output is checked against native syntax, never used as its own oracle.
			before, after, changes := scheduledPolicy(t, fw)
			renderer, err := vendors.Renderer(tc.vendor)
			if err != nil {
				t.Fatal(err)
			}
			commands, err := renderer.(plan.NativeRenderer).RenderNative(t.Context(), before, after, changes)
			if err != nil || !strings.Contains(strings.Join(commands, "\n"), tc.command) {
				t.Fatal(commands, err)
			}
			unknown, _ := scheduleCapture(t, tc.vendor, tc.version, tc.raw, false)
			if _, known := unknown.Schedule("office").ActiveAt(monday); known {
				t.Fatal("missing clock became unrestricted or known")
			}
			source, metadata := observedScheduleSource(tc.raw, fw.Metadata(), true)
			source.ScheduleClock.Calendar = fm.CalendarUnknown
			unknown, err = (vendors.Parser{}).Parse(t.Context(), source, metadata)
			if err != nil {
				t.Fatal(err)
			}
			if _, known := unknown.Schedule("office").ActiveAt(monday); known {
				t.Fatal("missing calendar attestation became known")
			}
		})
	}
}

func TestAdditionalAbsoluteNativeSchedules(t *testing.T) {
	for _, tc := range []struct{ vendor, version, raw string }{
		{"asa", "9.16(4)", "time-range temporary\n absolute start 10:00 31 October 2026 end 11:00 31 October 2026\n!\n"},
		{"srx", "21.4R3", "set schedulers scheduler temporary start-date 2026-10-31.10:00\nset schedulers scheduler temporary stop-date 2026-10-31.11:00\n"},
		{"paloalto", "10.2.7", "set schedule temporary schedule-type non-recurring 2026/10/31@10:00-2026/10/31@11:00\n"},
	} {
		t.Run(tc.vendor, func(t *testing.T) {
			fw, _ := scheduleCapture(t, tc.vendor, tc.version, tc.raw, true)
			if !fw.Complete() {
				t.Fatal(fw.Diagnostics())
			}
			at := time.Date(2026, 10, 31, 2, 0, 0, 0, time.UTC)
			if active, known := fw.Schedule("temporary").ActiveAt(at); !active || !known {
				t.Fatal(active, known)
			}
			before, after, changes := scheduledPolicy(t, fw)
			renderer, err := vendors.Renderer(tc.vendor)
			if err != nil {
				t.Fatal(err)
			}
			commands, err := renderer.(plan.NativeRenderer).RenderNative(t.Context(), before, after, changes)
			if err != nil || len(commands) == 0 {
				t.Fatal(commands, err)
			}
		})
	}
}

func TestDateBoundsIntersectPeriodicEntries(t *testing.T) {
	for _, tc := range []struct{ vendor, version, raw string }{
		{"hillstone", "5.5R8", "schedule office\nabsolute start 11/01/2026 00:00 end 11/06/2026 00:00\nperiodic weekdays 9:00 to 17:00\nexit\n"},
		{"asa", "9.16(4)", "time-range office\n absolute start 00:00 1 November 2026 end 00:00 6 November 2026\n periodic weekdays 9:00 to 17:00\n!\n"},
		{"srx", "21.4R3", "set schedulers scheduler office start-date 2026-11-01.00:00 stop-date 2026-11-06.00:00\nset schedulers scheduler office daily start-time 09:00 stop-time 17:00\nset schedulers scheduler office sunday exclude\nset schedulers scheduler office saturday exclude\n"},
	} {
		t.Run(tc.vendor, func(t *testing.T) {
			fw, _ := scheduleCapture(t, tc.vendor, tc.version, tc.raw, true)
			s := fw.Schedule("office")
			if !fw.Complete() || s == nil || len(s.Record().Windows) != 0 || len(s.Record().Weekly) != 1 {
				t.Fatal(fw.Diagnostics(), s)
			}
			for _, test := range []struct {
				stamp  string
				active bool
			}{{"2026-11-02T01:00:00Z", true}, {"2026-11-02T00:00:00Z", false}, {"2026-11-09T01:00:00Z", false}, {"2026-10-26T01:00:00Z", false}} {
				at, _ := time.Parse(time.RFC3339, test.stamp)
				active, known := s.ActiveAt(at)
				if !known || active != test.active {
					t.Fatal(test, active, known)
				}
			}
			before, after, changes := scheduledPolicy(t, fw)
			renderer, err := vendors.Renderer(tc.vendor)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := renderer.(plan.NativeRenderer).RenderNative(t.Context(), before, after, changes); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSRXWeekdayOverrideAndNetscreenTwoPeriods(t *testing.T) {
	for _, tc := range []struct {
		vendor, version, raw string
		hour                 int
		active               bool
	}{
		{"srx", "21.4R3", "set schedulers scheduler office daily start-time 09:00 stop-time 17:00\nset schedulers scheduler office monday start-time 10:00 stop-time 11:00\nset schedulers scheduler office sunday exclude\n", 9, false},
		{"srx", "21.4R3", "set schedulers scheduler office daily start-time 09:00 stop-time 17:00\nset schedulers scheduler office monday start-time 10:00 stop-time 11:00\nset schedulers scheduler office sunday exclude\n", 10, true},
		{"netscreen", "6.3.0", "set scheduler office recurrent monday start 09:00 stop 12:00 start 14:00 stop 17:00 comment lunch\n", 13, false},
		{"netscreen", "6.3.0", "set scheduler office recurrent monday start 09:00 stop 12:00 start 14:00 stop 17:00 comment lunch\n", 14, true},
	} {
		fw, _ := scheduleCapture(t, tc.vendor, tc.version, tc.raw, true)
		if !fw.Complete() {
			t.Fatal(tc.vendor, fw.Diagnostics())
		}
		active, known := fw.Schedule("office").ActiveAt(time.Date(2026, 11, 2, tc.hour-8, 0, 0, 0, time.UTC))
		if !known || active != tc.active {
			t.Fatal(tc.vendor, tc.hour, active, known)
		}
	}
}

func TestNativeScheduleUnrepresentableMeaningIsRejected(t *testing.T) {
	for _, tc := range []struct{ vendor, version, raw string }{
		{"asa", "9.16(4)", "time-range office\n absolute end 17:00 6 November 2026\n periodic monday 09:00 to 17:00\n!\n"},
		{"hillstone", "5.5R8", "schedule office\nperiodic holidays 09:00 to 17:00\nexit\n"},
		{"paloalto", "10.2.7", "set schedule office schedule-type recurring daily 09:00-17:00\nset schedule office schedule-type recurring weekly monday 10:00-11:00\n"},
		{"paloalto", "10.2.7", "set schedule office schedule-type recurring weekly monday 23:00-01:00\n"},
		{"huawei", "V500R005", "time-range office\n absolute-range 00:00:00 2026/11/01 to 00:00:00 2026/11/06\n period-range 09:00:00 to 17:00:00 monday\n#\n"},
	} {
		fw, _ := scheduleCapture(t, tc.vendor, tc.version, tc.raw, true)
		if s := fw.Schedule("office"); s == nil || !s.HasUnsupported() {
			t.Fatal(tc.vendor, "lost unknown schedule")
		}
		if _, known := fw.Schedule("office").ActiveAt(time.Date(2026, 11, 2, 2, 0, 0, 0, time.UTC)); known {
			t.Fatal(tc.vendor, "unknown meaning became known")
		}
	}
	fw, _ := scheduleCapture(t, "fortinet", "7.2.8", "config firewall schedule recurring\nedit office\nset day monday\nset start 09:00\nset end 17:00\nnext\nend\n", true)
	before, after, changes := scheduledPolicy(t, fw)
	r := after.Schedule("office").Record()
	r.Weekly[0].Windows = append(r.Weekly[0].Windows, fm.WeeklyWindow{Day: time.Tuesday, Start: 10 * time.Hour, End: 11 * time.Hour})
	data := after.Export()
	data.Schedules = []fm.ScheduleRecord{r}
	after, err := fm.Seal(data)
	if err != nil {
		t.Fatal(err)
	}
	changes.Additions.Schedules = []fm.ScheduleRecord{r}
	renderer, err := vendors.Renderer("fortinet")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := renderer.(plan.NativeRenderer).RenderNative(t.Context(), before, after, changes); !errors.Is(err, plan.ErrRender) {
		t.Fatal("heterogeneous FortiOS schedule widened", err)
	}
}

func scheduledPolicy(t *testing.T, fw *fm.Firewall) (*fm.Firewall, *fm.Firewall, plan.NativeChanges) {
	t.Helper()
	m := fw.Metadata()
	name := fw.Schedules()[0].ID()
	rules := map[string]string{
		"hillstone": "policy-global\nrule id 10\nsrc-zone inside\ndst-zone outside\nsrc-addr any\ndst-addr any\nservice any\nschedule office\naction permit\nexit\nexit\n",
		"asa":       "object network client\nhost 192.0.2.10\n!\nobject network server\nhost 198.51.100.20\n!\nobject service https\nservice tcp destination eq 443\n!\naccess-list IN extended permit object https object client object server time-range office\n",
		"srx":       "set security policies from-zone inside to-zone outside policy office-rule match source-address any\nset security policies from-zone inside to-zone outside policy office-rule match destination-address any\nset security policies from-zone inside to-zone outside policy office-rule match application any\nset security policies from-zone inside to-zone outside policy office-rule then permit\nset security policies from-zone inside to-zone outside policy office-rule scheduler-name office\n",
		"paloalto":  "set rulebase security rules office-rule from inside\nset rulebase security rules office-rule to outside\nset rulebase security rules office-rule source any\nset rulebase security rules office-rule destination any\nset rulebase security rules office-rule service any\nset rulebase security rules office-rule application any\nset rulebase security rules office-rule action allow\nset rulebase security rules office-rule log-start no\nset rulebase security rules office-rule log-end no\nset rulebase security rules office-rule schedule office\n",
		"fortinet":  "config firewall policy\nedit 10\nset name office-rule\nset srcintf lan1\nset dstintf wan1\nset srcaddr all\nset dstaddr all\nset service ALL\nset schedule office\nset action accept\nset logtraffic disable\nnext\nend\n",
		"huawei":    "security-policy\n rule name office-rule\n  source-zone trust\n  destination-zone untrust\n  time-range office\n  action permit\n#\n",
		"netscreen": "set policy id 10 from Trust to Untrust Any Any ANY permit schedule office\nexit\n",
	}
	base := ""
	for _, native := range nativeCases() {
		if native.vendor == m.Vendor {
			base = native.before
			break
		}
	}
	if m.Vendor == "asa" {
		base += "access-group IN in interface inside\n"
	}
	if m.Vendor == "paloalto" {
		base = "set network interface ethernet ethernet1/1 layer3 ip 192.0.2.1/24\nset network interface ethernet ethernet1/2 layer3 ip 198.51.100.1/24\nset zone inside network layer3 ethernet1/1\nset zone outside network layer3 ethernet1/2\n"
	}
	before, clock := scheduleCapture(t, m.Vendor, m.Software, base, true)
	after, _ := scheduleCapture(t, m.Vendor, m.Software, base+fw.Raw()+strings.ReplaceAll(rules[m.Vendor], "office", string(name)), true)
	if !before.Complete() || !after.Complete() {
		t.Fatal(before.Diagnostics(), after.Diagnostics())
	}
	changes := nativeDelta(before, after)
	changes.Clock = &clock
	changes.Additions.Schedules = []fm.ScheduleRecord{after.Schedule(name).Record()}
	return before, after, changes
}

func TestSevenNativeRecurringPolicyAttachments(t *testing.T) {
	refs := map[string]string{"hillstone": "schedule office", "asa": "time-range office", "srx": "scheduler-name office", "paloalto": "schedule office", "fortinet": "set schedule office", "huawei": "time-range office", "netscreen": "schedule office"}
	for _, tc := range weeklyCases() {
		t.Run(tc.vendor, func(t *testing.T) {
			fw, _ := scheduleCapture(t, tc.vendor, tc.version, tc.raw, true)
			before, after, changes := scheduledPolicy(t, fw)
			renderer, err := vendors.Renderer(tc.vendor)
			if err != nil {
				t.Fatal(err)
			}
			commands, err := renderer.(plan.NativeRenderer).RenderNative(t.Context(), before, after, changes)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(strings.Join(commands, "\n"), refs[tc.vendor]) {
				t.Fatal("missing policy schedule attachment", commands)
			}
			if len(changes.Additions.Rules) != 1 || after.Rule(changes.Additions.Rules[0].ID).Schedule() != after.Schedule("office") {
				t.Fatal("typed schedule reference not bound")
			}
		})
	}
}

func TestPeriodicContinuousWeekdaySpansAndFortinetFullDays(t *testing.T) {
	for _, tc := range []struct{ vendor, version, raw string }{
		{"hillstone", "5.5R8", "schedule office\nperiodic monday 23:00 to wednesday 01:00\nexit\n"},
		{"asa", "9.16(4)", "time-range office\n periodic Monday 23:00 to Wednesday 01:00\n!\n"},
		{"fortinet", "7.2.8", "config firewall schedule recurring\nedit office\nset day monday\nset start 23:00\nset end 01:00\nnext\nend\n"},
	} {
		fw, _ := scheduleCapture(t, tc.vendor, tc.version, tc.raw, true)
		if !fw.Complete() {
			t.Fatal(tc.vendor, fw.Diagnostics())
		}
		before, after, changes := scheduledPolicy(t, fw)
		renderer, err := vendors.Renderer(tc.vendor)
		if err != nil {
			t.Fatal(err)
		}
		commands, err := renderer.(plan.NativeRenderer).RenderNative(t.Context(), before, after, changes)
		if err != nil || len(commands) == 0 {
			t.Fatal(tc.vendor, commands, err)
		}
		for _, test := range []struct {
			day, hour int
			active    bool
		}{{2, 22, false}, {2, 23, true}, {3, 0, true}} {
			active, known := fw.Schedule("office").ActiveAt(time.Date(2026, 11, test.day, test.hour-8, 30, 0, 0, time.UTC))
			if !known || active != test.active {
				t.Fatal(tc.vendor, test, active, known)
			}
		}
	}
	for _, start := range []string{"00:00", "09:00"} {
		raw := "config firewall schedule recurring\nedit office\nset day monday\nset start " + start + "\nset end " + start + "\nnext\nend\n"
		fw, _ := scheduleCapture(t, "fortinet", "7.2.8", raw, true)
		if !fw.Complete() {
			t.Fatal(fw.Diagnostics())
		}
		at := time.Date(2026, 11, 2, 12-8, 0, 0, 0, time.UTC)
		if active, known := fw.Schedule("office").ActiveAt(at); !active || !known {
			t.Fatal(start, active, known)
		}
		before, after, changes := scheduledPolicy(t, fw)
		renderer, err := vendors.Renderer("fortinet")
		if err != nil {
			t.Fatal(err)
		}
		commands, err := renderer.(plan.NativeRenderer).RenderNative(t.Context(), before, after, changes)
		if err != nil || !strings.Contains(strings.Join(commands, "\n"), "set start "+start) || !strings.Contains(strings.Join(commands, "\n"), "set end "+start) {
			t.Fatal(commands, err)
		}
	}
}
