package hillstone_test

import (
	"testing"
	"time"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/audit"
	"github.com/gatework/firemon/vendors/hillstone"
)

// refConf has objects used only by QoS, a group nobody uses (whose member
// is therefore unused too), an empty service and a cross-day schedule.
const refConf = `schedule "workday-morning"
  periodic monday 00:01:00 to friday 18:10:00
exit
schedule "never"
  absolute end 1/1/2020 0:0:0
exit
address "qos-target"
  ip 192.0.2.0/24
exit
address "member-only"
  ip 198.51.100.1/32
exit
address "orphan-group"
  member "member-only"
exit
address "in-rule"
  ip 10.0.0.0/24
exit
service "no-ports"
exit
zone "inside"
exit
rule id 1
  action permit
  src-addr "in-rule"
  dst-addr "Any"
  service "no-ports"
exit
qos-engine first
  root-pipe "limit" id 1
    schedule "workday-morning"
    pipe-map id 1
      dst-addr "qos-target"
    exit
  exit
exit
`

func TestReferences_QoSGroupsAndSchedules(t *testing.T) {
	t.Parallel()
	fw := compileText(t, refConf)
	refs := fw.References()
	live := func(k firemon.ObjectKind, n string) bool { return refs.Live(firemon.ObjectRef{Kind: k, Name: n}) }
	if !live(firemon.ObjectKindAddress, "qos-target") || !live(firemon.ObjectKindSchedule, "workday-morning") {
		t.Fatal("objects a QoS pipe uses are in use")
	}
	unused := refs.Unused()
	want := []firemon.ObjectRef{
		{Kind: firemon.ObjectKindAddressGroup, Name: "orphan-group"},
		{Kind: firemon.ObjectKindAddress, Name: "member-only"},
		{Kind: firemon.ObjectKindSchedule, Name: "never"},
	}
	if len(unused) != len(want) {
		t.Fatalf("unused %v", unused)
	}
	for i := range want {
		if unused[i] != want[i] {
			t.Fatalf("unused %v, want groups first: %v", unused, want)
		}
	}
	rep := audit.Run(fw, audit.Options{Now: func() time.Time { return time.Date(2026, 11, 18, 0, 0, 0, 0, time.UTC) }})
	if rep.Count(audit.KindNeverMatches) != 1 || rep.Count(audit.KindEmptyObject) != 1 || rep.Count(audit.KindRedundant) != 0 || rep.Count(audit.KindUnusedSchedule) != 1 {
		t.Fatalf("findings %+v", rep.Findings)
	}
}

func TestSchedule_SpanningDays(t *testing.T) {
	t.Parallel()
	cfg := mustParse(t, hillstone.Options{}, refConf)
	s := cfg.Schedules[0]
	if s.Unsupported != "" || len(s.Recurrences) != 5 {
		t.Fatalf("monday 00:01 to friday 18:10: %+v", s)
	}
	in := func(day int, h, m int) bool {
		at := time.Date(2026, 11, 16+day, h, m, 0, 0, time.UTC) // 16 Nov 2026 is a Monday
		return s.ActiveAt(at)
	}
	if in(0, 0, 0) || !in(0, 0, 1) || !in(2, 3, 0) || !in(4, 18, 10) || in(4, 18, 11) || in(5, 12, 0) {
		t.Fatal("the period runs from Monday 00:01 to Friday 18:10 inclusive")
	}
}
