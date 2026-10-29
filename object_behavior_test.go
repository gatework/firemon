package firemon_test

import (
	fm "github.com/gatework/firemon"
	"testing"
	"time"
)

func TestScheduleOwnsActivityAndExpiryEvidence(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	end := start.Add(time.Hour)
	for _, tc := range []struct {
		name                   string
		record                 fm.ScheduleRecord
		at                     time.Time
		active, expired, known bool
	}{
		{name: "before", at: start.Add(-time.Second), known: true},
		{name: "start", at: start, active: true, known: true},
		{name: "end", at: end, expired: true, known: true},
		{name: "unknown time", active: true},
		{name: "recurring", at: start, record: fm.ScheduleRecord{Recurring: []string{"weekly"}}, active: true},
		{name: "unsupported", at: start, record: fm.ScheduleRecord{Object: fm.Object{Unsupported: []string{"unmodeled"}}}, active: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := tc.record
			r.ID = "window"
			r.Windows = []fm.TimeWindow{{Start: start, End: end}}
			fw, err := fm.Seal(fm.Data{Metadata: fm.Metadata{Device: "test", Vendor: "huawei"}, Schedules: []fm.ScheduleRecord{r}})
			if err != nil {
				t.Fatal(err)
			}
			schedule := fw.Schedule("window")
			if got, known := schedule.ActiveAt(tc.at); got != tc.active || known != tc.known {
				t.Fatalf("active=%v known=%v", got, known)
			}
			if got, known := schedule.ExpiredAt(tc.at); got != tc.expired || known != tc.known {
				t.Fatalf("expired=%v known=%v", got, known)
			}
		})
	}
	var empty fm.Schedule
	if value, known := empty.ActiveAt(start); !value || known {
		t.Fatal("empty schedule became known")
	}
	if value, known := empty.ExpiredAt(start); value || known {
		t.Fatal("empty schedule became expired")
	}
}

func TestDomainReadMethodsRetainDeclarationState(t *testing.T) {
	d := seed()
	d.Raw = "original capture"
	d.Rules = []fm.RuleRecord{{Object: fm.Object{ID: "r", Unsupported: []string{"condition"}}, Action: fm.Drop, Disabled: true, Builtin: true}}
	fw, err := fm.Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	d.Raw = "changed"
	r := fw.Rule("r")
	if fw.Raw() != "original capture" || r.Action() != fm.Drop || !r.Disabled() || !r.Builtin() || !r.HasUnsupported() {
		t.Fatal("read methods changed object semantics")
	}
	record := r.Record()
	record.Unsupported[0] = "changed"
	if !r.HasUnsupported() || r.Record().Unsupported[0] != "condition" {
		t.Fatal("record escaped ownership")
	}
}
