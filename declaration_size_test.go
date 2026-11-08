package firemon

import (
	"testing"
	"time"
)

func TestDeclarationSizeIncludesNestedWorkAndRemainsCached(t *testing.T) {
	d := Data{Metadata: Metadata{Device: "synthetic", Vendor: "asa"},
		Schedules: []ScheduleRecord{{Object: Object{ID: "weekly", Spans: []Span{{First: 1, Last: 1}}}, Timezone: "UTC", Calendar: CalendarCivil, Weekly: []WeeklyPeriod{{Windows: []WeeklyWindow{{Day: time.Monday, End: time.Hour}}}}}},
		Rules:     []RuleRecord{{Object: Object{ID: "rule"}, Match: Match{Schedule: "weekly", Applications: []string{"one", "two"}}}},
	}
	fw, err := Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	if fw.RecordCount() != 2 || fw.DeclarationSize() != 7 {
		t.Fatal("nested preflight estimate changed record-count contract", fw.RecordCount(), fw.DeclarationSize())
	}
	d.Rules[0].Match.Applications = append(d.Rules[0].Match.Applications, "three")
	if fw.DeclarationSize() != 7 {
		t.Fatal("caller changed sealed preflight estimate")
	}
	counter := declarationCounter(int(^uint(0)>>1) - 1)
	counter.add(2)
	counter.add(1)
	if int(counter) != int(^uint(0)>>1) {
		t.Fatal("declaration estimate overflowed", counter)
	}
}
