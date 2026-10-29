package firemon_test

import (
	"slices"
	"testing"
	"time"

	fm "github.com/gatework/firemon"
)

func TestGraphCountsAndScheduleWindowsPreserveImmutableDeclarationOrder(t *testing.T) {
	now := time.Date(2026, 10, 29, 0, 0, 0, 0, time.UTC)
	windows := []fm.TimeWindow{{Start: now, End: now.Add(time.Hour)}, {Start: now.Add(2 * time.Hour), End: now.Add(3 * time.Hour)}}
	fw, err := fm.Seal(fm.Data{
		Metadata:  fm.Metadata{Device: "test", Vendor: "huawei"},
		Zones:     []fm.ZoneRecord{{Object: fm.Object{ID: "z"}}},
		Rules:     []fm.RuleRecord{{Object: fm.Object{ID: "r"}}},
		Schedules: []fm.ScheduleRecord{{Object: fm.Object{ID: "s"}, Windows: windows}, {Object: fm.Object{ID: "recurring"}, Recurring: []string{"unsupported recurrence"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if fw.RuleCount() != 1 || fw.ZoneCount() != 1 || fw.ScheduleCount() != 2 {
		t.Fatal("incorrect collection count")
	}
	s := fw.Schedule("s")
	if s.HasRecurrence() || !fw.Schedule("recurring").HasRecurrence() {
		t.Fatal("recurrence identity lost")
	}
	if got := slices.Collect(s.Windows()); !slices.Equal(got, windows) {
		t.Fatalf("windows: %v", got)
	}
	visits := 0
	for window := range s.Windows() {
		window.End = now
		visits++
		break
	}
	if visits != 1 || !slices.Equal(slices.Collect(s.Windows()), windows) {
		t.Fatal("early stop or value isolation failed")
	}
	windows[0].End = now
	if !slices.Collect(s.Windows())[0].End.Equal(now.Add(time.Hour)) {
		t.Fatal("input mutated graph")
	}
}
