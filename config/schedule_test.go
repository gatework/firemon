package config_test

import (
	"crypto/sha256"
	"fmt"
	"testing"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
)

func TestBuilderRecurringHelpersRequireCaptureBoundCalendar(t *testing.T) {
	const text = "synthetic schedule declaration"
	at := time.Date(2026, 11, 7, 0, 0, 0, 0, time.UTC)
	metadata := fm.Metadata{Device: "synthetic", Vendor: "asa", Software: "test", CapturedAt: at}
	clock := fm.ScheduleClock{Device: metadata.Device, Vendor: metadata.Vendor, Software: metadata.Software, CapturedAt: at, SourceDigest: fmt.Sprintf("%x", sha256.Sum256([]byte(text))), Timezone: "UTC", Reference: "independent clock evidence", EndBoundary: "exclusive", TickSeconds: 60, Calendar: fm.CalendarCivil}
	content, err := config.NewContent(t.Context(), config.Source{Text: text, Complete: true, ScheduleClock: &clock}, config.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	builder, err := config.NewBuilder(content, metadata)
	if err != nil {
		t.Fatal(err)
	}
	clock.Calendar = fm.CalendarUnknown // the builder owns its evidence copy
	windows, timezone, err := builder.ScheduleWeekly([]time.Weekday{time.Saturday}, "23:00", "01:00")
	if err != nil || timezone != "UTC" || len(windows) != 2 {
		t.Fatal(windows, timezone, err)
	}
	span, timezone, err := builder.ScheduleWeeklySpan(time.Friday, time.Monday, "09:00", "17:00")
	if err != nil || timezone != "UTC" || len(span) != 4 {
		t.Fatal(span, timezone, err)
	}
	bound, timezone, err := builder.ScheduleBound("2006-01-02 15:04", "", false)
	if err != nil || timezone != "UTC" || !bound.IsZero() {
		t.Fatal(bound, timezone, err)
	}
	missing, err := config.NewBuilder(source(t, text), metadata)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := missing.ScheduleWeekly([]time.Weekday{time.Monday}, "09:00", "17:00"); err == nil {
		t.Fatal("missing clock admitted a recurring schedule")
	}
}
