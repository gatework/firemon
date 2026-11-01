package firemon_test

import (
	fm "github.com/gatework/firemon"
	"strings"
	"testing"
	"time"
)

func TestScheduleClockBindingAndCivilTime(t *testing.T) {
	m := fm.Metadata{CapturedAt: time.Date(2026, 10, 31, 0, 0, 0, 0, time.UTC), Device: "fw", Vendor: "hillstone", Software: "5.5R8", SourceDigest: strings.Repeat("a", 64)}
	c := fm.ScheduleClock{CapturedAt: m.CapturedAt, Device: m.Device, Vendor: m.Vendor, Software: m.Software, SourceDigest: m.SourceDigest, Timezone: "America/New_York", Reference: "synthetic independent clock observation", EndBoundary: "exclusive", TickSeconds: 1}
	if err := c.Validate(m); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*fm.ScheduleClock){func(c *fm.ScheduleClock) { c.SourceDigest = "wrong" }, func(c *fm.ScheduleClock) { c.Timezone = "Local" }, func(c *fm.ScheduleClock) { c.Reference = "" }, func(c *fm.ScheduleClock) { c.EndBoundary = "" }, func(c *fm.ScheduleClock) { c.Software = "other" }} {
		bad := c
		mutate(&bad)
		if bad.Validate(m) == nil {
			t.Fatalf("accepted unbound clock %+v", bad)
		}
	}
	for _, start := range []string{"2026-03-08 02:30", "2026-11-01 01:30", "2026-02-30 10:00"} {
		if _, err := c.ParseWindow("2006-01-02 15:04", start, "2026-12-01 12:00"); err == nil {
			t.Fatalf("accepted nonexistent/ambiguous %s", start)
		}
	}
	w, err := c.ParseWindow("2006-01-02 15:04", "2026-10-31 10:00", "2026-10-31 11:00")
	if err != nil || w.Start.Format(time.RFC3339) != "2026-10-31T14:00:00Z" || w.End.Sub(w.Start) != time.Hour {
		t.Fatal(w, err)
	}
	start, end, err := c.NativeWindow(w, time.Minute)
	if err != nil || start.Format("15:04") != "10:00" || end.Format("15:04") != "11:00" {
		t.Fatal(start, end, err)
	}
	w.End = w.End.Add(time.Second)
	if _, _, err = c.NativeWindow(w, time.Minute); err == nil {
		t.Fatal("rounded unrepresentable window")
	}
	c.EndBoundary = "inclusive"
	a, b, err := c.NativeWindow(w, time.Minute)
	if err != nil || b.Sub(a) != time.Hour {
		t.Fatal(a, b, err)
	}
	parsed, err := c.ParseWindow("2006-01-02 15:04", a.Format("2006-01-02 15:04"), b.Format("2006-01-02 15:04"))
	if err != nil || !parsed.End.Equal(w.End) {
		t.Fatal(parsed, err)
	}
}
