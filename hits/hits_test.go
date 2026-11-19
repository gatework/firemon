package hits_test

import (
	"strings"
	"testing"
	"time"

	"github.com/gatework/firemon/hits"
)

var day = 24 * time.Hour

func TestJudge(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 18, 0, 0, 0, 0, time.UTC)
	s := hits.Snapshot{Taken: now, Since: now.Add(-90 * day), Counters: []hits.Counter{
		{Rule: "used", Hits: 3},
		{Rule: "idle"},
		{Rule: "changed-lately", Reset: now.Add(-5 * day)},
	}}
	for rule, want := range map[string]hits.Verdict{
		"used": hits.VerdictUsed, "idle": hits.VerdictUnused, "changed-lately": hits.VerdictUnknown, "missing": hits.VerdictUnknown,
	} {
		if got := s.Judge(rule, 30*day); got != want {
			t.Errorf("%s: %s, want %s", rule, got, want)
		}
	}
	if (hits.Snapshot{Taken: now, Counters: []hits.Counter{{Rule: "x"}}}).Judge("x", 30*day) != hits.VerdictUnknown {
		t.Error("an unknown window never proves a rule unused")
	}
}

func TestMerge_HAMembers(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 18, 0, 0, 0, 0, time.UTC)
	a := hits.Snapshot{Taken: now, Since: now.Add(-60 * day), Counters: []hits.Counter{{Rule: "1", Hits: 0}, {Rule: "2", Hits: 5, LastHit: now.Add(-day)}}}
	b := hits.Snapshot{Taken: now.Add(-time.Hour), Since: now.Add(-40 * day), Counters: []hits.Counter{{Rule: "1", Hits: 2, LastHit: now.Add(-2 * day)}, {Rule: "3"}}}
	m := hits.Merge("cluster", a, b)
	if c, _ := m.Counter("1"); c.Hits != 2 || !c.LastHit.Equal(now.Add(-2*day)) {
		t.Fatalf("rule 1 %+v: the standby member's hits count", c)
	}
	if !m.Since.Equal(now.Add(-40*day)) || !m.Taken.Equal(now.Add(-time.Hour)) || len(m.Counters) != 2 {
		t.Fatalf("merged %+v: the window is what every member observed; rule 3 (one member, no hit) is left out", m)
	}
	if m.Judge("3", 30*day) != hits.VerdictUnknown {
		t.Fatal("a rule one member did not report is not judged unused")
	}
}

func TestDecode_CSV(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 18, 0, 0, 0, 0, time.UTC)
	s, err := hits.Decode(strings.NewReader("rule,hits,last_hit\n13,42,2026-11-17T08:00:00Z\n15,0,\n"), now, now.Add(-60*day))
	if err != nil {
		t.Fatal(err)
	}
	if s.Judge("15", 30*day) != hits.VerdictUnused || s.Judge("13", 30*day) != hits.VerdictUsed {
		t.Fatalf("decoded %+v", s)
	}
	if _, err := hits.Decode(strings.NewReader("name,count\nx,1\n"), now, now); err == nil {
		t.Fatal("columns are required")
	}
}
