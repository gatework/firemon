package paloalto_test

import (
	"testing"
	"time"

	"github.com/gatework/firemon/vendors/paloalto"
)

const hitOutput = `VSYS: vsys1
Rulebase: security
Rule Name                          Hit Count            Last Hit Timestamp               Last Reset Timestamp             First Hit Timestamp              Rule Creation Timestamp          Rule Modification Timestamp
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Allow updates                      1234                 Wed Nov 18 09:12:01 2026         -                                Mon Jan  5 08:00:00 2026         Mon Jan  5 07:59:00 2026         Tue Mar  3 10:00:00 2026
deny-old                           0                    -                                -                                -                                Thu Jan  1 00:00:00 2026         Thu Jan  1 00:00:00 2026
a-rule-with-a-very-long-name-that-pushes-the-columns-to-the-right 7 Wed Nov 18 09:00:00 2026 - Wed Nov 18 08:00:00 2026 Wed Nov 18 07:00:00 2026 Wed Nov 18 07:00:00 2026
intrazone-default                  0                    -                                -                                -                                -                                -
`

func TestParseHits(t *testing.T) {
	t.Parallel()
	loc := time.FixedZone("CST", 8*3600)
	now := time.Date(2026, 11, 18, 10, 0, 0, 0, loc)
	s, err := paloalto.ParseHits(hitOutput, "pa1", now, loc)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Counters) != 4 {
		t.Fatalf("counters %+v", s.Counters)
	}
	c, _ := s.Counter("Allow updates")
	if c.Hits != 1234 || c.LastHit.Day() != 18 || !c.Reset.Equal(time.Date(2026, 3, 3, 10, 0, 0, 0, loc)) {
		t.Fatalf("Allow updates %+v", c)
	}
	if c, ok := s.Counter("a-rule-with-a-very-long-name-that-pushes-the-columns-to-the-right"); !ok || c.Hits != 7 {
		t.Fatal("long names shift columns")
	}
	if _, err := paloalto.ParseHits("Error: no such vsys\n", "pa1", now, loc); err == nil {
		t.Fatal("no rows is an error")
	}
}

func FuzzParseHits(f *testing.F) {
	f.Add(hitOutput)
	f.Fuzz(func(t *testing.T, text string) {
		_, _ = paloalto.ParseHits(text, "pa1", time.Unix(0, 0), time.UTC)
	})
}
