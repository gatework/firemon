package hillstone_test

import (
	"testing"
	"time"

	"github.com/gatework/firemon/vendors/hillstone"
)

func TestParseHits(t *testing.T) {
	t.Parallel()
	out := `rule id 13
  action permit
  hit-count: 1042
rule id 15
  action deny
  hit count 0
Rule ID: 21, name: "x", hit count: 7
`
	s, err := hillstone.ParseHits(out, "fw1", time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]uint64{"13": 1042, "15": 0, "21": 7}
	for id, n := range want {
		if c, ok := s.Counter(id); !ok || c.Hits != n {
			t.Errorf("rule %s: %+v", id, c)
		}
	}
	if _, err := hillstone.ParseHits("% unknown command\n", "fw1", time.Unix(0, 0)); err == nil {
		t.Fatal("no counters is an error")
	}
}

func FuzzParseHits(f *testing.F) {
	f.Add("rule id 1\n hit-count: 3\n")
	f.Fuzz(func(t *testing.T, text string) {
		_, _ = hillstone.ParseHits(text, "fw", time.Unix(0, 0))
	})
}
