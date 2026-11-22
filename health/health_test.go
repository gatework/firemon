package health_test

import (
	"testing"

	"github.com/gatework/firemon/health"
)

func TestAssess(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name string
		c    health.Counts
		want int
	}{
		{"empty firewall", health.Counts{}, 100},
		{"clean", health.Counts{Rules: 10, Permits: 8, Objects: 20}, 100},
		{"everything ineffective", health.Counts{Rules: 10, Ineffective: 10}, 60},
		{"mixed", health.Counts{Rules: 100, Permits: 50, Objects: 200, Ineffective: 25, Broad: 10, NoLog: 25, Unused: 50, Unreadable: 2}, 76}, // 100 - 10 - 6 - 5 - 2.5 - 0.2
		{"capped at the weight", health.Counts{Rules: 1, Unreadable: 9}, 90},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := health.Assess(tt.c).Value; got != tt.want {
				t.Fatalf("got %d, want %d", got, tt.want)
			}
		})
	}
}

func TestPriorities(t *testing.T) {
	t.Parallel()
	dev := func(name string, c health.Counts) health.Device {
		return health.Device{Cluster: name, Counts: c, Score: health.Assess(c)}
	}
	devs := []health.Device{
		dev("small", health.Counts{Rules: 5, Permits: 4, Broad: 4}),             // every permit broad, but four rules
		dev("large", health.Counts{Rules: 500, Permits: 400, Ineffective: 180}), // 36% of a large rulebase
		dev("clean", health.Counts{Rules: 10}),
	}
	got := health.Priorities(devs, 5)
	if len(got) != 2 || got[0].Cluster != "large" || got[0].Worst.Factor != health.FactorIneffective || got[0].Affected != 180 || got[1].Cluster != "small" {
		t.Fatalf("%+v", got)
	}
}
