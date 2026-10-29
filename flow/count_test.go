package flow_test

import (
	"net/netip"
	"testing"

	"github.com/gatework/firemon/flow"
)

func TestCountsDescribeNormalizedImmutableSets(t *testing.T) {
	r, _ := flow.PrefixRange(netip.MustParsePrefix("192.0.2.0/24"))
	set, err := flow.NewSet(r, r)
	if err != nil {
		t.Fatal(err)
	}
	if set.RangeCount() != 1 || (flow.Set{}).RangeCount() != 0 {
		t.Fatal("incorrect normalized range count")
	}
	box := flow.Box{Source: r, Destination: r}
	traffic, err := flow.NewTraffic(2, box, box)
	if err != nil {
		t.Fatal(err)
	}
	if traffic.RegionCount() != 1 || (flow.Traffic{}).RegionCount() != 0 {
		t.Fatal("incorrect disjoint region count")
	}
	ranges, boxes := set.Ranges(), traffic.Boxes()
	ranges[0] = flow.Range{}
	boxes[0] = flow.Box{}
	if set.RangeCount() != 1 || traffic.RegionCount() != 1 || !set.Ranges()[0].Valid() || !traffic.Boxes()[0].Valid() {
		t.Fatal("copy changed immutable sets")
	}
}
