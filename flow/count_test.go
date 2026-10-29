package flow_test

import (
	"net/netip"
	"testing"

	"github.com/gatework/firemon/flow"
)

func TestCountsDescribeNormalizedImmutableSets(t *testing.T) {
	r, _ := flow.PrefixRange(netip.MustParsePrefix("192.0.2.0/24"))
	set, err := flow.NewAddressSet(r, r)
	if err != nil {
		t.Fatal(err)
	}
	if set.RangeCount() != 1 || (flow.AddressSet{}).RangeCount() != 0 {
		t.Fatal("incorrect normalized range count")
	}
	box := flow.TrafficRegion{Source: r, Destination: r}
	traffic, err := flow.NewTraffic(2, box, box)
	if err != nil {
		t.Fatal(err)
	}
	if traffic.RegionCount() != 1 || (flow.Traffic{}).RegionCount() != 0 {
		t.Fatal("incorrect disjoint region count")
	}
	ranges, boxes := set.Ranges(), traffic.Regions()
	ranges[0] = flow.AddressRange{}
	boxes[0] = flow.TrafficRegion{}
	if set.RangeCount() != 1 || traffic.RegionCount() != 1 || !set.Ranges()[0].Valid() || !traffic.Regions()[0].Valid() {
		t.Fatal("copy changed immutable sets")
	}
}
