package analysis_test

import (
	"context"
	"errors"
	"net/netip"
	"runtime"
	"testing"

	"github.com/gatework/firemon/analysis"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/policy"
)

func request(t *testing.T, src, dst string) policy.Request {
	t.Helper()
	a, b := netip.MustParseAddr(src), netip.MustParseAddr(dst)
	traffic, err := flow.NewTraffic(32, flow.TrafficRegion{Source: flow.AddressRange{First: a, Last: a}, Destination: flow.AddressRange{First: b, Last: b}, Protocol: flow.Interval{Low: 6, High: 6}, SourcePort: flow.Interval{High: 65535}, DestinationPort: flow.Interval{Low: 443, High: 443}, ICMPType: flow.Interval{High: 255}, ICMPCode: flow.Interval{High: 255}})
	if err != nil {
		t.Fatal(err)
	}
	return policy.Request{Traffic: traffic, RuleSet: "security"}
}

func TestOptimizerRegionBudgetDoesNotDependOnInputPacking(t *testing.T) {
	first := request(t, "192.0.2.1", "198.51.100.1")
	second := first
	region := first.Traffic.Regions()[0]
	region.DestinationPort = flow.Interval{Low: 444, High: 444}
	var err error
	second.Traffic, err = flow.NewTraffic(2, region)
	if err != nil {
		t.Fatal(err)
	}
	packed := first
	packed.Traffic, err = first.Traffic.Union(second.Traffic, 2)
	if err != nil || packed.Traffic.RegionCount() != 2 {
		t.Fatal("fixture", err)
	}
	for _, inputs := range [][]policy.Request{{packed}, {first, second}} {
		groups, err := (analysis.RequestOptimizer{MaxRegions: 1}).Optimize(context.Background(), inputs)
		if groups != nil || !errors.Is(err, flow.ErrBudget) {
			t.Errorf("oversized input accepted (%d requests): %v %v", len(inputs), groups, err)
		}
		groups, err = (analysis.RequestOptimizer{MaxRegions: 2}).Optimize(context.Background(), inputs)
		if err != nil || len(groups) != 1 || groups[0].Request.Traffic.RegionCount() != 1 || len(groups[0].Inputs) != len(inputs) {
			t.Fatalf("adequate budget: %v %v", groups, err)
		}
		if equal, err := groups[0].Request.Traffic.Equal(packed.Traffic, 4); err != nil || !equal {
			t.Fatal("optimization changed traffic", err)
		}
	}
}

func TestOptimizerRejectsOversizedInputBeforeCopying(t *testing.T) {
	q := request(t, "192.0.2.1", "198.51.100.1")
	region := q.Traffic.Regions()[0]
	regions := make([]flow.TrafficRegion, 1024)
	for i := range regions {
		regions[i] = region
		regions[i].DestinationPort = flow.Interval{Low: uint16(i), High: uint16(i)}
	}
	var err error
	q.Traffic, err = flow.NewTraffic(len(regions), regions...)
	if err != nil {
		t.Fatal(err)
	}
	var start, end runtime.MemStats
	runtime.ReadMemStats(&start)
	groups, err := (analysis.RequestOptimizer{MaxRegions: 1, MaxComparisons: 1}).Optimize(context.Background(), []policy.Request{q})
	runtime.ReadMemStats(&end)
	if groups != nil || !errors.Is(err, flow.ErrBudget) {
		t.Errorf("input region limit not checked: groups=%v err=%v", groups, err)
	}
	if allocated := end.TotalAlloc - start.TotalAlloc; allocated > 16<<10 {
		t.Fatalf("oversized traffic copied: %d bytes", allocated)
	}
}

func TestOptimizerPreservesPairsAndMergesToFixedPoint(t *testing.T) {
	requests := []policy.Request{request(t, "192.0.2.1", "198.51.100.1"), request(t, "192.0.2.2", "198.51.100.2")}
	groups, err := (analysis.RequestOptimizer{}).Optimize(context.Background(), requests)
	if err != nil || len(groups) != 1 || len(groups[0].Request.Traffic.Regions()) != 2 {
		t.Fatal(groups, err)
	}
	cross := request(t, "192.0.2.1", "198.51.100.2")
	hit, err := groups[0].Request.Traffic.Intersection(cross.Traffic, 32)
	if err != nil || !hit.Empty() {
		t.Fatal("cross pair introduced")
	}
	requests = append(requests, cross, request(t, "192.0.2.2", "198.51.100.1"))
	groups, err = (analysis.RequestOptimizer{}).Optimize(context.Background(), requests)
	if err != nil || len(groups) != 1 || len(groups[0].Request.Traffic.Regions()) != 1 || len(groups[0].Inputs) != 4 {
		t.Fatal("not a fixed point", groups, err)
	}
	if len(requests[0].Traffic.Regions()) != 1 || requests[0].Traffic.Regions()[0].Source.First != requests[0].Traffic.Regions()[0].Source.Last {
		t.Fatal("input mutated")
	}
}

func TestOptimizerKeepsContextsAndFailsAtComparisonBudget(t *testing.T) {
	a := request(t, "192.0.2.1", "198.51.100.1")
	b := a
	b.FromZone = "other"
	groups, err := (analysis.RequestOptimizer{}).Optimize(context.Background(), []policy.Request{a, b})
	if err != nil || len(groups) != 2 {
		t.Fatal(groups, err)
	}
	_, err = (analysis.RequestOptimizer{MaxComparisons: 1}).Optimize(context.Background(), []policy.Request{a, a, a})
	if !errors.Is(err, policy.ErrBudget) {
		t.Fatal("budget ignored", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (analysis.RequestOptimizer{}).Optimize(ctx, []policy.Request{a}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
