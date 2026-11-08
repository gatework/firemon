package analysis_test

import (
	"context"
	"errors"
	"math/rand/v2"
	"net/netip"
	"runtime"
	"slices"
	"testing"
	"time"

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

func TestOptimizerIndexesSemanticContexts(t *testing.T) {
	base := request(t, "192.0.2.1", "198.51.100.1")
	base.RuleSet = ""
	base.At = time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	same := base
	same.RuleSet, same.At = "security", base.At.In(time.FixedZone("capture", 8*3600))
	inputs := []policy.Request{base, same}
	for _, change := range []func(*policy.Request){
		func(q *policy.Request) { q.Scope = "tenant" },
		func(q *policy.Request) { q.RuleSet = "acl" },
		func(q *policy.Request) { q.FromZone = "inside" },
		func(q *policy.Request) { q.ToZone = "outside" },
		func(q *policy.Request) { q.EgressInterface = "eth1" },
		func(q *policy.Request) { q.At = q.At.Add(time.Second) },
	} {
		q := base
		change(&q)
		inputs = append(inputs, q)
	}
	groups, err := (analysis.RequestOptimizer{}).Optimize(t.Context(), inputs)
	if err != nil || len(groups) != len(inputs)-1 || !slices.Equal(groups[0].Inputs, []int{0, 1}) {
		t.Fatal("context index changed evaluation coordinates", groups, err)
	}
	for index, group := range groups[1:] {
		if !slices.Equal(group.Inputs, []int{index + 2}) {
			t.Fatal("context provenance order changed")
		}
	}
}

func TestOptimizerOverlappingBoxesAgainstTinyDomain(t *testing.T) {
	// Independent point membership covers all seven axes, including zero protocol,
	// overlapping boxes and both address families. No set operation computes want.
	for _, ipv6 := range []bool{false, true} {
		start := netip.MustParseAddr("192.0.2.0")
		if ipv6 {
			start = netip.MustParseAddr("2001:db8::")
		}
		addresses := []netip.Addr{start, start.Next(), start.Next().Next()}
		for seed := range uint64(8) {
			random := rand.New(rand.NewPCG(seed, 7))
			var declared []flow.TrafficRegion
			var inputs []policy.Request
			for range 12 {
				var low, high [7]uint16
				for axis := range 7 {
					a, b := uint16(random.IntN(3)), uint16(random.IntN(3))
					low[axis], high[axis] = min(a, b), max(a, b)
				}
				region := flow.TrafficRegion{Source: flow.AddressRange{First: addresses[low[0]], Last: addresses[high[0]]}, Destination: flow.AddressRange{First: addresses[low[1]], Last: addresses[high[1]]}, Protocol: flow.Interval{Low: low[2], High: high[2]}, SourcePort: flow.Interval{Low: low[3], High: high[3]}, DestinationPort: flow.Interval{Low: low[4], High: high[4]}, ICMPType: flow.Interval{Low: low[5], High: high[5]}, ICMPCode: flow.Interval{Low: low[6], High: high[6]}}
				declared = append(declared, region)
				inputs = append(inputs, policy.Request{Traffic: oracleMakeTraffic(t, region)})
			}
			groups, err := (analysis.RequestOptimizer{MaxComparisons: 1000000}).Optimize(t.Context(), inputs)
			if err != nil || len(groups) != 1 || len(groups[0].Inputs) != len(inputs) {
				t.Fatal(groups, err)
			}
			for point := range 2187 {
				var axes [7]uint16
				value := point
				for axis := range 7 {
					axes[axis] = uint16(value % 3)
					value /= 3
				}
				packet := oraclePacket{source: addresses[axes[0]], destination: addresses[axes[1]], protocol: axes[2], sourcePort: axes[3], destinationPort: axes[4], icmpType: axes[5], icmpCode: axes[6]}
				want := false
				for _, region := range declared {
					want = want || oracleRegion(region, packet)
				}
				if got := oracleTraffic(groups[0].Request.Traffic, packet); got != want {
					t.Fatalf("ipv6=%v seed=%d packet=%+v got=%v want=%v", ipv6, seed, packet, got, want)
				}
			}
			repeated, err := (analysis.RequestOptimizer{MaxComparisons: 1000000}).Optimize(t.Context(), []policy.Request{groups[0].Request})
			if err != nil || !slices.Equal(repeated[0].Request.Traffic.Regions(), groups[0].Request.Traffic.Regions()) {
				t.Fatal("optimizer did not reach deterministic fixed point", err)
			}
		}
	}
}
