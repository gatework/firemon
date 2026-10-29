package analysis_test

import (
	"context"
	"errors"
	"net/netip"
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
