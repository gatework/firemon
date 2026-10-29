package flow_test

import (
	"errors"
	"testing"

	"github.com/gatework/firemon/flow"
)

func box(src, dst string) flow.Box {
	return flow.Box{Source: iprange(src, src), Destination: iprange(dst, dst), Protocol: flow.Interval{Low: 6, High: 6}, SourcePort: flow.Interval{Low: 0, High: 65535}, DestinationPort: flow.Interval{Low: 443, High: 443}, ICMPType: flow.Interval{Low: 0, High: 255}, ICMPCode: flow.Interval{Low: 0, High: 255}}
}
func TestTrafficUnionDoesNotInventCrossPairs(t *testing.T) {
	a, b := box("192.0.2.1", "198.51.100.1"), box("192.0.2.2", "198.51.100.2")
	s, err := flow.NewTraffic(32, a, b)
	if err != nil {
		t.Fatal(err)
	}
	cross, err := flow.NewTraffic(32, box("192.0.2.1", "198.51.100.2"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.Intersection(cross, 32)
	if err != nil || !got.Empty() {
		t.Fatalf("invented pair: %v %v", got, err)
	}
}
func TestTrafficDifferenceSplitsBothDimensionsExactly(t *testing.T) {
	full := box("192.0.2.1", "198.51.100.1")
	full.Source.Last = address("192.0.2.2")
	full.Destination.Last = address("198.51.100.2")
	s, _ := flow.NewTraffic(32, full)
	diagonal, _ := flow.NewTraffic(32, box("192.0.2.1", "198.51.100.1"), box("192.0.2.2", "198.51.100.2"))
	got, err := s.Difference(diagonal, 32)
	if err != nil {
		t.Fatal(err)
	}
	for i, src := range []string{"192.0.2.1", "192.0.2.2"} {
		for j, dst := range []string{"198.51.100.1", "198.51.100.2"} {
			q, _ := flow.NewTraffic(32, box(src, dst))
			hit, err := got.Intersection(q, 32)
			if err != nil || hit.Empty() != (i == j) {
				t.Fatalf("%d,%d: %v %v", i, j, hit, err)
			}
		}
	}
	if _, err := s.Difference(diagonal, 1); !errors.Is(err, flow.ErrBudget) {
		t.Fatalf("expected budget failure, got %v", err)
	}
}
func TestTrafficProtocolZeroIsNotAny(t *testing.T) {
	a := box("192.0.2.1", "198.51.100.1")
	b := a
	a.Protocol = flow.Interval{Low: 0, High: 0}
	x, _ := flow.NewTraffic(8, a)
	y, _ := flow.NewTraffic(8, b)
	got, err := x.Intersection(y, 8)
	if err != nil || !got.Empty() {
		t.Fatalf("protocol zero became any: %v %v", got, err)
	}
}
