package servicecoverage_test

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"slices"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/internal/servicecoverage"
)

// Enumerate all 32 packets of a two-value, five-dimensional service domain.
// Membership uses integer comparisons, independently of flow's slab algorithm.
func servicePackets(terms []fm.ServiceTerm) [32]bool {
	var packets [32]bool
	for packet := range packets {
		for _, term := range terms {
			intervals := [...]flow.Interval{term.Protocol, term.SourcePort, term.DestinationPort, term.ICMPType, term.ICMPCode}
			matched := true
			for axis, interval := range intervals {
				value := uint16(packet >> axis & 1)
				matched = matched && interval.Low <= value && value <= interval.High
			}
			packets[packet] = packets[packet] || matched
		}
	}
	return packets
}

func FuzzCoverageAgainstServicePackets(f *testing.F) {
	f.Add(uint64(0x123456789abcdef), uint64(0xfedcba987654321))
	f.Add(uint64(0), ^uint64(0))
	f.Fuzz(func(t *testing.T, first, second uint64) {
		terms := func(seed uint64) []fm.ServiceTerm {
			out := make([]fm.ServiceTerm, 3)
			for i := range out {
				var bounds [5]flow.Interval
				for axis := range bounds {
					a, b := uint16(seed&1), uint16(seed>>1&1)
					seed >>= 2
					bounds[axis] = flow.Interval{Low: min(a, b), High: max(a, b)}
				}
				out[i] = fm.ServiceTerm{Protocol: bounds[0], SourcePort: bounds[1], DestinationPort: bounds[2], ICMPType: bounds[3], ICMPCode: bounds[4]}
			}
			return out
		}
		a, b := terms(first), terms(second)
		original := slices.Clone(a)
		coverage, err := servicecoverage.FromTerms(context.Background(), a, 4096)
		if err != nil {
			t.Fatal(err)
		}
		requested, err := servicecoverage.FromTerms(context.Background(), b, 4096)
		if err != nil {
			t.Fatal(err)
		}
		actualPackets, requestedPackets := servicePackets(a), servicePackets(b)
		wantContains := true
		for packet := range actualPackets {
			wantContains = wantContains && (!requestedPackets[packet] || actualPackets[packet])
		}
		contained, err := coverage.Contains(requested, 4096)
		if err != nil || contained != wantContains {
			t.Fatalf("service containment=%v, %v; want %v", contained, err, wantContains)
		}
		var regions []flow.TrafficRegion
		for i, term := range a {
			address := netip.MustParseAddr("192.0.2.1")
			if i%2 == 1 {
				address = netip.MustParseAddr("2001:db8::1")
			}
			regions = append(regions, flow.TrafficRegion{
				Source: flow.AddressRange{First: address, Last: address}, Destination: flow.AddressRange{First: address, Last: address},
				Protocol: term.Protocol, SourcePort: term.SourcePort, DestinationPort: term.DestinationPort,
				ICMPType: term.ICMPType, ICMPCode: term.ICMPCode,
			})
		}
		traffic, err := flow.NewTraffic(4096, regions...)
		if err != nil {
			t.Fatal(err)
		}
		projected, err := servicecoverage.FromTraffic(context.Background(), traffic, 4096)
		if err != nil {
			t.Fatal(err)
		}
		for _, result := range []flow.Traffic{coverage, projected} {
			var resultTerms []fm.ServiceTerm
			for _, region := range result.Regions() {
				if region.Source.First != netip.IPv4Unspecified() || region.Source.First != region.Source.Last || region.Source != region.Destination {
					t.Fatal("address context leaked into service projection")
				}
				resultTerms = append(resultTerms, fm.ServiceTerm{Protocol: region.Protocol, SourcePort: region.SourcePort, DestinationPort: region.DestinationPort, ICMPType: region.ICMPType, ICMPCode: region.ICMPCode})
			}
			if got := servicePackets(resultTerms); got != actualPackets {
				t.Fatalf("service tuple association changed: got %v, want %v", got, actualPackets)
			}
		}
		if !reflect.DeepEqual(a, original) {
			t.Fatal("input service terms mutated")
		}
	})
}

func TestCoverageFailuresReturnNoPartialTraffic(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, tc := range []struct {
		ctx   context.Context
		terms []fm.ServiceTerm
		limit int
		want  error
	}{
		{context.Background(), []fm.ServiceTerm{{}, {}}, 1, flow.ErrBudget},
		{context.Background(), []fm.ServiceTerm{{Protocol: flow.Interval{High: 256}}}, 1, flow.ErrRegion},
		{ctx, nil, 0, context.Canceled},
	} {
		got, err := servicecoverage.FromTerms(tc.ctx, tc.terms, tc.limit)
		if !errors.Is(err, tc.want) || !got.Empty() {
			t.Fatalf("partial service projection: %v, %v", got, err)
		}
	}
	traffic, _ := servicecoverage.FromTerms(context.Background(), []fm.ServiceTerm{{}}, 1)
	for _, tc := range []struct {
		ctx   context.Context
		limit int
		want  error
	}{
		{context.Background(), 0, flow.ErrBudget}, {ctx, 1, context.Canceled},
	} {
		got, err := servicecoverage.FromTraffic(tc.ctx, traffic, tc.limit)
		if !errors.Is(err, tc.want) || !got.Empty() {
			t.Fatalf("partial traffic projection: %v, %v", got, err)
		}
	}
}
