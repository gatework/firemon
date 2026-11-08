package policy_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/policy"
)

func preimagePacket(src, dst string, port uint16) flow.TrafficRegion {
	return flow.TrafficRegion{Source: rangeOf(src + "/32"), Destination: rangeOf(dst + "/32"), Protocol: flow.Interval{Low: 6, High: 6}, SourcePort: flow.Interval{Low: 1024, High: 1024}, DestinationPort: flow.Interval{Low: port, High: port}}
}

func preimageTraffic(t *testing.T, packets ...flow.TrafficRegion) flow.Traffic {
	t.Helper()
	got, err := flow.NewTraffic(4096, packets...)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func assertPreimage(t *testing.T, got, want flow.Traffic, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	if same, err := got.Equal(want, 4096); err != nil || !same {
		t.Fatalf("wire ownership differs: got=%v want=%v err=%v", got.Regions(), want.Regions(), err)
	}
}

func TestOriginalTrafficMatchesEnumeratedCompoundPermutation(t *testing.T) {
	// Enumerate actual tuples independently of the range mapper. The first
	// stage swaps two destinations but preserves the projected address set.
	permutation := []int{1, 0, 2, 3}
	d := migrationData("paloalto")
	d.StaticNATs = []fm.StaticNATRecord{
		{Object: fm.Object{ID: "permutation"}, Match: anyMatch(), Source: []fm.Mapping{{Original: rangeOf("192.0.2.0/30"), Translated: rangeOf("203.0.113.0/30"), Mode: fm.Offset}}, DestinationPorts: []fm.PortMapping{{Original: flow.Interval{Low: 100, High: 103}, Translated: flow.Interval{Low: 110, High: 113}, Mode: fm.Offset}}},
		{Object: fm.Object{ID: "backend"}, Match: anyMatch(), Destination: []fm.Mapping{{Original: rangeOf("198.51.100.0/30"), Translated: rangeOf("198.51.100.16/30"), Mode: fm.Offset}}, DestinationPorts: []fm.PortMapping{{Original: flow.Interval{Low: 110, High: 113}, Translated: flow.Interval{Low: 210, High: 213}, Mode: fm.Offset}}},
	}
	for from, to := range permutation {
		mode := fm.Offset
		if from == to {
			mode = fm.Identity
		}
		d.StaticNATs[0].Destination = append(d.StaticNATs[0].Destination, fm.Mapping{Original: rangeOf(fmt.Sprintf("198.51.100.%d/32", from)), Translated: rangeOf(fmt.Sprintf("198.51.100.%d/32", to)), Mode: mode})
	}
	fw := migrationGraph(t, d)
	var original, selected, expected []flow.TrafficRegion
	for src := range 4 {
		for dst := range 4 {
			for port := range 4 {
				if (src+dst+port)%3 != 0 {
					continue
				}
				packet := preimagePacket(fmt.Sprintf("192.0.2.%d", src), fmt.Sprintf("198.51.100.%d", dst), uint16(100+port))
				original = append(original, packet)
				if permutation[dst]%2 == port%2 {
					expected = append(expected, packet)
					selected = append(selected, preimagePacket(fmt.Sprintf("192.0.2.%d", src), fmt.Sprintf("198.51.100.%d", 16+permutation[dst]), uint16(210+port)))
				}
			}
		}
	}
	path := policy.PacketPath{Original: preimageTraffic(t, original...), PolicyNAT: []policy.NATStep{{Kind: fm.StaticNATObject, ID: "permutation"}, {Kind: fm.StaticNATObject, ID: "backend"}}}
	got, err := (policy.Engine{}).OriginalTraffic(t.Context(), fw, path, preimageTraffic(t, selected...))
	assertPreimage(t, got, preimageTraffic(t, expected...), err)
	if _, err := (policy.Engine{Limits: policy.Limits{MaxCombinations: 1}}).OriginalTraffic(t.Context(), fw, path, preimageTraffic(t, selected...)); !errors.Is(err, policy.ErrBudget) {
		t.Fatal("compound stages escaped their bound", err)
	}
}

func TestOriginalTrafficRestrictsConstantsToEstablishedTuples(t *testing.T) {
	d := migrationData("paloalto")
	d.StaticNATs[0].Source = nil
	d.StaticNATs[0].Destination = []fm.Mapping{{Original: rangeOf("198.51.100.0/29"), Translated: rangeOf("203.0.113.10/32"), Mode: fm.Constant}}
	d.StaticNATs[0].DestinationPorts = []fm.PortMapping{{Original: flow.Interval{Low: 100, High: 103}, Translated: flow.Interval{Low: 443, High: 443}, Mode: fm.Constant}}
	fw := migrationGraph(t, d)
	a := preimagePacket("192.0.2.1", "198.51.100.1", 101)
	b := preimagePacket("192.0.2.1", "198.51.100.4", 103)
	c := preimagePacket("192.0.2.2", "198.51.100.2", 102)
	path := policy.PacketPath{Original: preimageTraffic(t, a, b, c), PolicyNAT: []policy.NATStep{{Kind: fm.StaticNATObject, ID: "snat"}}}
	selected := preimageTraffic(t, preimagePacket("192.0.2.1", "203.0.113.10", 443))
	got, err := (policy.Engine{}).OriginalTraffic(t.Context(), fw, path, selected)
	assertPreimage(t, got, preimageTraffic(t, a, b), err)
	outside := preimageTraffic(t, preimagePacket("192.0.2.3", "203.0.113.10", 443))
	if got, err := (policy.Engine{}).OriginalTraffic(t.Context(), fw, path, outside); !errors.Is(err, policy.ErrNAT) || !got.Empty() {
		t.Fatal("constant mapping invented an unestablished source", got, err)
	}
	if got, err := (policy.Engine{Limits: policy.Limits{MaxRegions: 1}}).OriginalTraffic(t.Context(), fw, path, selected); !errors.Is(err, policy.ErrBudget) || !got.Empty() {
		t.Fatal("original input escaped region bound", got, err)
	}
}

func TestOriginalTrafficRejectsUnknownMappingsAndPreflightsWork(t *testing.T) {
	d := migrationData("paloalto")
	d.StaticNATs[0].Source = nil
	d.StaticNATs[0].Destination = []fm.Mapping{{Original: rangeOf("198.51.100.10/32"), Translated: rangeOf("203.0.113.10/32"), Mode: fm.Offset}}
	path := policy.PacketPath{Original: preimageTraffic(t, preimagePacket("192.0.2.1", "198.51.100.10", 443)), PolicyNAT: []policy.NATStep{{Kind: fm.StaticNATObject, ID: "snat"}}}
	selected := preimageTraffic(t, preimagePacket("192.0.2.1", "203.0.113.10", 443))
	fw := migrationGraph(t, d)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if got, err := (policy.Engine{}).OriginalTraffic(ctx, fw, path, selected); !errors.Is(err, context.Canceled) || !got.Empty() {
		t.Fatal("canceled inverse returned traffic", got, err)
	}
	d.StaticNATs[0].Spans = make([]fm.Span, 1000)
	if got, err := (policy.Engine{Limits: policy.Limits{MaxVisits: 50}}).OriginalTraffic(t.Context(), migrationGraph(t, d), path, selected); !errors.Is(err, policy.ErrBudget) || !got.Empty() {
		t.Fatal("nested declaration copy escaped preflight", got, err)
	}
	d.StaticNATs[0].Destination[0].Mode = fm.UnknownMapping
	fw, err := fm.Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := (policy.Engine{}).OriginalTraffic(t.Context(), fw, path, selected); !errors.Is(err, policy.ErrNAT) || !got.Empty() {
		t.Fatal("unknown mapping acquired an inverse", got, err)
	}
	d.StaticNATs = nil
	d.NATPools = []fm.NATPoolRecord{{Object: fm.Object{ID: "pool"}, Ranges: []flow.AddressRange{rangeOf("203.0.113.0/29")}}}
	d.DynamicNATs = []fm.DynamicNATRecord{{Object: fm.Object{ID: "allocation"}, Match: anyMatch(), SourceMode: fm.NoTranslation, DestinationMode: fm.DynamicIP, DestinationPool: "pool"}}
	path.PolicyNAT[0] = policy.NATStep{Kind: fm.DynamicNATObject, ID: "allocation"}
	if got, err := (policy.Engine{}).OriginalTraffic(t.Context(), migrationGraph(t, d), path, selected); !errors.Is(err, policy.ErrNAT) || !got.Empty() {
		t.Fatal("unproved destination allocation acquired an inverse", got, err)
	}
}
