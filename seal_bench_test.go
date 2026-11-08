package firemon_test

import (
	"fmt"
	"net/netip"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
)

// sealBenchmarkData builds a synthetic documentation-range graph with n
// addresses and rules, next-hop routes over many interfaces, grouped members
// and multi-mapping static NATs, so Seal's binding and validation work scale.
func sealBenchmarkData(n int) fm.Data {
	host := func(i int) netip.Addr { return netip.AddrFrom4([4]byte{198, 18, byte(i >> 8), byte(i)}) }
	d := fm.Data{Metadata: fm.Metadata{Device: "synthetic-benchmark", Vendor: "huawei"}}
	d.Zones = []fm.ZoneRecord{{Object: fm.Object{ID: "inside"}}, {Object: fm.Object{ID: "outside"}}}
	const interfaces = 64
	for i := range interfaces {
		d.Interfaces = append(d.Interfaces, fm.InterfaceRecord{
			Object:    fm.Object{ID: fm.ID(fmt.Sprintf("if-%d", i))},
			Zone:      d.Zones[i%2].ID,
			Addresses: []netip.Prefix{netip.PrefixFrom(netip.AddrFrom4([4]byte{203, 0, byte(i), 1}), 24)},
		})
	}
	for i := range n / 4 {
		d.Routes = append(d.Routes, fm.RouteRecord{
			Object:      fm.Object{ID: fm.ID(fmt.Sprintf("route-%d", i))},
			Destination: netip.PrefixFrom(host(i), 32),
			NextHop:     netip.AddrFrom4([4]byte{203, 0, byte(i % interfaces), 254}),
		})
	}
	d.Services = []fm.ServiceRecord{{Object: fm.Object{ID: "web"}, Terms: []fm.ServiceTerm{{
		Protocol:        flow.Interval{Low: 6, High: 6},
		SourcePort:      flow.Interval{High: 65535},
		DestinationPort: flow.Interval{Low: 443, High: 443},
	}}}}
	var members []fm.AddressRef
	for i := range n {
		id := fm.ID(fmt.Sprintf("host-%d", i))
		d.Addresses = append(d.Addresses, fm.AddressRecord{Object: fm.Object{ID: id}, Ranges: []flow.AddressRange{{First: host(i), Last: host(i)}}})
		members = append(members, fm.AddressRef{Kind: fm.AddressObject, ID: id})
		d.Rules = append(d.Rules, fm.RuleRecord{
			Object:   fm.Object{ID: fm.ID(fmt.Sprintf("rule-%d", i))},
			Position: n - i,
			Action:   fm.Permit,
			Match: fm.Match{
				Sources:        []fm.AddressRef{{Kind: fm.AddressObject, ID: id}},
				AnyDestination: true,
				Services:       []fm.ServiceRef{{Kind: fm.ServiceObject, ID: "web"}},
				FromZones:      []fm.ID{"inside"},
				ToZones:        []fm.ID{"outside"},
			},
		})
	}
	d.AddressGroups = []fm.AddressGroupRecord{{Object: fm.Object{ID: "all-hosts"}, Members: members}}
	for i := range n / 8 {
		var mappings []fm.Mapping
		for j := range 8 {
			first := host(i*8 + j)
			mappings = append(mappings, fm.Mapping{
				Original:   flow.AddressRange{First: first, Last: first},
				Translated: flow.AddressRange{First: netip.AddrFrom4([4]byte{192, 0, 2, byte(j)}), Last: netip.AddrFrom4([4]byte{192, 0, 2, byte(j)})},
				Mode:       fm.Offset,
			})
		}
		d.StaticNATs = append(d.StaticNATs, fm.StaticNATRecord{
			Object:      fm.Object{ID: fm.ID(fmt.Sprintf("snat-%d", i))},
			Order:       fm.NATOrder{Position: n - i},
			Destination: mappings,
			DestinationPorts: []fm.PortMapping{{
				Original:   flow.Interval{Low: 443, High: 443},
				Translated: flow.Interval{Low: 8443, High: 8443},
				Mode:       fm.Offset,
			}},
			Match: fm.Match{AnySource: true, AnyDestination: true, AnyService: true},
		})
	}
	return d
}

func TestSealBenchmarkDataIsComplete(t *testing.T) {
	fw, err := fm.Seal(sealBenchmarkData(64))
	if err != nil {
		t.Fatal(err)
	}
	if !fw.Complete() {
		t.Fatal(fw.Diagnostics())
	}
	for _, r := range fw.Routes() {
		if r.Interface() == nil {
			t.Fatalf("route %s did not bind its next-hop interface", r.ID())
		}
	}
}

func BenchmarkSeal(b *testing.B) {
	for _, n := range []int{256, 4096} {
		data := sealBenchmarkData(n)
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if _, err := fm.Seal(data); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
