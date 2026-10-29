package flow

import "net/netip"

// AllTraffic returns every IPv4 and IPv6 packet as two same-family regions.
// Protocol, both ports and ICMP type/code include their full valid intervals.
// A limit below two returns ErrBudget and no partial traffic.
func AllTraffic(limit int) (Traffic, error) {
	var regions []TrafficRegion
	for _, cidr := range []string{"0.0.0.0/0", "::/0"} {
		addresses, err := PrefixRange(netip.MustParsePrefix(cidr))
		if err != nil {
			return Traffic{}, err
		}
		regions = append(regions, TrafficRegion{
			Source: addresses, Destination: addresses, Protocol: Interval{High: 255},
			SourcePort: Interval{High: 65535}, DestinationPort: Interval{High: 65535},
			ICMPType: Interval{High: 255}, ICMPCode: Interval{High: 255},
		})
	}
	return NewTraffic(limit, regions...)
}
