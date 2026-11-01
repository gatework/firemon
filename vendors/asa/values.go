package asa

import (
	"net"
	"net/netip"

	"strconv"
	"strings"

	fm "github.com/gatework/firemon"

	"github.com/gatework/firemon/flow"
)

func prefix(ip, mask string) (netip.Prefix, error) {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return netip.Prefix{}, err
	}
	if mask == "" {
		return netip.PrefixFrom(a, a.BitLen()), nil
	}
	m, err := netip.ParseAddr(mask)
	if err != nil || !a.Is4() || !m.Is4() {
		return netip.Prefix{}, flow.ErrRange
	}
	bytes := m.As4()
	ones, total := net.IPMask(bytes[:]).Size()
	if total != 32 {
		return netip.Prefix{}, flow.ErrRange
	}
	return netip.PrefixFrom(a, ones), nil
}
func iprange(value string) (flow.AddressRange, error) {
	parts := strings.Split(value, "-")
	if len(parts) == 2 {
		a, e := netip.ParseAddr(parts[0])
		b, e2 := netip.ParseAddr(parts[1])
		r := flow.AddressRange{First: a, Last: b}
		if e != nil || e2 != nil || !r.Valid() {
			return flow.AddressRange{}, flow.ErrRange
		}
		return r, nil
	}
	if strings.Contains(value, "/") {
		p, e := netip.ParsePrefix(value)
		if e != nil {
			return flow.AddressRange{}, e
		}
		return flow.PrefixRange(p)
	}
	p, e := prefix(value, "")
	if e != nil {
		return flow.AddressRange{}, e
	}
	return flow.PrefixRange(p)
}

func protocol(value string) (uint16, bool) {
	if n, ok := map[string]uint16{"ip": 0, "icmp": 1, "tcp": 6, "udp": 17, "gre": 47, "esp": 50, "ah": 51, "icmp6": 58, "sctp": 132}[value]; ok {
		return n, true
	}
	n, err := strconv.ParseUint(value, 10, 8)
	return uint16(n), err == nil
}
func portNumber(value string) (uint16, bool) {
	if n, ok := map[string]uint16{"http": 80, "www": 80, "https": 443, "ssh": 22, "domain": 53, "smtp": 25, "ftp": 21}[value]; ok {
		return n, true
	}
	n, err := strconv.ParseUint(value, 10, 16)
	return uint16(n), err == nil
}
func portSpec(words []string) ([]flow.Interval, int, bool) {
	if len(words) < 2 {
		return nil, 0, false
	}
	a, ok := portNumber(words[1])
	if !ok {
		return nil, 0, false
	}
	switch words[0] {
	case "eq":
		return []flow.Interval{{Low: a, High: a}}, 2, true
	case "range":
		if len(words) < 3 {
			return nil, 0, false
		}
		b, ok := portNumber(words[2])
		return []flow.Interval{{Low: a, High: b}}, 3, ok && a <= b
	case "lt":
		if a == 0 {
			return nil, 0, false
		}
		return []flow.Interval{{Low: 0, High: a - 1}}, 2, true
	case "gt":
		if a == 65535 {
			return nil, 0, false
		}
		return []flow.Interval{{Low: a + 1, High: 65535}}, 2, true
	case "neq":
		var result []flow.Interval
		if a > 0 {
			result = append(result, flow.Interval{Low: 0, High: a - 1})
		}
		if a < 65535 {
			result = append(result, flow.Interval{Low: a + 1, High: 65535})
		}
		return result, 2, true
	}
	return nil, 0, false
}
func term(proto uint16, source, destination flow.Interval) fm.ServiceTerm {
	return fm.ServiceTerm{Protocol: flow.Interval{Low: proto, High: proto}, SourcePort: source, DestinationPort: destination, ICMPType: flow.Interval{Low: 0, High: 255}, ICMPCode: flow.Interval{Low: 0, High: 255}}
}
