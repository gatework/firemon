package hillstone

import (
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
)

func prefix(words []string) (netip.Prefix, error) {
	if len(words) == 0 {
		return netip.Prefix{}, fmt.Errorf("missing prefix")
	}
	if strings.Contains(words[0], "/") {
		return netip.ParsePrefix(words[0])
	}
	a, err := netip.ParseAddr(words[0])
	if err != nil {
		return netip.Prefix{}, err
	}
	bits := a.BitLen()
	if len(words) > 1 {
		mask, err := netip.ParseAddr(words[1])
		if err != nil || !mask.Is4() || !a.Is4() {
			return netip.Prefix{}, fmt.Errorf("invalid netmask")
		}
		b := mask.As4()
		ones, total := net.IPMask(b[:]).Size()
		if total != 32 {
			return netip.Prefix{}, fmt.Errorf("noncontiguous mask")
		}
		bits = ones
	}
	return netip.PrefixFrom(a, bits), nil
}
func literal(value string) (flow.AddressRange, error) {
	if parts := strings.Split(value, "-"); len(parts) == 2 {
		a, e := netip.ParseAddr(parts[0])
		b, e2 := netip.ParseAddr(parts[1])
		r := flow.AddressRange{First: a, Last: b}
		if e != nil || e2 != nil || !r.Valid() {
			return flow.AddressRange{}, flow.ErrRange
		}
		return r, nil
	}
	v, err := prefix([]string{value})
	if err != nil {
		return flow.AddressRange{}, err
	}
	return flow.PrefixRange(v)
}
func number(value string, max int) (uint16, bool) {
	v, err := strconv.Atoi(value)
	return uint16(v), err == nil && v >= 0 && v <= max
}
func port(words []string) (flow.Interval, bool) {
	if len(words) < 1 || len(words) > 2 {
		return flow.Interval{}, false
	}
	a, ok := number(words[0], 65535)
	b := a
	if len(words) == 2 {
		var valid bool
		b, valid = number(words[1], 65535)
		ok = ok && valid
	}
	return flow.Interval{Low: a, High: b}, ok && a <= b
}
func term(w []string) (fm.ServiceTerm, bool) {
	full := flow.Interval{Low: 0, High: 65535}
	octet := flow.Interval{Low: 0, High: 255}
	r := fm.ServiceTerm{SourcePort: full, DestinationPort: full, ICMPType: octet, ICMPCode: octet}
	if len(w) == 2 && w[0] == "protocol" {
		n, ok := number(w[1], 255)
		r.Protocol = flow.Interval{Low: n, High: n}
		return r, ok
	}
	if len(w) == 1 && w[0] == "icmp" {
		r.Protocol = flow.Interval{Low: 1, High: 1}
		return r, true
	}
	if len(w) < 3 || w[1] != "dst-port" {
		return r, false
	}
	protocols := map[string]uint16{"tcp": 6, "udp": 17, "sctp": 132}
	protocol, ok := protocols[w[0]]
	if !ok {
		return r, false
	}
	r.Protocol = flow.Interval{Low: protocol, High: protocol}
	split := slices.Index(w, "src-port")
	end := len(w)
	if split >= 0 {
		end = split
	}
	r.DestinationPort, ok = port(w[2:end])
	if split >= 0 {
		var valid bool
		r.SourcePort, valid = port(w[split+1:])
		ok = ok && valid
	}
	return r, ok
}
