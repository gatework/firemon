package paloalto

import (
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	fm "github.com/gatework/firemon"

	"github.com/gatework/firemon/flow"
)

func values(w []string) []string {
	out := make([]string, 0, len(w))
	for _, v := range w {
		if v != "[" && v != "]" {
			out = append(out, v)
		}
	}
	return out
}
func object(name string, r row) fm.Object {
	return fm.Object{ID: fm.ID(name), Name: name, Spans: []fm.Span{r.source.Span}}
}
func address(value string) (flow.AddressRange, error) {
	if parts := strings.Split(value, "-"); len(parts) == 2 {
		a, e := netip.ParseAddr(parts[0])
		b, e2 := netip.ParseAddr(parts[1])
		r := flow.AddressRange{First: a, Last: b}
		if e != nil || e2 != nil || !r.Valid() {
			return flow.AddressRange{}, flow.ErrRange
		}
		return r, nil
	}
	p, err := hostPrefix(value)
	if err != nil {
		return flow.AddressRange{}, err
	}
	return flow.PrefixRange(p)
}
func hostPrefix(value string) (netip.Prefix, error) {
	if strings.Contains(value, "/") {
		return netip.ParsePrefix(value)
	}
	a, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}
func ports(value string) ([]flow.Interval, error) {
	var out []flow.Interval
	for _, part := range strings.Split(value, ",") {
		ends := strings.Split(part, "-")
		if len(ends) > 2 {
			return nil, fmt.Errorf("invalid ports")
		}
		lo, err := strconv.ParseUint(ends[0], 10, 16)
		if err != nil {
			return nil, err
		}
		hi := lo
		if len(ends) == 2 {
			hi, err = strconv.ParseUint(ends[1], 10, 16)
			if err != nil {
				return nil, err
			}
		}
		if lo > hi {
			return nil, fmt.Errorf("reversed port interval")
		}
		out = append(out, flow.Interval{Low: uint16(lo), High: uint16(hi)})
	}
	return out, nil
}
func serviceTerms(protocol string, src, dst []flow.Interval) []fm.ServiceTerm {
	var terms []fm.ServiceTerm
	n := map[string]uint16{"tcp": 6, "udp": 17}[protocol]
	for _, a := range src {
		for _, b := range dst {
			terms = append(terms, fm.ServiceTerm{Protocol: flow.Interval{Low: n, High: n}, SourcePort: a, DestinationPort: b, ICMPType: flow.Interval{Low: 0, High: 255}, ICMPCode: flow.Interval{Low: 0, High: 255}})
		}
	}
	return terms
}
func keys[T any](m map[string]T) []string {
	out := make([]string, 0, len(m))
	for key := range m {
		out = append(out, key)
	}
	slices.Sort(out)
	return out
}
