package paloalto

import (
	"fmt"
	"net/netip"
	"slices"
	"strconv"

	fm "github.com/gatework/firemon"
)

func (t *topology) router(row row) bool {
	w := row.words
	if len(w) < 5 {
		return false
	}
	vrf := w[2]
	if w[3] == "interface" {
		for _, name := range values(w[4:]) {
			b := t.bindings[name]
			if b.vrf != "" && b.vrf != vrf {
				b.conflict = true
			} else {
				b.vrf = vrf
			}
			t.bindings[name] = b
		}
		return true
	}
	if len(w) < 9 || w[3] != "routing-table" || (w[4] != "ip" && w[4] != "ipv6") || w[5] != "static-route" {
		return false
	}
	name := w[6]
	family := w[4]
	key := fmt.Sprintf("static:%q:%q:%q", vrf, family, name)
	r := t.routes[key]
	if r.ID == "" {
		r.Object = object(name, row)
		r.ID = fm.ID(key)
		r.Scope = vrf
	} else {
		r.Spans = append(r.Spans, row.source.Span)
	}
	ok := routeField(&r, w[7:])
	if !ok {
		r.Unsupported = append(r.Unsupported, "unsupported route field "+w[7])
	}
	if r.Destination.IsValid() && r.Destination.Addr().Is6() != (family == "ipv6") {
		r.Unsupported = append(r.Unsupported, "destination address family differs from route table")
	}
	if r.NextHop.IsValid() && r.NextHop.Is6() != (family == "ipv6") {
		r.Unsupported = append(r.Unsupported, "next hop address family differs from route table")
	}
	t.routes[key] = r
	return ok
}

func routeField(r *fm.RouteRecord, w []string) bool {
	if len(w) < 2 {
		return false
	}
	switch w[0] {
	case "destination":
		if len(w) != 2 {
			return false
		}
		if v, err := hostPrefix(w[1]); err == nil {
			r.Destination = v.Masked()
			return true
		}
	case "interface":
		if len(w) == 2 {
			r.Interface = fm.ID(w[1])
			return true
		}
	case "nexthop":
		if len(w) == 3 && (w[1] == "ip-address" || w[1] == "ipv6-address") {
			if v, err := netip.ParseAddr(w[2]); err == nil {
				r.NextHop = v
				return true
			}
		}
	case "metric":
		if len(w) != 2 {
			return false
		}
		if v, err := strconv.ParseUint(w[1], 10, 32); err == nil {
			r.Metric = uint32(v)
			return true
		}
	case "route-table":
		return slices.Equal(w, []string{"route-table", "unicast"})
	case "bfd":
		return slices.Equal(w, []string{"bfd", "profile", "None"})
	case "path-monitor":
		return slices.Equal(w, []string{"path-monitor", "enable", "no"})
	}
	return false
}
