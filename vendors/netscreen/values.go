package netscreen

import (
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"

	fm "github.com/gatework/firemon"

	"github.com/gatework/firemon/flow"
)

func begins(w []string, prefix ...string) bool {
	return len(w) >= len(prefix) && slices.Equal(w[:len(prefix)], prefix)
}
func unique[T comparable](in []T, v T) []T {
	if !slices.Contains(in, v) {
		return append(in, v)
	}
	return in
}
func nativeID(kind string, parts ...string) fm.ID {
	for i := range parts {
		parts[i] = url.PathEscape(parts[i])
	}
	return fm.ID(kind + ":" + strings.Join(parts, "/"))
}
func addressScope(zone string) string {
	if zone == "Global" {
		return ""
	}
	return "zone:" + zone
}
func addressID(scope, name string) fm.ID {
	if scope == "" {
		return fm.ID(name)
	}
	return nativeID("address", scope, name)
}
func touch(o *fm.Object, r row) { o.Spans = append(o.Spans, r.Span) }
func object(id fm.ID, name, scope string) fm.Object {
	return fm.Object{ID: id, Name: name, Scope: scope}
}

func prefix(w []string) (netip.Prefix, int, bool) {
	if len(w) == 0 {
		return netip.Prefix{}, 0, false
	}
	if strings.Contains(w[0], "/") {
		p, e := netip.ParsePrefix(w[0])
		return p, 1, e == nil && p.Addr().Is4()
	}
	a, e := netip.ParseAddr(w[0])
	if e != nil || !a.Is4() || len(w) < 2 {
		return netip.Prefix{}, 0, false
	}
	mask, e := netip.ParseAddr(w[1])
	if e != nil || !mask.Is4() {
		return netip.Prefix{}, 0, false
	}
	bytes := mask.As4()
	bits, zero := 0, false
	for _, b := range bytes {
		for bit := 7; bit >= 0; bit-- {
			if b&(1<<bit) == 0 {
				zero = true
			} else {
				if zero {
					return netip.Prefix{}, 0, false
				}
				bits++
			}
		}
	}
	return netip.PrefixFrom(a, bits), 2, true
}
func ports(value string) (flow.Interval, bool) {
	parts := strings.Split(value, "-")
	if len(parts) > 2 {
		return flow.Interval{}, false
	}
	a, e := strconv.ParseUint(parts[0], 10, 16)
	if e != nil {
		return flow.Interval{}, false
	}
	b := a
	if len(parts) == 2 {
		b, e = strconv.ParseUint(parts[1], 10, 16)
	}
	return flow.Interval{Low: uint16(a), High: uint16(b)}, e == nil && a <= b
}
func protocol(value string) (uint16, bool) {
	switch value {
	case "tcp":
		return 6, true
	case "udp":
		return 17, true
	case "icmp":
		return 1, true
	}
	n, e := strconv.ParseUint(value, 10, 8)
	return uint16(n), e == nil
}

func invalid(id fm.ID, message string) fm.Diagnostic {
	return fm.Diagnostic{Object: id, Code: "unsupported-native", Message: message}
}
func policyID(value string) (fm.ID, bool) {
	n, e := strconv.ParseUint(value, 10, 32)
	return fm.ID(value), e == nil && n > 0 && n < 320000 && strconv.FormatUint(n, 10) == value
}
