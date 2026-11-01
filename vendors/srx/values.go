package srx

import (
	"fmt"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/flow"
)

func begins(words []string, prefix ...string) bool {
	return len(words) >= len(prefix) && slices.Equal(words[:len(prefix)], prefix)
}
func nativeID(kind string, parts ...string) fm.ID {
	for i := range parts {
		parts[i] = url.PathEscape(parts[i])
	}
	return fm.ID(kind + ":" + strings.Join(parts, "/"))
}
func addressID(scope, name string) fm.ID {
	if scope == "" {
		return fm.ID(name)
	}
	return nativeID("address", scope, name)
}
func touch(object *fm.Object, row config.Statement) { object.Spans = append(object.Spans, row.Span) }
func unique[T comparable](values []T, value T) []T {
	if !slices.Contains(values, value) {
		return append(values, value)
	}
	return values
}

// A display-set leaf has one argument or a fully delimited native list. Unknown
// punctuation is retained as pending rather than silently stripped.
func list(words []string) ([]string, bool) {
	if len(words) == 1 && words[0] != "[" && words[0] != "]" {
		return words, true
	}
	if len(words) < 3 || words[0] != "[" || words[len(words)-1] != "]" {
		return nil, false
	}
	for _, w := range words[1 : len(words)-1] {
		if w == "[" || w == "]" {
			return nil, false
		}
	}
	return words[1 : len(words)-1], true
}
func prefix(value string) (netip.Prefix, error) {
	if strings.Contains(value, "/") {
		return netip.ParsePrefix(value)
	}
	a, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}
func addressRange(value string) (flow.AddressRange, error) {
	p, err := prefix(value)
	if err != nil {
		return flow.AddressRange{}, err
	}
	if p != p.Masked() {
		return flow.AddressRange{}, fmt.Errorf("unaligned address prefix %s", p)
	}
	return flow.PrefixRange(p)
}
func ports(value string) (flow.Interval, bool) {
	if value == "any" {
		return flow.Interval{High: 65535}, true
	}
	ends := strings.Split(value, "-")
	if len(ends) > 2 {
		return flow.Interval{}, false
	}
	a, err := strconv.ParseUint(ends[0], 10, 16)
	if err != nil {
		return flow.Interval{}, false
	}
	b := a
	if len(ends) == 2 {
		b, err = strconv.ParseUint(ends[1], 10, 16)
	}
	return flow.Interval{Low: uint16(a), High: uint16(b)}, err == nil && a <= b
}
func protocol(value string) (uint16, bool) {
	switch value {
	case "tcp":
		return 6, true
	case "udp":
		return 17, true
	case "icmp":
		return 1, true
	case "icmp6":
		return 58, true
	case "sctp":
		return 132, true
	case "gre":
		return 47, true
	case "esp":
		return 50, true
	case "ah":
		return 51, true
	}
	n, err := strconv.ParseUint(value, 10, 8)
	return uint16(n), err == nil
}
func diagnostic(code, message string) fm.Diagnostic {
	return fm.Diagnostic{Code: code, Message: message}
}
