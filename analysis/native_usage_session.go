package analysis

import (
	"context"
	"encoding/json"
	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func usageRuleKey(name, from, to string) string {
	b, _ := json.Marshal([3]string{name, from, to})
	return string(b)
}

var srxSession = regexp.MustCompile(`\bsession created (\S+)/(\d+)->(\S+)/(\d+)(?:\s+\S+){4}\s+(\d+)\s+(\S+)\s+(\S+)\s+(\S+)(?:\s|$)`)

type nativeSession struct {
	at      time.Time
	key     string
	traffic flow.TrafficRegion
}

func parseSession(vendor, raw string) (nativeSession, string) {
	var out nativeSession
	stamp, _, ok := strings.Cut(strings.TrimSpace(raw), " ")
	if !ok {
		return out, "missing_timestamp"
	}
	at, err := time.Parse(time.RFC3339Nano, stamp)
	if err != nil {
		return out, "missing_timestamp_or_timezone"
	}
	out.at = at.UTC()
	var src, dst, sport, dport, proto string
	if vendor == "srx" {
		m := srxSession.FindStringSubmatch(raw)
		if m == nil {
			return out, "unrecognized_record"
		}
		src, sport, dst, dport, proto = m[1], m[2], m[3], m[4], m[5]
		out.key = usageRuleKey(m[6], m[7], m[8])
	} else {
		fields := map[string]string{}
		for word := range strings.FieldsSeq(raw) {
			if k, v, ok := strings.Cut(word, "="); ok {
				if _, exists := fields[k]; exists {
					return out, "repeated_field"
				}
				fields[k] = v
			}
		}
		src, dst, sport, dport, proto = fields["src"], fields["dst"], fields["src_port"], fields["dst_port"], fields["proto"]
		out.key = fields["policy_id"]
		if out.key == "" {
			return out, "unrecognized_record"
		}
	}
	a, e1 := netip.ParseAddr(src)
	b, e2 := netip.ParseAddr(dst)
	sp, e3 := strconv.ParseUint(sport, 10, 16)
	dp, e4 := strconv.ParseUint(dport, 10, 16)
	p, e5 := strconv.ParseUint(proto, 10, 8)
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || e5 != nil || a.Is4() != b.Is4() || a.Zone() != "" || b.Zone() != "" {
		return out, "incomplete_tuple"
	}
	if p != 6 && p != 17 {
		return out, "unsupported_protocol"
	}
	out.traffic = flow.TrafficRegion{Source: flow.AddressRange{First: a, Last: a}, Destination: flow.AddressRange{First: b, Last: b}, Protocol: flow.Interval{Low: uint16(p), High: uint16(p)}, SourcePort: flow.Interval{Low: uint16(sp), High: uint16(sp)}, DestinationPort: flow.Interval{Low: uint16(dp), High: uint16(dp)}, ICMPType: flow.Interval{High: 255}, ICMPCode: flow.Interval{High: 255}}
	return out, ""
}
func (u NativeUsage) memberMatches(ctx context.Context, fw *fm.Firewall, m MemberIdentity, t flow.TrafficRegion) (bool, error) {
	switch m.Role {
	case Source, Destination:
		refs := []fm.AddressRef{{Kind: m.Kind, ID: m.ID}}
		set, known, err := u.Engine.ResolveAddresses(ctx, fw, refs, false)
		if err != nil || !known {
			return false, err
		}
		address := t.Source.First
		if m.Role == Destination {
			address = t.Destination.First
		}
		return set.ContainsAddr(address), nil
	case Service:
		terms, known, err := u.Engine.ResolveServices(ctx, fw, []fm.ServiceRef{{Kind: m.Kind, ID: m.ID}}, false)
		if err != nil || !known {
			return false, err
		}
		for _, s := range terms {
			contains := true
			for _, p := range [][2]flow.Interval{{s.Protocol, t.Protocol}, {s.SourcePort, t.SourcePort}, {s.DestinationPort, t.DestinationPort}, {s.ICMPType, t.ICMPType}, {s.ICMPCode, t.ICMPCode}} {
				contains = contains && p[0].Low <= p[1].Low && p[0].High >= p[1].High
			}
			if contains {
				return true, nil
			}
		}
	}
	return false, nil
}
