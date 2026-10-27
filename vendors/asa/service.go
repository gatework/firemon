package asa

import (
	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
)

// serviceDefinition consumes the entire native definition. A recognized protocol
// never authorizes dropping an unrecognized port condition or suffix.
func serviceDefinition(words []string) ([]fm.ServiceTerm, bool) {
	if len(words) == 0 {
		return nil, false
	}
	full := flow.Interval{High: 65535}
	var protocols []flow.Interval
	if words[0] == "tcp-udp" {
		protocols = []flow.Interval{{Low: 6, High: 6}, {Low: 17, High: 17}}
	} else {
		n, ok := protocol(words[0])
		if !ok {
			return nil, false
		}
		p := flow.Interval{Low: n, High: n}
		if words[0] == "ip" {
			p = flow.Interval{High: 255}
		}
		protocols = []flow.Interval{p}
	}
	source, destination := []flow.Interval{full}, []flow.Interval{full}
	rest := words[1:]
	for _, axis := range []string{"source", "destination"} {
		if len(rest) == 0 || rest[0] != axis {
			continue
		}
		// Port qualifiers are defined only for transport protocols.
		for _, p := range protocols {
			if p.Low != p.High || (p.Low != 6 && p.Low != 17 && p.Low != 132) {
				return nil, false
			}
		}
		ports, n, ok := portSpec(rest[1:])
		if !ok {
			return nil, false
		}
		if axis == "source" {
			source = ports
		} else {
			destination = ports
		}
		rest = rest[n+1:]
	}
	if len(rest) > 0 {
		return nil, false
	}
	var terms []fm.ServiceTerm
	for _, p := range protocols {
		for _, src := range source {
			for _, dst := range destination {
				t := term(0, src, dst)
				t.Protocol = p
				terms = append(terms, t)
			}
		}
	}
	return terms, true
}

func intersectService(a, b fm.ServiceTerm) (fm.ServiceTerm, bool) {
	out := a
	for i, pair := range [][2]flow.Interval{{a.Protocol, b.Protocol}, {a.SourcePort, b.SourcePort}, {a.DestinationPort, b.DestinationPort}, {a.ICMPType, b.ICMPType}, {a.ICMPCode, b.ICMPCode}} {
		v := flow.Interval{Low: max(pair[0].Low, pair[1].Low), High: min(pair[0].High, pair[1].High)}
		if v.Low > v.High {
			return fm.ServiceTerm{}, false
		}
		switch i {
		case 0:
			out.Protocol = v
		case 1:
			out.SourcePort = v
		case 2:
			out.DestinationPort = v
		case 3:
			out.ICMPType = v
		case 4:
			out.ICMPCode = v
		}
	}
	return out, true
}
