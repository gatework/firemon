package hillstone

import (
	"strconv"
	"strings"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/traffic"
)

// service parses: service "NAME"
//
//	tcp|udp dst-port LO [HI] [src-port LO [HI]]
//	icmp type T [code LO [HI]] | protocol N|any | description "TEXT"
func (s *state) service(b block, head *words) {
	name := head.next()
	svc := s.services.upsert(name, func() firemon.Service { return firemon.Service{Name: name} })
	for _, l := range b.body {
		w := newWords(l.Text)
		switch kw := w.next(); kw {
		case "tcp", "udp", "sctp":
			e, ok := portEntry(kw, w)
			if !ok {
				s.diagnose(l, "invalid service ports")
				svc.Invalid = append(svc.Invalid, strings.TrimSpace(l.Text))
				continue
			}
			svc.Entries = append(svc.Entries, e)
		case "icmp", "icmpv6":
			e, ok := icmpEntry(kw, w)
			if !ok {
				s.diagnose(l, "invalid icmp service")
				svc.Invalid = append(svc.Invalid, strings.TrimSpace(l.Text))
				continue
			}
			svc.Entries = append(svc.Entries, e)
		case "protocol":
			e, ok := protocolEntry(w.next())
			if !ok {
				s.diagnose(l, "invalid protocol")
				svc.Invalid = append(svc.Invalid, strings.TrimSpace(l.Text))
				continue
			}
			svc.Entries = append(svc.Entries, e)
		case "description":
			svc.Description = w.next()
		default:
			continue
		}
		s.mark(l)
	}
}

// serviceGroup parses: servgroup "NAME" / service "MEMBER" / description.
func (s *state) serviceGroup(b block, head *words) {
	name := head.next()
	g := s.groups.upsert(name, func() firemon.ServiceGroup { return firemon.ServiceGroup{Name: name} })
	for _, l := range b.body {
		w := newWords(l.Text)
		switch w.next() {
		case "service":
			g.Members = append(g.Members, w.next())
		case "description":
			g.Description = w.next()
		default:
			continue
		}
		s.mark(l)
	}
}

func portEntry(proto string, w *words) (firemon.ServiceEntry, bool) {
	p, err := traffic.ParseProtocol(proto)
	if err != nil {
		return firemon.ServiceEntry{}, false
	}
	e := firemon.ServiceEntry{Protocol: p, Src: traffic.AnyPort, Dst: traffic.AnyPort}
	for !w.done() {
		var r *traffic.PortRange
		switch w.next() {
		case "dst-port":
			r = &e.Dst
		case "src-port":
			r = &e.Src
		case "timeout", "timeout-day":
			w.next() // session timeouts do not change matching
			continue
		default:
			return firemon.ServiceEntry{}, false
		}
		lo, ok := portNumber(w.next())
		if !ok {
			return firemon.ServiceEntry{}, false
		}
		hi := lo
		if v, ok := portNumber(w.peek()); ok {
			hi = v
			w.next()
		}
		if hi < lo {
			return firemon.ServiceEntry{}, false
		}
		*r = traffic.PortRange{Low: lo, High: hi}
	}
	return e, true
}

func icmpEntry(proto string, w *words) (firemon.ServiceEntry, bool) {
	p, err := traffic.ParseProtocol(proto)
	if err != nil {
		return firemon.ServiceEntry{}, false
	}
	e := firemon.ServiceEntry{Protocol: p, Src: traffic.AnyPort, Dst: traffic.AnyPort}
	if w.done() {
		return e, true
	}
	if w.next() != "type" {
		return firemon.ServiceEntry{}, false
	}
	typ, err := strconv.ParseUint(w.next(), 10, 8)
	if err != nil {
		return firemon.ServiceEntry{}, false
	}
	codeLo, codeHi := uint64(0), uint64(0xff)
	if w.peek() == "code" {
		w.next()
		if codeLo, err = strconv.ParseUint(w.next(), 10, 8); err != nil {
			return firemon.ServiceEntry{}, false
		}
		codeHi = codeLo
		if v, err := strconv.ParseUint(w.peek(), 10, 8); err == nil {
			codeHi = v
			w.next()
		}
	}
	e.Dst = traffic.ICMPRange(uint8(typ), uint8(codeLo), uint8(codeHi))
	return e, w.done()
}

func protocolEntry(text string) (firemon.ServiceEntry, bool) {
	if text == "any" {
		return firemon.ServiceEntry{AnyProtocol: true}, true
	}
	p, err := traffic.ParseProtocol(text)
	if err != nil {
		return firemon.ServiceEntry{}, false
	}
	return firemon.ServiceEntry{Protocol: p, Src: traffic.AnyPort, Dst: traffic.AnyPort}, true
}

func portNumber(text string) (uint16, bool) {
	n, err := strconv.ParseUint(text, 10, 16)
	return uint16(n), err == nil
}

// inlineService parses the operand of a rule "service-rule" line, which
// uses the service object line syntax.
func inlineService(w *words) (firemon.ServiceEntry, bool) {
	switch kw := w.next(); kw {
	case "tcp", "udp", "sctp":
		return portEntry(kw, w)
	case "icmp", "icmpv6":
		return icmpEntry(kw, w)
	case "protocol":
		return protocolEntry(w.next())
	default:
		return firemon.ServiceEntry{}, false
	}
}
