package intake

import (
	"strconv"
	"strings"

	"github.com/gatework/firemon/traffic"
)

// serviceSide accumulates the service field.
type serviceSide struct {
	set   traffic.ServiceSet
	apps  []string
	notes []Note
	// last is the protocol of the latest explicit item; bare ports after it
	// inherit it ("udp/53,54" means UDP 54).
	last traffic.Protocol
	opts Options
}

// parseServices reads the service field.
func parseServices(text string, opts Options) serviceSide {
	side := serviceSide{opts: opts}
	tokens := fields(text)
	for i := 0; i < len(tokens); i++ {
		tok := tokens[i]
		// "tcp 80": a protocol keyword followed by its ports.
		if p, err := traffic.ParseProtocol(tok); err == nil && p.HasPorts() && i+1 < len(tokens) && isPortSpec(tokens[i+1]) {
			side.explicit(tok+" "+tokens[i+1], p, tokens[i+1])
			i++
			continue
		}
		side.item(tok)
	}
	return side
}

func (s *serviceSide) item(tok string) {
	low := strings.ToLower(tok)
	switch {
	case low == "any" || low == "all":
		s.merge(tok, traffic.AnyService(), CodeUnset)
	case strings.HasPrefix(low, "app:"):
		s.application(tok, tok[4:])
	case isPortSpec(tok):
		s.barePort(tok)
	case low == "ping":
		s.merge(tok, traffic.PortService(traffic.ProtocolICMP, traffic.ICMPRange(8, 0, 0xff)), CodeServiceName)
	default:
		if s.protocolForm(tok) || s.named(tok) {
			return
		}
		if s.opts.IsApplication != nil && s.opts.IsApplication(low) {
			s.application(tok, low)
			return
		}
		s.notes = append(s.notes, Note{Field: FieldService, Code: CodeInvalid, Input: tok})
	}
}

// protocolForm reads "tcp/80", "tcp:80", "80/tcp", "udp/53-60", "icmp",
// "icmp/8" and "proto/89" (protocol numbers).
func (s *serviceSide) protocolForm(tok string) bool {
	norm := strings.ToLower(strings.ReplaceAll(tok, ":", "/"))
	head, rest, _ := strings.Cut(norm, "/")
	if isPortSpec(head) && rest != "" { // "80/tcp"
		head, rest = rest, head
	}
	if head == "proto" || head == "protocol" {
		head = "ip"
	}
	if p, err := traffic.ParseProtocol(head); err == nil && p.HasPorts() && rest != "" {
		s.explicit(tok, p, rest)
		return true
	}
	set, err := traffic.ParseServiceSet(head + suffix(rest))
	if err != nil {
		return false
	}
	if p, err := traffic.ParseProtocol(head); err == nil {
		s.last = p
	}
	s.merge(tok, set, CodeUnset)
	return true
}

func suffix(rest string) string {
	if rest == "" {
		return ""
	}
	return "/" + rest
}

// explicit adds ports of protocol p; ports may be a list ("80,443" was
// split already) or a range.
func (s *serviceSide) explicit(input string, p traffic.Protocol, ports string) {
	r, err := traffic.ParsePortRange(ports)
	if err != nil {
		s.notes = append(s.notes, Note{Field: FieldService, Code: CodeInvalid, Input: input})
		return
	}
	s.last = p
	s.merge(input, traffic.PortService(p, r), CodeUnset)
}

// barePort takes a port or port range without protocol: TCP, or the
// protocol of the item before it.
func (s *serviceSide) barePort(tok string) {
	r, err := traffic.ParsePortRange(tok)
	if err != nil {
		s.notes = append(s.notes, Note{Field: FieldService, Code: CodeInvalid, Input: tok})
		return
	}
	p, code := traffic.ProtocolTCP, CodeDefaultTCP
	if s.last != 0 {
		p, code = s.last, CodeInheritedProtocol
	}
	s.merge(tok, traffic.PortService(p, r), code)
}

// named looks a service name up in the book, ignoring case.
func (s *serviceSide) named(tok string) bool {
	for name, entries := range s.opts.Services {
		if strings.EqualFold(name, tok) {
			var set traffic.ServiceSet
			for _, e := range entries {
				set = set.Union(e.Set())
			}
			s.merge(tok, set, CodeServiceName)
			return true
		}
	}
	return false
}

func (s *serviceSide) application(input, name string) {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		s.notes = append(s.notes, Note{Field: FieldService, Code: CodeInvalid, Input: input})
		return
	}
	s.apps = append(s.apps, name)
	s.notes = append(s.notes, Note{Field: FieldService, Code: CodeApplication, Input: input, Result: name})
}

func (s *serviceSide) merge(input string, set traffic.ServiceSet, code Code) {
	if !s.set.IsEmpty() && s.set.ContainsSet(set) {
		s.notes = append(s.notes, Note{Field: FieldService, Code: CodeDuplicate, Input: input, Result: set.String()})
		return
	}
	s.set = s.set.Union(set)
	if code != CodeUnset {
		s.notes = append(s.notes, Note{Field: FieldService, Code: code, Input: input, Result: set.String()})
	}
}

// isPortSpec reports "80" or "80-90".
func isPortSpec(s string) bool {
	lo, hi, isRange := strings.Cut(s, "-")
	if _, err := strconv.ParseUint(lo, 10, 16); err != nil {
		return false
	}
	if isRange {
		_, err := strconv.ParseUint(hi, 10, 16)
		return err == nil
	}
	return true
}
