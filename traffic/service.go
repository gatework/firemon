package traffic

import (
	"errors"
	"fmt"
	"iter"
	"math"
	"strconv"
	"strings"
)

// ErrInvalidService reports text that is not a service expression.
var ErrInvalidService = errors.New("traffic: invalid service")

// Protocol is an IP protocol number.
type Protocol uint8

// Well-known protocol numbers.
const (
	ProtocolICMP   Protocol = 1
	ProtocolTCP    Protocol = 6
	ProtocolUDP    Protocol = 17
	ProtocolICMPv6 Protocol = 58
	ProtocolSCTP   Protocol = 132
)

// ParseProtocol accepts a protocol keyword (tcp, udp, icmp, icmpv6, sctp)
// or a decimal number from 0 to 255.
func ParseProtocol(text string) (Protocol, error) {
	switch strings.ToLower(text) {
	case "tcp":
		return ProtocolTCP, nil
	case "udp":
		return ProtocolUDP, nil
	case "icmp":
		return ProtocolICMP, nil
	case "icmpv6", "icmp6":
		return ProtocolICMPv6, nil
	case "sctp":
		return ProtocolSCTP, nil
	}
	n, err := strconv.ParseUint(text, 10, 8)
	if err != nil {
		return 0, fmt.Errorf("%w: protocol %q", ErrInvalidService, text)
	}
	return Protocol(n), nil
}

// String returns the keyword of a well-known protocol or its number.
func (p Protocol) String() string {
	switch p {
	case ProtocolICMP:
		return "icmp"
	case ProtocolTCP:
		return "tcp"
	case ProtocolUDP:
		return "udp"
	case ProtocolICMPv6:
		return "icmpv6"
	case ProtocolSCTP:
		return "sctp"
	default:
		return strconv.Itoa(int(p))
	}
}

// MarshalText implements encoding.TextMarshaler with the String form.
func (p Protocol) MarshalText() ([]byte, error) { return []byte(p.String()), nil }

// UnmarshalText implements encoding.TextUnmarshaler with ParseProtocol.
func (p *Protocol) UnmarshalText(text []byte) error {
	parsed, err := ParseProtocol(string(text))
	if err != nil {
		return err
	}
	*p = parsed
	return nil
}

// HasPorts reports whether the protocol carries source and destination ports.
func (p Protocol) HasPorts() bool {
	return p == ProtocolTCP || p == ProtocolUDP || p == ProtocolSCTP
}

// IsICMP reports whether the protocol carries an ICMP type and code.
func (p Protocol) IsICMP() bool { return p == ProtocolICMP || p == ProtocolICMPv6 }

// ICMPRange returns the encoded range for an ICMP type and inclusive code range.
func ICMPRange(typ, codeLow, codeHigh uint8) PortRange {
	return PortRange{Low: uint16(typ)<<8 | uint16(codeLow), High: uint16(typ)<<8 | uint16(codeHigh)}
}

// ServiceRange is one rectangle of a service set: a protocol interval with a
// source-port range and a destination-port range. For ICMP the destination
// range encodes type<<8|code; for protocols without ports both ranges are
// AnyPort.
type ServiceRange struct {
	ProtocolLow  Protocol
	ProtocolHigh Protocol
	Src          PortRange
	Dst          PortRange
}

// IsAnyProtocol reports whether the range spans every protocol number.
func (r ServiceRange) IsAnyProtocol() bool {
	return r.ProtocolLow == 0 && r.ProtocolHigh == math.MaxUint8
}

// ServiceSet is an immutable set of (protocol, source port, destination port)
// tuples. The zero value is empty.
type ServiceSet struct {
	p stripes[Protocol, portSpace]
}

// AnyService returns every protocol with every port.
func AnyService() ServiceSet {
	return ServiceSet{p: stripes[Protocol, portSpace]{{lo: 0, hi: math.MaxUint8, v: fullPortSpace()}}}
}

// ProtocolService returns every port of protocol p.
func ProtocolService(p Protocol) ServiceSet {
	return ServiceSet{p: stripes[Protocol, portSpace]{{lo: p, hi: p, v: fullPortSpace()}}}
}

// PortService returns destination ports dst of protocol p from any source
// port. For protocols without ports it returns ProtocolService(p).
func PortService(p Protocol, dst PortRange) ServiceSet {
	return NewService(p, AnyPort, dst)
}

// NewService returns protocol p restricted to source ports src and
// destination ports dst. For ICMP, dst encodes type<<8|code and src is
// ignored. For protocols without ports both ranges are ignored.
func NewService(p Protocol, src, dst PortRange) ServiceSet {
	switch {
	case p.HasPorts():
	case p.IsICMP():
		src = AnyPort
	default:
		return ProtocolService(p)
	}
	ps := portSpace{s: stripes[uint16, PortSet]{{lo: src.Low, hi: src.High, v: NewPortSet(dst)}}}
	return ServiceSet{p: stripes[Protocol, portSpace]{{lo: p, hi: p, v: ps}}}
}

// ParseServiceSet parses a comma-separated list of service expressions:
// "any", "ip/0-5" (protocol numbers), "tcp", "tcp/80", "tcp/8000-8080", "udp/53", "icmp", "icmp/8"
// (type), "icmp/3/4" (type and code) and protocol numbers such as "89".
func ParseServiceSet(text string) (ServiceSet, error) {
	var out ServiceSet
	items := 0
	for item := range strings.SplitSeq(text, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		items++
		s, err := parseServiceItem(item)
		if err != nil {
			return ServiceSet{}, err
		}
		out = out.Union(s)
	}
	if items == 0 {
		return ServiceSet{}, fmt.Errorf("%w: empty list", ErrInvalidService)
	}
	return out, nil
}

// Union returns the tuples in s or o.
func (s ServiceSet) Union(o ServiceSet) ServiceSet { return ServiceSet{p: s.p.union(o.p)} }

// anyService is every tuple, for the fast paths below.
var anyService = AnyService()

// Intersect returns the tuples in both s and o. Rules often match any
// service: that case returns the other set as it is.
func (s ServiceSet) Intersect(o ServiceSet) ServiceSet {
	switch {
	case s.IsEmpty() || o.IsEmpty():
		return ServiceSet{}
	case s.IsAny():
		return o
	case o.IsAny():
		return s
	}
	return ServiceSet{p: s.p.intersect(o.p)}
}

// Subtract returns the tuples in s that are not in o.
func (s ServiceSet) Subtract(o ServiceSet) ServiceSet {
	switch {
	case s.IsEmpty() || o.IsEmpty():
		return s
	case o.IsAny():
		return ServiceSet{}
	}
	return ServiceSet{p: s.p.subtract(o.p)}
}

// IsEmpty reports whether s holds no tuple.
func (s ServiceSet) IsEmpty() bool { return len(s.p) == 0 }

// IsAny reports whether s holds every tuple.
func (s ServiceSet) IsAny() bool { return len(s.p) == 1 && s.p.equal(anyService.p) }

// Equal reports whether s and o hold the same tuples.
func (s ServiceSet) Equal(o ServiceSet) bool { return s.p.equal(o.p) }

// ContainsSet reports whether every tuple of o is in s.
func (s ServiceSet) ContainsSet(o ServiceSet) bool { return o.Subtract(s).IsEmpty() }

// Overlaps reports whether s and o share a tuple.
func (s ServiceSet) Overlaps(o ServiceSet) bool { return !s.Intersect(o).IsEmpty() }

// Relation classifies s against o.
func (s ServiceSet) Relation(o ServiceSet) Relation {
	return relate(s.Equal(o), s.ContainsSet(o), o.ContainsSet(s), s.Overlaps(o))
}

// All yields the disjoint rectangles of s in protocol, source-port and
// destination-port order.
func (s ServiceSet) All() iter.Seq[ServiceRange] {
	return func(yield func(ServiceRange) bool) {
		for _, pb := range s.p {
			for _, sb := range pb.v.s {
				for _, dst := range sb.v.Ranges() {
					r := ServiceRange{ProtocolLow: pb.lo, ProtocolHigh: pb.hi, Src: PortRange{Low: sb.lo, High: sb.hi}, Dst: dst}
					if !yield(r) {
						return
					}
				}
			}
		}
	}
}

// String writes the canonical expression list accepted by ParseServiceSet,
// with source ports written as "tcp/80<-1024-2048". The empty set is "none".
func (s ServiceSet) String() string {
	if s.IsEmpty() {
		return "none"
	}
	if s.IsAny() {
		return "any"
	}
	var parts []string
	for r := range s.All() {
		parts = append(parts, formatServiceRange(r)...)
	}
	return strings.Join(parts, ",")
}

// MarshalText implements encoding.TextMarshaler with the String form.
func (s ServiceSet) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

func formatServiceRange(r ServiceRange) []string {
	if r.IsAnyProtocol() && r.Src.IsAny() && r.Dst.IsAny() {
		return []string{"any"}
	}
	if r.ProtocolLow != r.ProtocolHigh && r.Src.IsAny() && r.Dst.IsAny() {
		return []string{"ip/" + strconv.Itoa(int(r.ProtocolLow)) + "-" + strconv.Itoa(int(r.ProtocolHigh))}
	}
	var out []string
	for p := int(r.ProtocolLow); p <= int(r.ProtocolHigh); p++ {
		proto := Protocol(p)
		text := proto.String()
		switch {
		case proto.IsICMP() && !r.Dst.IsAny():
			text += formatICMP(r.Dst)
		case proto.HasPorts() && !(r.Dst.IsAny() && r.Src.IsAny()):
			text += "/" + r.Dst.String()
			if !r.Src.IsAny() {
				text += "<-" + r.Src.String()
			}
		}
		out = append(out, text)
	}
	return out
}

func formatICMP(r PortRange) string {
	typ, codeLow, codeHigh := r.Low>>8, r.Low&0xff, r.High&0xff
	if r.High>>8 != typ {
		return "/" + r.String() // spans several types; keep the raw encoding
	}
	if codeLow == 0 && codeHigh == 0xff {
		return "/" + strconv.Itoa(int(typ))
	}
	code := strconv.Itoa(int(codeLow))
	if codeHigh != codeLow {
		code += "-" + strconv.Itoa(int(codeHigh))
	}
	return "/" + strconv.Itoa(int(typ)) + "/" + code
}

func parseServiceItem(item string) (ServiceSet, error) {
	if strings.EqualFold(item, "any") {
		return AnyService(), nil
	}
	head, rest, _ := strings.Cut(item, "/")
	if strings.EqualFold(head, "ip") {
		return parseProtocolRange(rest)
	}
	p, err := ParseProtocol(head)
	if err != nil {
		return ServiceSet{}, err
	}
	switch {
	case rest == "":
		return ProtocolService(p), nil
	case p.IsICMP():
		return parseICMP(p, rest)
	case p.HasPorts():
		dstText, srcText, hasSrc := strings.Cut(rest, "<-")
		dst, err := ParsePortRange(dstText)
		if err != nil {
			return ServiceSet{}, err
		}
		src := AnyPort
		if hasSrc {
			if src, err = ParsePortRange(srcText); err != nil {
				return ServiceSet{}, err
			}
		}
		return NewService(p, src, dst), nil
	default:
		return ServiceSet{}, fmt.Errorf("%w: protocol %s has no ports: %q", ErrInvalidService, p, item)
	}
}

func parseProtocolRange(text string) (ServiceSet, error) {
	r, err := ParsePortRange(text)
	if err != nil || r.High > math.MaxUint8 {
		return ServiceSet{}, fmt.Errorf("%w: protocol range %q", ErrInvalidService, text)
	}
	band := band[Protocol, portSpace]{lo: Protocol(r.Low), hi: Protocol(r.High), v: fullPortSpace()}
	return ServiceSet{p: stripes[Protocol, portSpace]{band}}, nil
}

func parseICMP(p Protocol, rest string) (ServiceSet, error) {
	typText, codeText, hasCode := strings.Cut(rest, "/")
	typ, err := strconv.ParseUint(typText, 10, 8)
	if err != nil {
		return ServiceSet{}, fmt.Errorf("%w: icmp type %q", ErrInvalidService, typText)
	}
	codes := PortRange{Low: 0, High: 0xff}
	if hasCode {
		if codes, err = ParsePortRange(codeText); err != nil || codes.High > 0xff {
			return ServiceSet{}, fmt.Errorf("%w: icmp code %q", ErrInvalidService, codeText)
		}
	}
	return PortService(p, ICMPRange(uint8(typ), uint8(codes.Low), uint8(codes.High))), nil
}

// ParsePortRange parses "80", "80-90" or "any".
func ParsePortRange(text string) (PortRange, error) {
	text = strings.TrimSpace(text)
	if strings.EqualFold(text, "any") {
		return AnyPort, nil
	}
	lo, hi, isRange := strings.Cut(text, "-")
	low, err := strconv.ParseUint(strings.TrimSpace(lo), 10, 16)
	if err != nil {
		return PortRange{}, fmt.Errorf("%w: port %q", ErrInvalidService, text)
	}
	high := low
	if isRange {
		if high, err = strconv.ParseUint(strings.TrimSpace(hi), 10, 16); err != nil || high < low {
			return PortRange{}, fmt.Errorf("%w: port %q", ErrInvalidService, text)
		}
	}
	return PortRange{Low: uint16(low), High: uint16(high)}, nil
}

// portSpace maps source-port bands to destination-port sets.
type portSpace struct {
	s stripes[uint16, PortSet]
}

func fullPortSpace() portSpace {
	return portSpace{s: stripes[uint16, PortSet]{{lo: 0, hi: math.MaxUint16, v: AllPorts()}}}
}

// Union implements lattice.
func (p portSpace) Union(o portSpace) portSpace { return portSpace{s: p.s.union(o.s)} }

// Intersect implements lattice.
func (p portSpace) Intersect(o portSpace) portSpace { return portSpace{s: p.s.intersect(o.s)} }

// Subtract implements lattice.
func (p portSpace) Subtract(o portSpace) portSpace { return portSpace{s: p.s.subtract(o.s)} }

// Equal implements lattice.
func (p portSpace) Equal(o portSpace) bool { return p.s.equal(o.s) }

// IsEmpty implements lattice.
func (p portSpace) IsEmpty() bool { return len(p.s) == 0 }
