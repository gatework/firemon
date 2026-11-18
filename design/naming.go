package design

import (
	"strconv"
	"strings"

	"go4.org/netipx"

	"github.com/gatework/firemon/traffic"
)

// Naming names the objects and rules a plan creates. Nil functions fall
// back to DefaultNaming.
type Naming struct {
	// Address names an object holding one address range.
	Address func(r netipx.IPRange) string
	// Service names an object holding one service rectangle.
	Service func(r traffic.ServiceRange) string
	// Rule names a new rule; index counts the rules created for one intent.
	Rule func(i Intent, index int) string
	// Sanitize adapts a name to the vendor's object name rules.
	Sanitize func(name string) string
}

// DefaultNaming follows the operations convention of the Perl designer:
// Host_10.0.0.1, Net_10.0.0.0_24, Range_10.0.0.1-10.0.0.9, TCP_80,
// TCP_8000-8010, UDP_53, ICMP, ICMP_8, PROTO_89; rules are named after the
// intent name or fm_<index>.
func DefaultNaming() Naming {
	return Naming{Address: addressName, Service: serviceName, Rule: ruleName, Sanitize: func(s string) string { return s }}
}

func (n Naming) withDefaults() Naming {
	d := DefaultNaming()
	if n.Address == nil {
		n.Address = d.Address
	}
	if n.Service == nil {
		n.Service = d.Service
	}
	if n.Rule == nil {
		n.Rule = d.Rule
	}
	if n.Sanitize == nil {
		n.Sanitize = d.Sanitize
	}
	return n
}

func addressName(r netipx.IPRange) string {
	if r.From() == r.To() {
		return "Host_" + r.From().String()
	}
	if p, ok := r.Prefix(); ok {
		return "Net_" + p.Addr().String() + "_" + strconv.Itoa(p.Bits())
	}
	return "Range_" + r.From().String() + "-" + r.To().String()
}

func serviceName(r traffic.ServiceRange) string {
	if r.IsAnyProtocol() {
		return "ANY"
	}
	p := r.ProtocolLow
	var b strings.Builder
	switch {
	case p.HasPorts():
		b.WriteString(strings.ToUpper(p.String()) + "_" + strings.ReplaceAll(r.Dst.String(), "any", "ALL"))
		if !r.Src.IsAny() {
			b.WriteString("_FROM_" + r.Src.String())
		}
	case p.IsICMP():
		b.WriteString(strings.ToUpper(p.String()))
		if !r.Dst.IsAny() {
			b.WriteString("_" + strconv.Itoa(int(r.Dst.Low>>8)))
		}
	default:
		b.WriteString("PROTO_" + p.String())
	}
	if r.ProtocolHigh != r.ProtocolLow {
		b.WriteString("_TO_" + r.ProtocolHigh.String())
	}
	return b.String()
}

func ruleName(i Intent, index int) string {
	base := i.Name
	if base == "" {
		base = "fm"
	}
	if index == 0 && i.Name != "" {
		return base
	}
	return base + "_" + strconv.Itoa(index+1)
}
