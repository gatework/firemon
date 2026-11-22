package design

import (
	"cmp"
	"slices"
	"strings"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/traffic"
)

// RiskLevel grades a risk of a planned change.
type RiskLevel uint8

// Risk levels, from least to most severe.
const (
	RiskUnset RiskLevel = iota
	RiskLow
	RiskMedium
	RiskHigh
)

// String returns the level name used in JSON output.
func (l RiskLevel) String() string {
	switch l {
	case RiskUnset:
		return "unset"
	case RiskLow:
		return "low"
	case RiskMedium:
		return "medium"
	case RiskHigh:
		return "high"
	default:
		return "invalid"
	}
}

// MarshalText implements encoding.TextMarshaler.
func (l RiskLevel) MarshalText() ([]byte, error) { return []byte(l.String()), nil }

// RiskCode names what a risk is about.
type RiskCode string

// Risk codes.
const (
	// RiskAnyAddress: a permit opens any source or destination.
	RiskAnyAddress RiskCode = "any-address"
	// RiskWideNetwork: a permit opens a network wider than /16.
	RiskWideNetwork RiskCode = "wide-network"
	// RiskAnyService: a permit opens every service.
	RiskAnyService RiskCode = "any-service"
	// RiskManyPorts: a permit opens more than maxPorts ports.
	RiskManyPorts RiskCode = "many-ports"
	// RiskSensitiveService: a permit opens a service commonly abused for
	// lateral movement between zones (telnet, SMB, RDP, ...).
	RiskSensitiveService RiskCode = "sensitive-service"
	// RiskBypassIsolation: new rules go before a deny that isolates a
	// network (a network on one side, every service).
	RiskBypassIsolation RiskCode = "bypass-isolation"
	// RiskBypassDeny: new rules go before another explicit deny.
	RiskBypassDeny RiskCode = "bypass-deny"
)

// Risk is one finding on a planned change, in the manner of commercial
// change-risk analysis: what the change opens that a reviewer should weigh.
type Risk struct {
	Level RiskLevel `json:"level"`
	Code  RiskCode  `json:"code"`
	// Rule is the rule the risk is about: the planned rule, or the deny it
	// bypasses.
	Rule string `json:"rule"`
	// Detail is what is risky, in traffic terms (addresses, ports).
	Detail string `json:"detail,omitempty"`
}

// maxPorts is the port count above which a permit counts as wide.
const maxPorts = 100

// widestPrefix is the shortest IPv4 prefix length a permit may open
// without a wide-network risk.
const widestPrefix = 16

// SensitiveServices are the services that cross zones only with care,
// with the reason they are listed. Callers may replace the list.
var SensitiveServices = []struct {
	Name    string
	Service traffic.ServiceSet
}{
	{"FTP", traffic.PortService(traffic.ProtocolTCP, traffic.Port(21))},
	{"Telnet", traffic.PortService(traffic.ProtocolTCP, traffic.Port(23))},
	{"MSRPC", traffic.PortService(traffic.ProtocolTCP, traffic.Port(135))},
	{"NetBIOS", traffic.PortService(traffic.ProtocolTCP, traffic.Port(139)).Union(traffic.PortService(traffic.ProtocolUDP, traffic.PortRange{Low: 137, High: 138}))},
	{"SNMP", traffic.PortService(traffic.ProtocolUDP, traffic.PortRange{Low: 161, High: 162})},
	{"SMB", traffic.PortService(traffic.ProtocolTCP, traffic.Port(445))},
	{"MSSQL", traffic.PortService(traffic.ProtocolTCP, traffic.Port(1433))},
	{"MySQL", traffic.PortService(traffic.ProtocolTCP, traffic.Port(3306))},
	{"RDP", traffic.PortService(traffic.ProtocolTCP, traffic.Port(3389))},
	{"VNC", traffic.PortService(traffic.ProtocolTCP, traffic.PortRange{Low: 5900, High: 5910})},
	{"Redis", traffic.PortService(traffic.ProtocolTCP, traffic.Port(6379))},
}

// Risks assesses the plan against fw, the firewall it was designed on:
// what each new or extended permit opens, and the denies new rules go
// before. Risks never block a plan; they are for the reviewer.
func (p *Plan) Risks(fw *firemon.Firewall) []Risk {
	if p == nil || fw == nil || len(p.Changes) == 0 {
		return nil
	}
	cfg := fw.Config()
	if Apply(cfg, p.Changes) != nil {
		return nil
	}
	after, err := firemon.Compile(cfg)
	if err != nil {
		return nil
	}
	var out []Risk
	for _, c := range p.Changes {
		var id string
		switch x := c.(type) {
		case AddRule:
			id = x.Rule.ID
		case ExtendRule:
			id = x.RuleID
		default:
			continue
		}
		if r, ok := after.Rule(id); ok && r.Action() == firemon.ActionPermit {
			out = append(out, permitRisks(r)...)
		}
	}
	for _, id := range p.Bypassed {
		if r, ok := fw.Rule(id); ok {
			out = append(out, bypassRisk(r))
		}
	}
	slices.SortStableFunc(out, func(a, b Risk) int { return cmp.Compare(b.Level, a.Level) })
	return out
}

// permitRisks grades what a permit rule opens.
func permitRisks(r *firemon.Rule) []Risk {
	m := r.Match()
	var out []Risk
	for _, side := range []traffic.AddressSet{m.Src, m.Dst} {
		switch {
		case side.ContainsSet(traffic.AnyIPv4()):
			out = append(out, Risk{Level: RiskHigh, Code: RiskAnyAddress, Rule: r.ID(), Detail: "any"})
		case wider(side):
			out = append(out, Risk{Level: RiskMedium, Code: RiskWideNetwork, Rule: r.ID(), Detail: side.String()})
		}
	}
	switch {
	case m.Service.IsAny():
		out = append(out, Risk{Level: RiskHigh, Code: RiskAnyService, Rule: r.ID(), Detail: "any"})
	case portCount(m.Service) > maxPorts:
		out = append(out, Risk{Level: RiskMedium, Code: RiskManyPorts, Rule: r.ID(), Detail: m.Service.String()})
	}
	from, to := r.Zones()
	crossZone := len(from) == 0 || len(to) == 0 || !slices.Equal(from, to)
	if crossZone && !m.Service.IsAny() {
		for _, s := range SensitiveServices {
			if m.Service.Overlaps(s.Service) {
				out = append(out, Risk{Level: RiskMedium, Code: RiskSensitiveService, Rule: r.ID(), Detail: s.Name})
			}
		}
	}
	return out
}

// bypassRisk grades a deny that new rules are placed before: one that
// isolates a whole network for every service is a segmentation control.
func bypassRisk(r *firemon.Rule) Risk {
	m := r.Match()
	if apps := r.Spec().Applications(); len(apps) > 0 {
		return Risk{Level: RiskMedium, Code: RiskBypassDeny, Rule: r.ID(), Detail: m.Src.String() + " -> " + m.Dst.String() + " 应用 " + strings.Join(apps, "、")}
	}
	isolation := m.Service.IsAny() && (network(m.Src) || network(m.Dst))
	if isolation {
		detail := m.Src.String() + " -> " + m.Dst.String()
		return Risk{Level: RiskHigh, Code: RiskBypassIsolation, Rule: r.ID(), Detail: detail}
	}
	return Risk{Level: RiskMedium, Code: RiskBypassDeny, Rule: r.ID(), Detail: m.String()}
}

// wider reports addresses holding an IPv4 network wider than /16.
func wider(s traffic.AddressSet) bool {
	for _, p := range s.Prefixes() {
		if p.Addr().Is4() && p.Bits() < widestPrefix {
			return true
		}
	}
	return false
}

// network reports addresses that are a network (more than one host) but
// not every address: what a segmentation deny names.
func network(s traffic.AddressSet) bool {
	if _, single := s.Single(); single || s.IsEmpty() {
		return false
	}
	return !s.ContainsSet(traffic.AnyIPv4())
}

// portCount counts the TCP and UDP destination ports of s.
func portCount(s traffic.ServiceSet) int {
	n := 0
	for r := range s.All() {
		for p := int(r.ProtocolLow); p <= int(r.ProtocolHigh); p++ {
			if traffic.Protocol(p).HasPorts() {
				n += int(r.Dst.High) - int(r.Dst.Low) + 1
			}
		}
	}
	return n
}
