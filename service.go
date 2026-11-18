package firemon

import (
	"github.com/gatework/firemon/traffic"
)

// ServiceEntry is one protocol and port combination of a service object.
// For ICMP, Dst encodes type<<8|code (see traffic.ICMPRange).
type ServiceEntry struct {
	// AnyProtocol matches every protocol; Protocol and ports are ignored.
	AnyProtocol bool              `json:"any_protocol,omitempty"`
	Protocol    traffic.Protocol  `json:"protocol"`
	Src         traffic.PortRange `json:"src"`
	Dst         traffic.PortRange `json:"dst"`
}

// PortEntry returns destination ports dst of protocol p from any source port.
func PortEntry(p traffic.Protocol, dst traffic.PortRange) ServiceEntry {
	return ServiceEntry{Protocol: p, Src: traffic.AnyPort, Dst: dst}
}

// Set returns the tuples of the entry.
func (e ServiceEntry) Set() traffic.ServiceSet {
	if e.AnyProtocol {
		return traffic.AnyService()
	}
	return traffic.NewService(e.Protocol, e.Src, e.Dst)
}

// String writes the entry in the traffic.ParseServiceSet syntax.
func (e ServiceEntry) String() string { return e.Set().String() }

// Service is a named service object.
type Service struct {
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	Entries     []ServiceEntry `json:"entries"`
	Predefined  bool           `json:"predefined,omitempty"`
}

// ServiceGroup is a named collection of services and service groups.
type ServiceGroup struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Members     []string `json:"members"`
	Predefined  bool     `json:"predefined,omitempty"`
}
