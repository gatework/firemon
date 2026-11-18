package firemon

import "net/netip"

// VirtualRouter is a routing context (Hillstone vrouter, PAN-OS
// virtual-router). Interfaces, zones and routes belong to exactly one.
type VirtualRouter struct {
	Name string `json:"name"`
}

// ZoneMode tells how traffic enters a security zone.
type ZoneMode uint8

// Zone modes.
const (
	ZoneModeUnset ZoneMode = iota
	// ZoneModeLayer3 zones route between interfaces.
	ZoneModeLayer3
	// ZoneModeLayer2 zones bridge between interfaces (transparent mode).
	ZoneModeLayer2
	// ZoneModeTap zones only observe traffic.
	ZoneModeTap
	// ZoneModeTunnel zones terminate tunnels.
	ZoneModeTunnel
)

// String returns the mode name.
func (m ZoneMode) String() string {
	switch m {
	case ZoneModeUnset:
		return "unset"
	case ZoneModeLayer3:
		return "layer3"
	case ZoneModeLayer2:
		return "layer2"
	case ZoneModeTap:
		return "tap"
	case ZoneModeTunnel:
		return "tunnel"
	default:
		return "invalid"
	}
}

// MarshalText implements encoding.TextMarshaler.
func (m ZoneMode) MarshalText() ([]byte, error) { return []byte(m.String()), nil }

// Zone is a security zone: the unit security rules are written between.
type Zone struct {
	Name          string   `json:"name"`
	VirtualRouter string   `json:"virtual_router,omitempty"`
	Mode          ZoneMode `json:"mode"`
	Description   string   `json:"description,omitempty"`
}

// Interface is a physical, aggregate, VLAN, loopback or tunnel interface.
type Interface struct {
	Name          string `json:"name"`
	Zone          string `json:"zone,omitempty"`
	VirtualRouter string `json:"virtual_router,omitempty"`
	// Addresses are the interface addresses with their subnet lengths; each
	// one also yields a connected route.
	Addresses   []netip.Prefix `json:"addresses,omitempty"`
	Description string         `json:"description,omitempty"`
}

// Route is a static route in a virtual router. Interface, NextHop or both
// may be set.
type Route struct {
	Name          string       `json:"name,omitempty"`
	VirtualRouter string       `json:"virtual_router"`
	Destination   netip.Prefix `json:"destination"`
	NextHop       netip.Addr   `json:"next_hop,omitzero"`
	Interface     string       `json:"interface,omitempty"`
	// NextVirtualRouter forwards matching traffic to another virtual
	// router's table (PAN-OS next-vr).
	NextVirtualRouter string `json:"next_virtual_router,omitempty"`
	// Distance is the administrative distance; Metric breaks ties between
	// routes of equal distance.
	Distance    uint32 `json:"distance,omitempty"`
	Metric      uint32 `json:"metric,omitempty"`
	Description string `json:"description,omitempty"`
}
