package paloalto

import (
	"net/netip"
	"slices"
	"strconv"

	"github.com/gatework/firemon"
)

// zone parses: zone NAME network layer3|layer2|virtual-wire|tap [ IFS ].
// PAN-OS binds interfaces to zones on the zone side only.
func (s *state) zone(p *path) {
	name := p.next()
	i, ok := s.zones[name]
	if !ok {
		i = len(s.cfg.Zones)
		s.zones[name] = i
		s.cfg.Zones = append(s.cfg.Zones, firemon.Zone{Name: name})
	}
	if p.next() != "network" {
		return
	}
	z := &s.cfg.Zones[i]
	switch p.next() {
	case "layer3":
		z.Mode = firemon.ZoneModeLayer3
	case "layer2", "virtual-wire":
		z.Mode = firemon.ZoneModeLayer2
	case "tap":
		z.Mode = firemon.ZoneModeTap
	case "tunnel":
		z.Mode = firemon.ZoneModeTunnel
	default:
		return
	}
	for _, ifname := range p.value() {
		s.ensureInterface(ifname).Zone = name
	}
}

func (s *state) ensureInterface(name string) *firemon.Interface {
	i, ok := s.ifaces[name]
	if !ok {
		i = len(s.cfg.Interfaces)
		s.ifaces[name] = i
		s.cfg.Interfaces = append(s.cfg.Interfaces, firemon.Interface{Name: name})
	}
	return &s.cfg.Interfaces[i]
}

// network parses interfaces and virtual routers; other network settings
// (IKE, IPsec, QoS, profiles) do not affect policy matching.
func (s *state) network(p *path, st statement) {
	switch p.next() {
	case "interface":
		s.iface(p)
	case "virtual-router":
		s.virtualRouter(p, st)
	}
}

// iface parses the interface name and address of:
//
//	network interface ethernet NAME layer3 ip VALUE
//	network interface ethernet NAME layer3 units SUB ip VALUE
//	network interface tunnel|loopback|vlan units SUB ip VALUE
//	network interface loopback|vlan|tunnel ip VALUE
//
// VALUE is a prefix or the name of an address object.
func (s *state) iface(p *path) {
	kind := p.next()
	name := kind // loopback, tunnel and vlan without units
	if kind == "ethernet" || kind == "aggregate-ethernet" {
		name = p.next()
	}
	var values []string
	for !p.done() {
		switch w := p.next(); w {
		case "units":
			name = p.next()
		case "ip":
			values = p.value()
		case "comment":
			s.ensureInterface(name).Description = p.scalar()
		}
	}
	if len(values) == 0 {
		return
	}
	i := s.ensureInterface(name)
	for _, v := range values {
		if p, ok := interfaceAddress(v); ok {
			i.Addresses = append(i.Addresses, p)
		} else {
			s.ifaceRefs[name] = append(s.ifaceRefs[name], v)
		}
	}
}

// virtualRouter parses:
//
//	network virtual-router VR interface [ IFS ]
//	network virtual-router VR routing-table ip|ipv6 static-route NAME
//	    destination P | nexthop ip-address A | nexthop ipv6-address A |
//	    interface IF | metric N | admin-dist N
func (s *state) virtualRouter(p *path, st statement) {
	vr := p.next()
	if !slices.ContainsFunc(s.cfg.VirtualRouters, func(v firemon.VirtualRouter) bool { return v.Name == vr }) {
		s.cfg.VirtualRouters = append(s.cfg.VirtualRouters, firemon.VirtualRouter{Name: vr})
	}
	switch p.next() {
	case "interface":
		for _, ifname := range p.value() {
			s.ifaceVR[ifname] = vr
		}
	case "routing-table":
		if fam := p.next(); fam != "ip" && fam != "ipv6" {
			return
		}
		if p.next() != "static-route" {
			return
		}
		s.staticRoute(vr, p, st)
	}
}

func (s *state) staticRoute(vr string, p *path, st statement) {
	name := p.next()
	key := vr + "/" + name
	r, ok := s.routes[key]
	if !ok {
		r = &firemon.Route{Name: name, VirtualRouter: vr, Distance: 10}
		s.routes[key] = r
		s.routeKeys = append(s.routeKeys, key)
	}
	var err error
	switch p.next() {
	case "destination":
		s.routeRefs[key] = routeRef{dst: p.scalar(), hop: s.routeRefs[key].hop}
	case "nexthop":
		switch p.next() {
		case "ip-address", "ipv6-address":
			s.routeRefs[key] = routeRef{dst: s.routeRefs[key].dst, hop: p.scalar()}
		case "next-vr":
			r.NextVirtualRouter = p.scalar()
		case "discard":
			r.Discard = true
		}
	case "interface":
		r.Interface = p.scalar()
	case "metric":
		r.Metric, err = parseUint32(p.scalar())
	case "admin-dist":
		r.Distance, err = parseUint32(p.scalar())
	}
	if err != nil {
		s.diagnose(st, "invalid static route attribute")
	}
}

// bindInterfaces assigns virtual routers and resolves interface addresses
// given as address object names.
func (s *state) bindInterfaces() {
	for i := range s.cfg.Interfaces {
		ifc := &s.cfg.Interfaces[i]
		ifc.VirtualRouter = s.ifaceVR[ifc.Name]
		for _, ref := range s.ifaceRefs[ifc.Name] {
			p, ok := interfaceAddress(s.hostBits[ref])
			if !ok {
				s.cfg.Diagnostics = append(s.cfg.Diagnostics, firemon.Diagnostic{Text: "interface " + ifc.Name + " ip " + ref, Reason: "unknown address object"})
				continue
			}
			ifc.Addresses = append(ifc.Addresses, p)
		}
	}
	for i := range s.cfg.Zones {
		z := &s.cfg.Zones[i]
		for _, ifc := range s.cfg.Interfaces {
			if ifc.Zone == z.Name && ifc.VirtualRouter != "" {
				z.VirtualRouter = ifc.VirtualRouter
				break
			}
		}
	}
}

// routeRef keeps the raw destination and next hop of a static route; both
// may name address objects, resolved once every object is known.
type routeRef struct {
	dst, hop string
}

// flushRoutes appends the complete static routes in declaration order.
func (s *state) flushRoutes() {
	for _, key := range s.routeKeys {
		r := s.routes[key]
		ref := s.routeRefs[key]
		if p, ok := s.prefixValue(ref.dst); ok {
			r.Destination = p
		}
		if p, ok := s.prefixValue(ref.hop); ok && p.IsSingleIP() {
			r.NextHop = p.Addr()
		}
		if !r.Destination.IsValid() {
			s.cfg.Diagnostics = append(s.cfg.Diagnostics, firemon.Diagnostic{Text: "static-route " + r.Name, Reason: "route without destination"})
			continue
		}
		s.cfg.Routes = append(s.cfg.Routes, *r)
	}
}

func parseUint32(text string) (uint32, error) {
	n, err := strconv.ParseUint(text, 10, 32)
	return uint32(n), err
}

// prefixValue parses a prefix, an address or the name of an address object
// holding exactly one prefix.
func (s *state) prefixValue(v string) (netip.Prefix, bool) {
	if v == "" {
		return netip.Prefix{}, false
	}
	if p, err := netip.ParsePrefix(v); err == nil {
		return p.Masked(), true
	}
	if a, err := netip.ParseAddr(v); err == nil {
		return netip.PrefixFrom(a, a.BitLen()), true
	}
	if i, ok := s.addresses[v]; ok {
		if es := s.cfg.Addresses[i].Entries; len(es) == 1 && es[0].Kind == firemon.AddressKindPrefix {
			return es[0].Prefix, true
		}
	}
	return netip.Prefix{}, false
}

// interfaceAddress parses an interface address with its subnet length,
// keeping the host bits; a bare address is a host route.
func interfaceAddress(v string) (netip.Prefix, bool) {
	if p, err := netip.ParsePrefix(v); err == nil {
		return p, true
	}
	a, err := netip.ParseAddr(v)
	if err != nil {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(a, a.BitLen()), true
}
