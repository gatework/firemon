package paloalto

import (
	"cmp"
	"fmt"
	"strconv"
	"strings"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/design"
)

// renderNetwork writes virtual routers, zones, interfaces and static
// routes; ok is false for other changes.
func renderNetwork(ch design.Change) (do, undo []string, ok bool, err error) {
	ok = true
	switch c := ch.(type) {
	case design.AddVirtualRouter:
		do = []string{"set network virtual-router " + name(c.VirtualRouter.Name)}
		undo = []string{"delete network virtual-router " + name(c.VirtualRouter.Name)}
	case design.AddZone:
		do, err = renderZone(c.Zone, c.Interfaces)
		undo = []string{"delete zone " + name(c.Zone.Name)}
	case design.AddInterface:
		do, undo = renderInterface(c.Interface)
	case design.AddRoute:
		do, undo, err = renderRoute(c.Route)
	case design.AddPolicyRoute:
		do, err = renderPolicyRoute(c.Route)
		undo = []string{"delete rulebase pbf rules " + name(c.Route.Policy)}
	case design.AddPolicyBinding:
		do = renderPolicyBinding(c.Binding)
	default:
		ok = false
	}
	return do, undo, ok, err
}

func renderZone(z firemon.Zone, ifaces []string) ([]string, error) {
	mode := map[firemon.ZoneMode]string{
		firemon.ZoneModeUnset: "layer3", firemon.ZoneModeLayer3: "layer3", firemon.ZoneModeLayer2: "layer2",
		firemon.ZoneModeTap: "tap", firemon.ZoneModeTunnel: "tunnel",
	}[z.Mode]
	if mode == "" {
		return nil, fmt.Errorf("paloalto: zone %q: mode %s", z.Name, z.Mode)
	}
	return []string{"set zone " + name(z.Name) + " network " + mode + " " + bracket(ifaces)}, nil
}

// interfacePath returns the configuration path of an interface name:
// ethernet1/1, ethernet1/1.100 (unit), ae1, tunnel.1, loopback.1, vlan.1.
func interfacePath(ifname string) string {
	parent, _, unit := strings.Cut(ifname, ".")
	switch {
	case strings.HasPrefix(ifname, "ethernet") && unit:
		return "ethernet " + parent + " layer3 units " + ifname
	case strings.HasPrefix(ifname, "ethernet"):
		return "ethernet " + ifname + " layer3"
	case strings.HasPrefix(ifname, "ae") && unit:
		return "aggregate-ethernet " + parent + " layer3 units " + ifname
	case strings.HasPrefix(ifname, "ae"):
		return "aggregate-ethernet " + ifname + " layer3"
	default:
		return parent + " units " + ifname // tunnel, loopback, vlan
	}
}

func renderInterface(i firemon.Interface) (do, undo []string) {
	p := "set network interface " + interfacePath(i.Name)
	for _, a := range i.Addresses {
		do = append(do, p+" ip "+a.String())
	}
	if i.Description != "" {
		do = append(do, p+" comment "+strconv.Quote(i.Description))
	}
	if i.VirtualRouter != "" {
		do = append(do, "set network virtual-router "+name(i.VirtualRouter)+" interface "+name(i.Name))
		undo = append(undo, "delete network virtual-router "+name(i.VirtualRouter)+" interface "+name(i.Name))
	}
	return do, append(undo, "delete network interface "+interfacePath(i.Name))
}

func renderRoute(r firemon.Route) (do, undo []string, err error) {
	vr := cmp.Or(r.VirtualRouter, DefaultVirtualRouter)
	rname := cmp.Or(r.Name, "route-"+strings.NewReplacer("/", "_", ":", "_").Replace(r.Destination.String()))
	p := "set network virtual-router " + name(vr) + " routing-table ip static-route " + name(rname) + " "
	do = []string{p + "destination " + r.Destination.String()}
	switch {
	case r.Discard:
		do = append(do, p+"nexthop discard")
	case r.NextVirtualRouter != "":
		do = append(do, p+"nexthop next-vr "+name(r.NextVirtualRouter))
	case r.NextHop.IsValid():
		do = append(do, p+"nexthop ip-address "+r.NextHop.String())
	}
	if r.Interface != "" {
		do = append(do, p+"interface "+name(r.Interface))
	}
	if r.Metric != 0 {
		do = append(do, p+"metric "+strconv.FormatUint(uint64(r.Metric), 10))
	}
	if r.Distance != 0 && r.Distance != 10 {
		do = append(do, p+"admin-dist "+strconv.FormatUint(uint64(r.Distance), 10))
	}
	return do, []string{"delete network virtual-router " + name(vr) + " routing-table ip static-route " + name(rname)}, nil
}

// renderPolicyRoute writes one PBF rule; its ingress comes from its
// bindings (renderPolicyBinding).
func renderPolicyRoute(r firemon.PolicyRoute) ([]string, error) {
	if len(r.Conditions) > 0 {
		return nil, fmt.Errorf("paloalto: policy route %s: criteria beyond addresses and services", r.Policy)
	}
	if r.Interface == "" {
		return nil, fmt.Errorf("paloalto: policy route %s: a PBF rule forwards through an egress interface", r.Policy)
	}
	src, err := operandTexts(r.Source)
	if err != nil {
		return nil, fmt.Errorf("paloalto: policy route %s: %w", r.Policy, err)
	}
	dst, err := operandTexts(r.Destination)
	if err != nil {
		return nil, fmt.Errorf("paloalto: policy route %s: %w", r.Policy, err)
	}
	p := "set rulebase pbf rules " + name(r.Policy) + " "
	out := []string{
		p + "source " + list(orAny(src)),
		p + "destination " + list(orAny(dst)),
		p + "service " + list(orAny(r.Services)),
	}
	if r.NegateSource {
		out = append(out, p+"negate-source yes")
	}
	if r.NegateDestination {
		out = append(out, p+"negate-destination yes")
	}
	out = append(out, p+"action forward egress-interface "+r.Interface)
	if r.NextHop.IsValid() {
		out = append(out, p+"action forward nexthop ip-address "+r.NextHop.String())
	}
	if r.Disabled {
		out = append(out, p+"disabled yes")
	}
	return out, nil
}

// renderPolicyBinding adds an ingress zone or interface to a PBF rule; the
// rule's deletion undoes it.
func renderPolicyBinding(b firemon.PolicyBinding) []string {
	p := "set rulebase pbf rules " + name(b.Policy) + " from "
	if b.Zone != "" {
		return []string{p + "zone " + name(b.Zone)}
	}
	return []string{p + "interface " + b.Interface}
}
