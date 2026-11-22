package hillstone

import (
	"cmp"
	"fmt"
	"slices"
	"strconv"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/design"
)

// renderNetwork writes virtual routers, zones, interfaces and static
// routes; ok is false for other changes.
func renderNetwork(ch design.Change) (do, undo []string, ok bool, err error) {
	ok = true
	switch c := ch.(type) {
	case design.AddVirtualRouter:
		do = []string{"ip vrouter " + q(c.VirtualRouter.Name), "exit"}
		undo = []string{"no ip vrouter " + q(c.VirtualRouter.Name)}
	case design.AddZone:
		do, err = renderZone(c.Zone)
		undo = []string{"no zone " + q(c.Zone.Name)}
	case design.AddInterface:
		do, undo = renderInterface(c.Interface)
	case design.AddRoute:
		do, undo, err = renderRoute(c.Route)
	case design.AddPolicyRoute:
		do, undo, err = renderPolicyRoute(c.Route)
	case design.AddPolicyBinding:
		do, undo = renderPolicyBinding(c.Binding)
	default:
		ok = false
	}
	return do, undo, ok, err
}

func renderZone(z firemon.Zone) ([]string, error) {
	head := "zone " + q(z.Name)
	switch z.Mode {
	case firemon.ZoneModeLayer2:
		head += " l2"
	case firemon.ZoneModeTap:
		head += " tap"
	case firemon.ZoneModeTunnel:
		return nil, fmt.Errorf("hillstone: zone %q: tunnel zones are layer-3 zones on StoneOS", z.Name)
	case firemon.ZoneModeUnset, firemon.ZoneModeLayer3:
	}
	out := []string{head}
	if z.VirtualRouter != "" && z.VirtualRouter != DefaultVirtualRouter && z.Mode == firemon.ZoneModeLayer3 {
		out = append(out, "  vrouter "+q(z.VirtualRouter))
	}
	if z.Description != "" {
		out = append(out, "  description "+q(z.Description))
	}
	return append(out, "exit"), nil
}

func renderInterface(i firemon.Interface) (do, undo []string) {
	do, undo = []string{"interface " + i.Name}, []string{"interface " + i.Name}
	if i.Zone != "" {
		do = append(do, "  zone "+q(i.Zone))
		undo = append(undo, "  no zone")
	}
	for _, p := range i.Addresses {
		kw := "ip"
		if p.Addr().Is6() {
			kw = "ipv6"
		}
		do = append(do, "  "+kw+" address "+p.String())
		undo = append(undo, "  no "+kw+" address "+p.String())
	}
	if i.Description != "" {
		do = append(do, "  description "+q(i.Description))
	}
	return append(do, "exit"), append(undo, "exit")
}

func renderRoute(r firemon.Route) (do, undo []string, err error) {
	if r.Discard {
		return nil, nil, fmt.Errorf("hillstone: route %s: discard routes are not written", r.Destination)
	}
	line := "ip route " + r.Destination.String()
	switch {
	case r.NextVirtualRouter != "":
		line += " vrouter " + q(r.NextVirtualRouter)
	default:
		if r.NextHop.IsValid() {
			line += " " + r.NextHop.String()
		}
		if r.Interface != "" {
			line += " " + q(r.Interface)
		}
	}
	if r.Distance != 0 && r.Distance != 1 {
		line += " distance " + strconv.FormatUint(uint64(r.Distance), 10)
	}
	if r.Metric != 0 {
		line += " weight " + strconv.FormatUint(uint64(r.Metric), 10)
	}
	vr := "ip vrouter " + q(cmp.Or(r.VirtualRouter, DefaultVirtualRouter))
	return []string{vr, "  " + line, "exit"}, []string{vr, "  no " + line, "exit"}, nil
}

// renderPolicyRoute writes one entry of a routing policy; entries are
// evaluated in the order they are written.
func renderPolicyRoute(r firemon.PolicyRoute) (do, undo []string, err error) {
	switch {
	case len(r.Conditions) > 0:
		return nil, nil, fmt.Errorf("hillstone: policy route %s/%s: criteria beyond addresses and services", r.Policy, r.ID)
	case r.NegateSource || r.NegateDestination:
		return nil, nil, fmt.Errorf("hillstone: policy route %s/%s: negated addresses", r.Policy, r.ID)
	case !r.NextHop.IsValid():
		return nil, nil, fmt.Errorf("hillstone: policy route %s/%s: a next hop is required", r.Policy, r.ID)
	}
	head := "pbr-policy " + q(r.Policy)
	if r.VirtualRouter != "" && r.VirtualRouter != DefaultVirtualRouter {
		head += " vrouter " + q(r.VirtualRouter)
	}
	src, err := refLines("src", r.Source, false)
	if err != nil {
		return nil, nil, fmt.Errorf("hillstone: policy route %s/%s: %w", r.Policy, r.ID, err)
	}
	dst, err := refLines("dst", r.Destination, false)
	if err != nil {
		return nil, nil, fmt.Errorf("hillstone: policy route %s/%s: %w", r.Policy, r.ID, err)
	}
	do = []string{head, "  match id " + r.ID}
	for _, l := range slices.Concat(src, dst) {
		do = append(do, "  "+l)
	}
	for _, s := range r.Services {
		do = append(do, "    service "+q(s))
	}
	do = append(do, "    nexthop "+r.NextHop.String())
	if r.Disabled {
		do = append(do, "    disable")
	}
	do = append(do, "  exit", "exit")
	undo = []string{head, "  no match id " + r.ID, "exit"}
	return do, undo, nil
}

// renderPolicyBinding binds a routing policy to a zone or an interface.
func renderPolicyBinding(b firemon.PolicyBinding) (do, undo []string) {
	head := "zone " + q(b.Zone)
	if b.Zone == "" {
		head = "interface " + b.Interface
	}
	return []string{head, "  bind pbr-policy " + q(b.Policy), "exit"}, []string{head, "  no bind pbr-policy", "exit"}
}
