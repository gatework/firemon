package design

import (
	"github.com/gatework/firemon"
)

// AddVirtualRouter creates a routing context.
type AddVirtualRouter struct {
	VirtualRouter firemon.VirtualRouter `json:"virtual_router"`
}

// AddZone creates a security zone; Interfaces are its members, which
// PAN-OS lists on the zone.
type AddZone struct {
	Zone       firemon.Zone `json:"zone"`
	Interfaces []string     `json:"interfaces,omitempty"`
}

// AddInterface configures a layer-3 interface: its zone, virtual router
// and addresses.
type AddInterface struct {
	Interface firemon.Interface `json:"interface"`
}

// AddRoute adds a static route.
type AddRoute struct {
	Route firemon.Route `json:"route"`
}

// AddPolicyRoute appends one entry in forwarding evaluation order.
type AddPolicyRoute struct {
	Route firemon.PolicyRoute `json:"route"`
}

// AddPolicyBinding attaches a routing policy to one ingress zone or interface.
type AddPolicyBinding struct {
	Binding firemon.PolicyBinding `json:"binding"`
}

// String describes the change.
func (c AddPolicyRoute) String() string {
	return "add policy route " + c.Route.Policy + "/" + c.Route.ID
}

// String describes the change.
func (c AddPolicyBinding) String() string { return "bind routing policy " + c.Binding.Policy }

// String describes the change.
func (c AddVirtualRouter) String() string { return "add virtual router " + c.VirtualRouter.Name }

// String describes the change.
func (c AddZone) String() string { return "add zone " + c.Zone.Name }

// String describes the change.
func (c AddInterface) String() string { return "add interface " + c.Interface.Name }

// String describes the change.
func (c AddRoute) String() string {
	return "add route " + c.Route.VirtualRouter + " " + c.Route.Destination.String()
}

func (AddVirtualRouter) change() {}
func (AddZone) change()          {}
func (AddInterface) change()     {}
func (AddRoute) change()         {}
func (AddPolicyRoute) change()   {}
func (AddPolicyBinding) change() {}

// applyNetwork applies the network changes; ok is false for other kinds.
func applyNetwork(cfg *firemon.Config, ch Change) bool {
	switch c := ch.(type) {
	case AddVirtualRouter:
		cfg.VirtualRouters = append(cfg.VirtualRouters, c.VirtualRouter)
	case AddZone:
		cfg.Zones = append(cfg.Zones, c.Zone)
	case AddInterface:
		cfg.Interfaces = append(cfg.Interfaces, c.Interface)
	case AddPolicyRoute:
		cfg.PolicyRoutes = append(cfg.PolicyRoutes, c.Route)
	case AddPolicyBinding:
		cfg.PolicyBindings = append(cfg.PolicyBindings, c.Binding)
	case AddRoute:
		cfg.Routes = append(cfg.Routes, c.Route)
	default:
		return false
	}
	return true
}
