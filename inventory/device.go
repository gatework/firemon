package inventory

import (
	"net/netip"
	"strings"
)

// Device identifies one member to an operator: its name and management
// address, the way tickets and change windows name firewalls.
type Device struct {
	// Name is the member name; Host its management address, empty when
	// unknown.
	Name string `json:"name"`
	Host string `json:"host,omitempty"`
	// Evaluated marks the member a cluster is evaluated and planned on;
	// the others receive its configuration by HA synchronization.
	Evaluated bool `json:"evaluated,omitempty"`
}

// Label writes "SZX9-IN-FW01(10.251.8.203)": the name without a trailing
// "-<address>" (backup file names carry it) and the address in brackets.
func (d Device) Label() string {
	host := d.Host
	name := d.Name
	if host == "" {
		if i := strings.LastIndexByte(name, '-'); i > 0 {
			if a, err := netip.ParseAddr(name[i+1:]); err == nil {
				host = a.String()
			}
		}
	}
	if host == "" {
		return name
	}
	name = strings.TrimSuffix(name, "-"+host)
	return name + "(" + host + ")"
}

// Devices returns the members of a cluster, the evaluated one first.
func (inv *Inventory) Devices(cluster string) []Device {
	p := inv.primary(cluster)
	var out []Device
	for _, m := range inv.members {
		if m.cluster != cluster {
			continue
		}
		d := Device{Name: m.name, Host: m.host, Evaluated: p != nil && p.name == m.name}
		if d.Evaluated {
			out = append([]Device{d}, out...)
			continue
		}
		out = append(out, d)
	}
	return out
}
