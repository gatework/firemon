package yamlfile

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"

	"go.yaml.in/yaml/v3"

	"github.com/gatework/firemon/inventory"
)

// Firewall is one inventory entry.
type Firewall struct {
	Name string `yaml:"name"`
	// Host is the management address, shown with the name in reports.
	Host     string `yaml:"host,omitempty"`
	Cluster  string `yaml:"cluster,omitempty"`
	Snapshot string `yaml:"snapshot,omitempty"`
	// Role is active or backup within the cluster; the active member is
	// evaluated and planned on.
	Role string `yaml:"role,omitempty"`
	// ProtectedZone is the zone behind which the protected networks sit,
	// for the entries of Protected that name no zone of their own.
	ProtectedZone string      `yaml:"protected_zone,omitempty"`
	Protected     []Protected `yaml:"protected,omitempty"`
	// Zones bind networks to the firewall's zones: protected zones are the
	// networks the firewall protects; the others tell where the far end of
	// a request is (for example untrust 0.0.0.0/0).
	Zones []Zone `yaml:"zones,omitempty"`
}

// Zone binds networks to one zone of a firewall.
type Zone struct {
	VirtualRouter string   `yaml:"virtual_router,omitempty"`
	Zone          string   `yaml:"zone"`
	Protected     bool     `yaml:"protected,omitempty"`
	Networks      []string `yaml:"networks"`
	Exclude       []string `yaml:"exclude,omitempty"`
}

// Active reports whether the firewall is its cluster's active member.
func (fw Firewall) Active() bool { return fw.Role == "active" }

// Protected is one group of protected networks behind a zone.
type Protected struct {
	VirtualRouter string   `yaml:"virtual_router,omitempty"`
	Zone          string   `yaml:"zone,omitempty"`
	Networks      []string `yaml:"networks"`
	Exclude       []string `yaml:"exclude,omitempty"`
}

// File is a decoded inventory file.
type File struct {
	// Store is the snapshot directory of the firewalls, relative to the
	// inventory file; empty leaves the choice to the command line.
	Store     string     `yaml:"store,omitempty"`
	Firewalls []Firewall `yaml:"firewalls"`
}

// Load reads and validates an inventory file. Unknown keys are errors, so
// typos do not silently drop protected networks.
func Load(path string) (*File, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("yamlfile: %w", err)
	}
	return Parse(raw)
}

// Parse decodes and validates inventory YAML.
func Parse(raw []byte) (*File, error) {
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	var f File
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("yamlfile: %w", err)
	}
	seen := map[string]bool{}
	for _, fw := range f.Firewalls {
		if fw.Name == "" {
			return nil, errors.New("yamlfile: firewall without name")
		}
		if seen[fw.Name] {
			return nil, fmt.Errorf("yamlfile: firewall %q listed twice", fw.Name)
		}
		seen[fw.Name] = true
		if fw.Role != "" && fw.Role != "active" && fw.Role != "backup" {
			return nil, fmt.Errorf("yamlfile: firewall %q: role %q: use active or backup", fw.Name, fw.Role)
		}
		if _, err := fw.bindings(); err != nil {
			return nil, err
		}
	}
	return &f, nil
}

// Protections implements the protected-network source.
func (f *File) Protections(context.Context) ([]inventory.Protection, error) {
	var out []inventory.Protection
	for _, fw := range f.Firewalls {
		ps, err := fw.protections()
		if err != nil {
			return nil, err
		}
		out = append(out, ps...)
	}
	return out, nil
}

// ZoneBindings returns every firewall's zone bindings: its zones, and its
// protected networks (the older form) as protected zones.
func (f *File) ZoneBindings() ([]inventory.ZoneBinding, error) {
	var out []inventory.ZoneBinding
	for _, fw := range f.Firewalls {
		bs, err := fw.bindings()
		if err != nil {
			return nil, err
		}
		out = append(out, bs...)
	}
	return out, nil
}

// SnapshotOf returns the snapshot name of a firewall: its snapshot field,
// or its name.
func (fw Firewall) SnapshotOf() string { return cmp.Or(fw.Snapshot, fw.Name) }

func (fw Firewall) bindings() ([]inventory.ZoneBinding, error) {
	ps, err := fw.protections()
	if err != nil {
		return nil, err
	}
	out := make([]inventory.ZoneBinding, 0, len(ps)+len(fw.Zones))
	for _, p := range ps {
		out = append(out, inventory.ZoneBinding{Firewall: p.Firewall, VirtualRouter: p.VirtualRouter, Zone: p.Zone, Networks: p.Networks, Exclude: p.Exclude, Protected: true})
	}
	for _, z := range fw.Zones {
		if z.Zone == "" {
			return nil, fmt.Errorf("yamlfile: firewall %q: a zone binding needs a zone", fw.Name)
		}
		nets, err := prefixes(fw.Name, z.Networks)
		if err != nil {
			return nil, err
		}
		excl, err := prefixes(fw.Name, z.Exclude)
		if err != nil {
			return nil, err
		}
		out = append(out, inventory.ZoneBinding{Firewall: fw.Name, VirtualRouter: z.VirtualRouter, Zone: z.Zone, Networks: nets, Exclude: excl, Protected: z.Protected})
	}
	return out, nil
}

func (fw Firewall) protections() ([]inventory.Protection, error) {
	var out []inventory.Protection
	for _, p := range fw.Protected {
		nets, err := prefixes(fw.Name, p.Networks)
		if err != nil {
			return nil, err
		}
		excl, err := prefixes(fw.Name, p.Exclude)
		if err != nil {
			return nil, err
		}
		out = append(out, inventory.Protection{Firewall: fw.Name, VirtualRouter: p.VirtualRouter, Zone: cmp.Or(p.Zone, fw.ProtectedZone), Networks: nets, Exclude: excl})
	}
	return out, nil
}

// prefixes parses prefixes and bare addresses.
func prefixes(owner string, values []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(values))
	for _, v := range values {
		if p, err := netip.ParsePrefix(v); err == nil {
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(v)
		if err != nil {
			return nil, fmt.Errorf("yamlfile: firewall %q: invalid network %q", owner, v)
		}
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
}
