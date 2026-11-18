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
	Name     string `yaml:"name"`
	Cluster  string `yaml:"cluster,omitempty"`
	Snapshot string `yaml:"snapshot,omitempty"`
	// Role is active or backup within the cluster; the active member is
	// evaluated and planned on.
	Role string `yaml:"role,omitempty"`
	// ProtectedZone is the zone behind which the protected networks sit,
	// for the entries of Protected that name no zone of their own.
	ProtectedZone string      `yaml:"protected_zone,omitempty"`
	Protected     []Protected `yaml:"protected,omitempty"`
}

// Active reports whether the firewall is its cluster's active member.
func (fw Firewall) Active() bool { return fw.Role == "active" }

// Protected is one group of protected networks behind a zone.
type Protected struct {
	Zone     string   `yaml:"zone,omitempty"`
	Networks []string `yaml:"networks"`
	Exclude  []string `yaml:"exclude,omitempty"`
}

// File is a decoded inventory file.
type File struct {
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
		if _, err := fw.protections(); err != nil {
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

// SnapshotOf returns the snapshot name of a firewall: its snapshot field,
// or its name.
func (fw Firewall) SnapshotOf() string { return cmp.Or(fw.Snapshot, fw.Name) }

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
		out = append(out, inventory.Protection{Firewall: fw.Name, Zone: cmp.Or(p.Zone, fw.ProtectedZone), Networks: nets, Exclude: excl})
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
