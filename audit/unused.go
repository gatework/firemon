package audit

import (
	"slices"

	"github.com/gatework/firemon"
)

// unused lists configured, non-predefined objects that no rule, group or
// NAT rule references.
func unused(fw *firemon.Firewall) []Finding {
	cfg := fw.Config()
	addrRefs, svcRefs := references(cfg)
	var out []Finding
	for _, a := range cfg.Addresses {
		if !a.Predefined && !addrRefs[a.Name] {
			out = append(out, Finding{Kind: KindUnusedAddress, Object: a.Name})
		}
	}
	for _, g := range cfg.AddressGroups {
		if !g.Predefined && !addrRefs[g.Name] {
			out = append(out, Finding{Kind: KindUnusedAddress, Object: g.Name})
		}
	}
	for _, s := range cfg.Services {
		if !s.Predefined && !svcRefs[s.Name] {
			out = append(out, Finding{Kind: KindUnusedService, Object: s.Name})
		}
	}
	for _, g := range cfg.ServiceGroups {
		if !g.Predefined && !svcRefs[g.Name] {
			out = append(out, Finding{Kind: KindUnusedService, Object: g.Name})
		}
	}
	slices.SortStableFunc(out, func(a, b Finding) int {
		if a.Kind != b.Kind {
			return int(a.Kind) - int(b.Kind)
		}
		switch {
		case a.Object < b.Object:
			return -1
		case a.Object > b.Object:
			return 1
		default:
			return 0
		}
	})
	return out
}

// references collects every address and service name in use.
func references(cfg *firemon.Config) (addrs, svcs map[string]bool) {
	addrs, svcs = map[string]bool{}, map[string]bool{}
	named := func(refs []firemon.AddressRef) {
		for _, r := range refs {
			if !r.IsInline() {
				addrs[r.Name] = true
			}
		}
	}
	for _, r := range cfg.Rules {
		named(r.Source)
		named(r.Destination)
		for _, s := range r.Services {
			svcs[s] = true
		}
	}
	for _, g := range cfg.AddressGroups {
		for _, m := range g.Members {
			addrs[m] = true
		}
	}
	for _, g := range cfg.ServiceGroups {
		for _, m := range g.Members {
			svcs[m] = true
		}
	}
	for _, n := range cfg.DynamicNATs {
		named(n.Source)
		named(n.Destination)
		named(n.TranslatedSource.Addresses)
		named(n.TranslatedDestination.Addresses)
		for _, s := range n.Services {
			svcs[s] = true
		}
	}
	for _, m := range cfg.StaticNATs {
		named([]firemon.AddressRef{m.Real, m.Mapped})
	}
	for _, i := range cfg.Interfaces {
		for _, name := range i.AddressObjects {
			addrs[name] = true
		}
	}
	for _, r := range cfg.Routes {
		for _, name := range r.Objects {
			addrs[name] = true
		}
	}
	return addrs, svcs
}
