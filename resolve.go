package firemon

import (
	"net/netip"
	"slices"

	"github.com/gatework/firemon/traffic"
)

// resolved is the exact set a named object or operand list denotes, plus
// the reasons it is not exact. A non-empty problems list means the true
// set may differ from set: the object depends on something that cannot be
// evaluated offline (domain names, dynamic groups) or is broken (unknown
// members, cycles).
type resolved[T any] struct {
	set      T
	problems []string
	// domains are the domain names among the entries; each also leaves a
	// problem in domainProblems, since IP-based evaluation cannot use it.
	domains        traffic.DomainSet
	domainProblems []string
	// overstated is set when set may contain values the true set lacks: an
	// exclusion or a membership could not be resolved. Otherwise set is
	// always part of the true set, the problems only hiding more of it.
	overstated bool
}

func (r resolved[T]) exact() bool { return len(r.problems) == 0 && len(r.domainProblems) == 0 }

// absorb adds a part to an OR-list: the list overstates when any part does.
func (r *resolved[T]) absorb(problems, domainProblems []string, domains traffic.DomainSet, overstated bool) {
	r.problems = append(r.problems, problems...)
	r.domains = r.domains.Union(domains)
	r.domainProblems = append(r.domainProblems, domainProblems...)
	r.overstated = r.overstated || overstated
}

// allProblems returns every reason the set is inexact, domains included.
func (r resolved[T]) allProblems() []string {
	return append(slices.Clip(r.problems), r.domainProblems...)
}

// resolver turns object names into sets, memoizing results and detecting
// membership cycles. It is used only while compiling.
type resolver struct {
	addresses     map[string]*Address
	addressGroups map[string]*AddressGroup
	services      map[string]*Service
	serviceGroups map[string]*ServiceGroup

	addressCache map[string]resolved[traffic.AddressSet]
	serviceCache map[string]resolved[traffic.ServiceSet]
	visiting     map[string]bool
}

func newResolver(cfg *Config) *resolver {
	r := &resolver{
		addresses:     make(map[string]*Address, len(cfg.Addresses)),
		addressGroups: make(map[string]*AddressGroup, len(cfg.AddressGroups)),
		services:      make(map[string]*Service, len(cfg.Services)),
		serviceGroups: make(map[string]*ServiceGroup, len(cfg.ServiceGroups)),
		addressCache:  make(map[string]resolved[traffic.AddressSet]),
		serviceCache:  make(map[string]resolved[traffic.ServiceSet]),
		visiting:      make(map[string]bool),
	}
	for i := range cfg.Addresses {
		r.addresses[cfg.Addresses[i].Name] = &cfg.Addresses[i]
	}
	for i := range cfg.AddressGroups {
		r.addressGroups[cfg.AddressGroups[i].Name] = &cfg.AddressGroups[i]
	}
	for i := range cfg.Services {
		r.services[cfg.Services[i].Name] = &cfg.Services[i]
	}
	for i := range cfg.ServiceGroups {
		r.serviceGroups[cfg.ServiceGroups[i].Name] = &cfg.ServiceGroups[i]
	}
	return r
}

// address resolves an address object or group by name.
func (r *resolver) address(name string) resolved[traffic.AddressSet] {
	if res, ok := r.addressCache[name]; ok {
		return res
	}
	key := "address:" + name
	if r.visiting[key] {
		return resolved[traffic.AddressSet]{problems: []string{"address membership cycle through " + quote(name)}, overstated: true}
	}
	r.visiting[key] = true
	defer delete(r.visiting, key)

	var res resolved[traffic.AddressSet]
	switch {
	case r.addresses[name] != nil:
		res = entriesSet(withAny(r.addresses[name].Entries), name)
		for _, bad := range r.addresses[name].Invalid {
			res.problems = append(res.problems, "invalid entry "+quote(bad)+" in "+quote(name))
		}
	case r.addressGroups[name] != nil:
		res = r.group(r.addressGroups[name])
	default:
		res.problems = []string{"unknown address " + quote(name)}
	}
	r.addressCache[name] = res
	return res
}

func (r *resolver) group(g *AddressGroup) resolved[traffic.AddressSet] {
	entries := g.Entries
	if len(g.Members) == 0 && g.Filter == "" {
		entries = withAny(entries)
	}
	res := entriesSet(entries, g.Name)
	if g.Filter != "" {
		res.problems = append(res.problems, "dynamic address group "+quote(g.Name))
	}
	for _, bad := range g.Invalid {
		res.problems = append(res.problems, "invalid entry "+quote(bad)+" in "+quote(g.Name))
	}
	for _, m := range g.Members {
		member := r.address(m)
		res.set = res.set.Union(member.set)
		res.absorb(member.problems, member.domainProblems, member.domains, member.overstated)
	}
	// Excluded entries apply after members are merged.
	for _, e := range g.Entries {
		if s, ok := e.Set(); ok && e.Exclude {
			res.set = res.set.Subtract(s)
		}
	}
	return res
}

// operands resolves a rule's address list; an empty list is any address.
func (r *resolver) operands(refs []AddressRef) resolved[traffic.AddressSet] {
	if len(refs) == 0 {
		return resolved[traffic.AddressSet]{set: traffic.AnyAddress()}
	}
	var res resolved[traffic.AddressSet]
	for _, ref := range refs {
		var part resolved[traffic.AddressSet]
		if ref.IsInline() {
			part = entriesSet([]AddressEntry{ref.Entry}, "")
		} else {
			part = r.address(ref.Name)
		}
		res.set = res.set.Union(part.set)
		res.absorb(part.problems, part.domainProblems, part.domains, part.overstated)
	}
	return res
}

// service resolves a service object or group by name.
func (r *resolver) service(name string) resolved[traffic.ServiceSet] {
	if res, ok := r.serviceCache[name]; ok {
		return res
	}
	key := "service:" + name
	if r.visiting[key] {
		return resolved[traffic.ServiceSet]{problems: []string{"service membership cycle through " + quote(name)}, overstated: true}
	}
	r.visiting[key] = true
	defer delete(r.visiting, key)

	var res resolved[traffic.ServiceSet]
	switch {
	case r.services[name] != nil:
		for _, e := range r.services[name].Entries {
			res.set = res.set.Union(e.Set())
		}
		for _, bad := range r.services[name].Invalid {
			res.problems = append(res.problems, "invalid entry "+quote(bad)+" in "+quote(name))
		}
	case r.serviceGroups[name] != nil:
		for _, m := range r.serviceGroups[name].Members {
			member := r.service(m)
			res.set = res.set.Union(member.set)
			res.absorb(member.problems, nil, traffic.DomainSet{}, member.overstated)
		}
	default:
		res.problems = []string{"unknown service " + quote(name)}
	}
	r.serviceCache[name] = res
	return res
}

// serviceList resolves a rule's service list; an empty list is any service.
func (r *resolver) serviceList(names []string) resolved[traffic.ServiceSet] {
	if len(names) == 0 {
		return resolved[traffic.ServiceSet]{set: traffic.AnyService()}
	}
	var res resolved[traffic.ServiceSet]
	for _, n := range names {
		part := r.service(n)
		res.set = res.set.Union(part.set)
		res.absorb(part.problems, nil, traffic.DomainSet{}, part.overstated)
	}
	return res
}

// entriesSet unions the included entries and subtracts the excluded ones.
func entriesSet(entries []AddressEntry, owner string) resolved[traffic.AddressSet] {
	var res resolved[traffic.AddressSet]
	var excluded traffic.AddressSet
	for _, e := range entries {
		s, ok := e.Set()
		if !ok {
			where := ""
			if owner != "" {
				where = " in " + quote(owner)
			}
			reason := "unresolvable " + e.Kind.String() + " " + quote(e.String()) + where
			if e.Kind == AddressKindFQDN && !e.Exclude {
				res.domains = res.domains.Union(traffic.NewDomainSet(e.FQDN))
				res.domainProblems = append(res.domainProblems, reason)
				continue
			}
			res.problems = append(res.problems, reason)
			res.overstated = res.overstated || e.Exclude // an unknown exclusion may remove more
			continue
		}
		if e.Exclude {
			excluded = excluded.Union(s)
		} else {
			res.set = res.set.Union(s)
		}
	}
	res.set = res.set.Subtract(excluded)
	return res
}

func quote(s string) string { return "\"" + s + "\"" }

var (
	anyIPv4 = netip.PrefixFrom(netip.IPv4Unspecified(), 0)
	anyIPv6 = netip.PrefixFrom(netip.IPv6Unspecified(), 0)
)

// onlyExclusions reports whether entries exclude addresses but include none.
func onlyExclusions(entries []AddressEntry) bool {
	return len(entries) > 0 && !slices.ContainsFunc(entries, func(e AddressEntry) bool { return !e.Exclude })
}

// withAny reads entries that are all exclusions as every address except
// them, as StoneOS objects with only exclude lines are written.
func withAny(entries []AddressEntry) []AddressEntry {
	if !onlyExclusions(entries) {
		return entries
	}
	return append([]AddressEntry{{Kind: AddressKindPrefix, Prefix: anyIPv4}, {Kind: AddressKindPrefix, Prefix: anyIPv6}}, entries...)
}
