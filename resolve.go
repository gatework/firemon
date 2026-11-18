package firemon

import (
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
}

func (r resolved[T]) exact() bool { return len(r.problems) == 0 }

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
		return resolved[traffic.AddressSet]{problems: []string{"address membership cycle through " + quote(name)}}
	}
	r.visiting[key] = true
	defer delete(r.visiting, key)

	var res resolved[traffic.AddressSet]
	switch {
	case r.addresses[name] != nil:
		res = entriesSet(r.addresses[name].Entries, name)
	case r.addressGroups[name] != nil:
		res = r.group(r.addressGroups[name])
	default:
		res.problems = []string{"unknown address " + quote(name)}
	}
	r.addressCache[name] = res
	return res
}

func (r *resolver) group(g *AddressGroup) resolved[traffic.AddressSet] {
	res := entriesSet(g.Entries, g.Name)
	if g.Filter != "" {
		res.problems = append(res.problems, "dynamic address group "+quote(g.Name))
	}
	for _, m := range g.Members {
		member := r.address(m)
		res.set = res.set.Union(member.set)
		res.problems = append(res.problems, member.problems...)
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
		res.problems = append(res.problems, part.problems...)
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
		return resolved[traffic.ServiceSet]{problems: []string{"service membership cycle through " + quote(name)}}
	}
	r.visiting[key] = true
	defer delete(r.visiting, key)

	var res resolved[traffic.ServiceSet]
	switch {
	case r.services[name] != nil:
		for _, e := range r.services[name].Entries {
			res.set = res.set.Union(e.Set())
		}
	case r.serviceGroups[name] != nil:
		for _, m := range r.serviceGroups[name].Members {
			member := r.service(m)
			res.set = res.set.Union(member.set)
			res.problems = append(res.problems, member.problems...)
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
		res.problems = append(res.problems, part.problems...)
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
			res.problems = append(res.problems, "unresolvable "+e.Kind.String()+" "+quote(e.String())+where)
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
