package firemon

import (
	"cmp"
	"fmt"
	"slices"
)

// ObjectKind classifies the named objects a configuration defines.
type ObjectKind uint8

// Object kinds.
const (
	ObjectKindUnset ObjectKind = iota
	ObjectKindAddress
	ObjectKindAddressGroup
	ObjectKindService
	ObjectKindServiceGroup
	ObjectKindSchedule
)

// String returns the kind name.
func (k ObjectKind) String() string {
	switch k {
	case ObjectKindUnset:
		return "unset"
	case ObjectKindAddress:
		return "address"
	case ObjectKindAddressGroup:
		return "address-group"
	case ObjectKindService:
		return "service"
	case ObjectKindServiceGroup:
		return "service-group"
	case ObjectKindSchedule:
		return "schedule"
	default:
		return "invalid"
	}
}

// MarshalText implements encoding.TextMarshaler.
func (k ObjectKind) MarshalText() ([]byte, error) { return []byte(k.String()), nil }

// ObjectRef names one object of a kind.
type ObjectRef struct {
	Kind ObjectKind `json:"kind"`
	Name string     `json:"name"`
}

func (r ObjectRef) String() string { return r.Kind.String() + " " + r.Name }

// UseSite is the kind of construct that refers to an object.
type UseSite uint8

// Use sites.
const (
	UseSiteUnset UseSite = iota
	UseSiteRule
	UseSiteDynamicNAT
	UseSiteStaticNAT
	UseSitePolicyRoute
	UseSiteInterface
	UseSiteRoute
	UseSiteGroup
	// UseSiteQoS is a QoS pipe or rule, which the model does not evaluate
	// but which the device refuses to lose its objects to.
	UseSiteQoS
	// UseSiteOther is any other construct the parser saw a reference in,
	// such as a DoS rule.
	UseSiteOther
)

// String returns the site name.
func (s UseSite) String() string {
	switch s {
	case UseSiteUnset:
		return "unset"
	case UseSiteRule:
		return "rule"
	case UseSiteDynamicNAT:
		return "nat"
	case UseSiteStaticNAT:
		return "static-nat"
	case UseSitePolicyRoute:
		return "policy-route"
	case UseSiteInterface:
		return "interface"
	case UseSiteRoute:
		return "route"
	case UseSiteGroup:
		return "group"
	case UseSiteQoS:
		return "qos"
	case UseSiteOther:
		return "other"
	default:
		return "invalid"
	}
}

// MarshalText implements encoding.TextMarshaler.
func (s UseSite) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// ExternalUse is a reference to an object from a construct the model does
// not evaluate (QoS pipes, DoS rules). Parsers record them so that objects
// they use are not reported unused.
type ExternalUse struct {
	Site UseSite `json:"site"`
	ID   string  `json:"id"`
	// Kind tells the namespace: address (object or group), service (object
	// or group) or schedule; the group kinds are resolved by name.
	Kind ObjectKind `json:"kind"`
	Name string     `json:"name"`
}

// Use is one construct referring to an object.
type Use struct {
	Site UseSite `json:"site"`
	ID   string  `json:"id"`
}

// References is the reference graph of a configuration: who uses each
// object, and which objects are live, that is reachable from a rule, NAT
// rule, policy route, interface, route or external construct through
// group membership. It is immutable.
type References struct {
	users map[ObjectRef][]Use
	live  map[ObjectRef]bool
	all   []ObjectRef // declared, non-predefined objects in declaration order
}

// Users returns the constructs that refer to o directly, groups included.
func (r References) Users(o ObjectRef) []Use { return slices.Clone(r.users[o]) }

// Live reports whether o is reachable from a construct that is not an
// object: deleting it would change or break the configuration.
func (r References) Live(o ObjectRef) bool { return r.live[o] }

// Unused returns the declared, non-predefined objects that are not live,
// each after every unused group that contains it, so that deleting them in
// this order never removes an object something still refers to.
func (r References) Unused() []ObjectRef {
	unused := map[ObjectRef]bool{}
	for _, o := range r.all {
		if !r.live[o] {
			unused[o] = true
		}
	}
	var out []ObjectRef
	done := map[ObjectRef]bool{}
	var visit func(o ObjectRef)
	visit = func(o ObjectRef) {
		if done[o] {
			return
		}
		done[o] = true
		for _, u := range r.users[o] {
			if u.Site != UseSiteGroup {
				continue
			}
			for _, kind := range []ObjectKind{ObjectKindAddressGroup, ObjectKindServiceGroup} {
				if g := (ObjectRef{Kind: kind, Name: u.ID}); unused[g] && sameNamespace(g.Kind, o.Kind) {
					visit(g) // the group that contains o goes first
				}
			}
		}
		out = append(out, o)
	}
	for _, o := range r.all {
		if unused[o] {
			visit(o)
		}
	}
	return out
}

// sameNamespace reports whether two kinds share a name space: addresses
// with address groups, services with service groups.
func sameNamespace(a, b ObjectKind) bool {
	isAddr := func(k ObjectKind) bool { return k == ObjectKindAddress || k == ObjectKindAddressGroup }
	isSvc := func(k ObjectKind) bool { return k == ObjectKindService || k == ObjectKindServiceGroup }
	return (isAddr(a) && isAddr(b)) || (isSvc(a) && isSvc(b)) || a == b
}

// ReferencesOf returns the reference graph of a configuration without
// compiling it, for checks on configurations being changed.
func ReferencesOf(cfg *Config) References { return buildReferences(cfg) }

// References returns the reference graph of the configuration.
func (fw *Firewall) References() References { return fw.refs }

// buildReferences computes the graph once at compile time.
func buildReferences(cfg *Config) References {
	b := refBuilder{cfg: cfg, r: References{users: map[ObjectRef][]Use{}, live: map[ObjectRef]bool{}}}
	b.index()
	b.roots()
	b.groups()
	b.propagate()
	return b.r
}

type refBuilder struct {
	cfg     *Config
	r       References
	kind    map[string]ObjectKind // address namespace
	svcKind map[string]ObjectKind // service namespace
	members map[ObjectRef][]ObjectRef
	seeds   []ObjectRef
}

func (b *refBuilder) index() {
	b.kind, b.svcKind = map[string]ObjectKind{}, map[string]ObjectKind{}
	declare := func(o ObjectRef, predefined bool) {
		if !predefined {
			b.r.all = append(b.r.all, o)
		}
	}
	for _, a := range b.cfg.Addresses {
		b.kind[a.Name] = ObjectKindAddress
		declare(ObjectRef{ObjectKindAddress, a.Name}, a.Predefined)
	}
	for _, g := range b.cfg.AddressGroups {
		b.kind[g.Name] = ObjectKindAddressGroup
		declare(ObjectRef{ObjectKindAddressGroup, g.Name}, g.Predefined)
	}
	for _, s := range b.cfg.Services {
		b.svcKind[s.Name] = ObjectKindService
		declare(ObjectRef{ObjectKindService, s.Name}, s.Predefined)
	}
	for _, g := range b.cfg.ServiceGroups {
		b.svcKind[g.Name] = ObjectKindServiceGroup
		declare(ObjectRef{ObjectKindServiceGroup, g.Name}, g.Predefined)
	}
	for _, s := range b.cfg.Schedules {
		declare(ObjectRef{ObjectKindSchedule, s.Name}, false)
	}
}

func (b *refBuilder) address(name string) ObjectRef {
	return ObjectRef{Kind: cmp.Or(b.kind[name], ObjectKindAddress), Name: name}
}

func (b *refBuilder) service(name string) ObjectRef {
	return ObjectRef{Kind: cmp.Or(b.svcKind[name], ObjectKindService), Name: name}
}

// use records a root reference.
func (b *refBuilder) use(o ObjectRef, u Use) {
	if o.Name == "" {
		return
	}
	b.r.users[o] = append(b.r.users[o], u)
	b.seeds = append(b.seeds, o)
}

func (b *refBuilder) addresses(refs []AddressRef, u Use) {
	for _, a := range refs {
		if !a.IsInline() {
			b.use(b.address(a.Name), u)
		}
	}
}

func (b *refBuilder) services(names []string, u Use) {
	for _, n := range names {
		b.use(b.service(n), u)
	}
}

func (b *refBuilder) roots() {
	cfg := b.cfg
	for _, r := range cfg.Rules {
		u := Use{UseSiteRule, r.ID}
		b.addresses(r.Source, u)
		b.addresses(r.Destination, u)
		b.services(r.Services, u)
		if r.Schedule != "" {
			b.use(ObjectRef{ObjectKindSchedule, r.Schedule}, u)
		}
	}
	for _, n := range cfg.DynamicNATs {
		u := Use{UseSiteDynamicNAT, n.ID}
		b.addresses(slices.Concat(n.Source, n.Destination, n.TranslatedSource.Addresses, n.TranslatedDestination.Addresses), u)
		b.services(n.Services, u)
	}
	for _, m := range cfg.StaticNATs {
		b.addresses([]AddressRef{m.Real, m.Mapped}, Use{UseSiteStaticNAT, m.ID})
	}
	for _, p := range cfg.PolicyRoutes {
		u := Use{UseSitePolicyRoute, p.Policy + "/" + p.ID}
		b.addresses(slices.Concat(p.Source, p.Destination), u)
		b.services(p.Services, u)
	}
	for _, i := range cfg.Interfaces {
		for _, n := range i.AddressObjects {
			b.use(b.address(n), Use{UseSiteInterface, i.Name})
		}
	}
	for _, rt := range cfg.Routes {
		for _, n := range rt.Objects {
			b.use(b.address(n), Use{UseSiteRoute, rt.Destination.String()})
		}
	}
	for _, e := range cfg.ExternalUses {
		u := Use{e.Site, e.ID}
		switch e.Kind {
		case ObjectKindAddress, ObjectKindAddressGroup:
			b.use(b.address(e.Name), u)
		case ObjectKindService, ObjectKindServiceGroup:
			b.use(b.service(e.Name), u)
		case ObjectKindSchedule:
			b.use(ObjectRef{ObjectKindSchedule, e.Name}, u)
		case ObjectKindUnset:
		}
	}
}

// groups records membership edges; a member is used by its group but is
// live only when the group is.
func (b *refBuilder) groups() {
	b.members = map[ObjectRef][]ObjectRef{}
	for _, g := range b.cfg.AddressGroups {
		self := ObjectRef{ObjectKindAddressGroup, g.Name}
		for _, m := range g.Members {
			o := b.address(m)
			b.members[self] = append(b.members[self], o)
			b.r.users[o] = append(b.r.users[o], Use{UseSiteGroup, g.Name})
		}
	}
	for _, g := range b.cfg.ServiceGroups {
		self := ObjectRef{ObjectKindServiceGroup, g.Name}
		for _, m := range g.Members {
			o := b.service(m)
			b.members[self] = append(b.members[self], o)
			b.r.users[o] = append(b.r.users[o], Use{UseSiteGroup, g.Name})
		}
	}
}

// propagate marks everything reachable from the roots.
func (b *refBuilder) propagate() {
	stack := slices.Clone(b.seeds)
	for len(stack) > 0 {
		o := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if b.r.live[o] {
			continue
		}
		b.r.live[o] = true
		stack = append(stack, b.members[o]...)
	}
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (k *ObjectKind) UnmarshalText(text []byte) error {
	for v := ObjectKindUnset; v <= ObjectKindSchedule; v++ {
		if v.String() == string(text) {
			*k = v
			return nil
		}
	}
	return fmt.Errorf("firemon: unknown object kind %q", text)
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (s *UseSite) UnmarshalText(text []byte) error {
	for v := UseSiteUnset; v <= UseSiteOther; v++ {
		if v.String() == string(text) {
			*s = v
			return nil
		}
	}
	return fmt.Errorf("firemon: unknown use site %q", text)
}
