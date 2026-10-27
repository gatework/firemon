package firemon

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gatework/firemon/flow"
	"math/big"
	"net/netip"
	"slices"
	"strings"
	"time"
)

var ErrGraph = errors.New("invalid firewall graph")

type Firewall struct {
	data          Data
	diagnostics   []Diagnostic
	sequence      []NATEntry
	digest        string
	zones         map[ID]*Zone
	interfaces    map[ID]*Interface
	routes        map[ID]*Route
	addresses     map[ID]*Address
	addressGroups map[ID]*AddressGroup
	services      map[ID]*Service
	serviceGroups map[ID]*ServiceGroup
	schedules     map[ID]*Schedule
	rules         map[ID]*Rule
	ruleBindings  map[ID]*RuleBinding
	staticNATs    map[ID]*StaticNAT
	dynamicNATs   map[ID]*DynamicNAT
	natPools      map[ID]*NATPool
}

func (f *Firewall) Zone(id ID) *Zone { return f.zones[id] }
func (f *Firewall) Zones() []*Zone {
	out := make([]*Zone, 0, len(f.data.Zones))
	for _, r := range f.data.Zones {
		out = append(out, f.zones[r.ID])
	}
	return out
}
func (f *Firewall) Interface(id ID) *Interface { return f.interfaces[id] }
func (f *Firewall) Interfaces() []*Interface {
	out := make([]*Interface, 0, len(f.data.Interfaces))
	for _, r := range f.data.Interfaces {
		out = append(out, f.interfaces[r.ID])
	}
	return out
}
func (f *Firewall) Route(id ID) *Route { return f.routes[id] }
func (f *Firewall) Routes() []*Route {
	out := make([]*Route, 0, len(f.data.Routes))
	for _, r := range f.data.Routes {
		out = append(out, f.routes[r.ID])
	}
	return out
}
func (f *Firewall) Address(id ID) *Address { return f.addresses[id] }
func (f *Firewall) Addresses() []*Address {
	out := make([]*Address, 0, len(f.data.Addresses))
	for _, r := range f.data.Addresses {
		out = append(out, f.addresses[r.ID])
	}
	return out
}
func (f *Firewall) AddressGroup(id ID) *AddressGroup { return f.addressGroups[id] }
func (f *Firewall) AddressGroups() []*AddressGroup {
	out := make([]*AddressGroup, 0, len(f.data.AddressGroups))
	for _, r := range f.data.AddressGroups {
		out = append(out, f.addressGroups[r.ID])
	}
	return out
}
func (f *Firewall) Service(id ID) *Service { return f.services[id] }
func (f *Firewall) Services() []*Service {
	out := make([]*Service, 0, len(f.data.Services))
	for _, r := range f.data.Services {
		out = append(out, f.services[r.ID])
	}
	return out
}
func (f *Firewall) ServiceGroup(id ID) *ServiceGroup { return f.serviceGroups[id] }
func (f *Firewall) ServiceGroups() []*ServiceGroup {
	out := make([]*ServiceGroup, 0, len(f.data.ServiceGroups))
	for _, r := range f.data.ServiceGroups {
		out = append(out, f.serviceGroups[r.ID])
	}
	return out
}
func (f *Firewall) Schedule(id ID) *Schedule { return f.schedules[id] }
func (f *Firewall) Schedules() []*Schedule {
	out := make([]*Schedule, 0, len(f.data.Schedules))
	for _, r := range f.data.Schedules {
		out = append(out, f.schedules[r.ID])
	}
	return out
}
func (f *Firewall) Rule(id ID) *Rule { return f.rules[id] }
func (f *Firewall) Rules() []*Rule {
	out := make([]*Rule, 0, len(f.data.Rules))
	for _, r := range f.data.Rules {
		out = append(out, f.rules[r.ID])
	}
	return out
}
func (f *Firewall) RuleBinding(id ID) *RuleBinding { return f.ruleBindings[id] }
func (f *Firewall) RuleBindings() []*RuleBinding {
	out := make([]*RuleBinding, 0, len(f.data.RuleBindings))
	for _, r := range f.data.RuleBindings {
		out = append(out, f.ruleBindings[r.ID])
	}
	return out
}
func (f *Firewall) StaticNAT(id ID) *StaticNAT { return f.staticNATs[id] }
func (f *Firewall) StaticNATs() []*StaticNAT {
	out := make([]*StaticNAT, 0, len(f.data.StaticNATs))
	for _, r := range f.data.StaticNATs {
		out = append(out, f.staticNATs[r.ID])
	}
	return out
}
func (f *Firewall) DynamicNAT(id ID) *DynamicNAT { return f.dynamicNATs[id] }
func (f *Firewall) DynamicNATs() []*DynamicNAT {
	out := make([]*DynamicNAT, 0, len(f.data.DynamicNATs))
	for _, r := range f.data.DynamicNATs {
		out = append(out, f.dynamicNATs[r.ID])
	}
	return out
}
func (f *Firewall) NATPool(id ID) *NATPool { return f.natPools[id] }
func (f *Firewall) NATPools() []*NATPool {
	out := make([]*NATPool, 0, len(f.data.NATPools))
	for _, r := range f.data.NATPools {
		out = append(out, f.natPools[r.ID])
	}
	return out
}
func (f *Firewall) Metadata() Metadata        { return f.data.Metadata }
func (f *Firewall) Export() Data              { return f.data.Clone() }
func (f *Firewall) Complete() bool            { return len(f.diagnostics) == 0 }
func (f *Firewall) Diagnostics() []Diagnostic { return slices.Clone(f.diagnostics) }
func (f *Firewall) NATSequence() []NATEntry   { return slices.Clone(f.sequence) }
func (f *Firewall) SemanticDigest() string    { return f.digest }
func (f *Firewall) issue(id ID, code, message string) {
	f.diagnostics = append(f.diagnostics, Diagnostic{Object: id, Code: code, Message: message})
}
func add[T any](m map[ID]*T, o Object, v *T) error {
	if strings.TrimSpace(string(o.ID)) == "" {
		return fmt.Errorf("%w: empty object ID", ErrGraph)
	}
	if _, ok := m[o.ID]; ok {
		return fmt.Errorf("%w: duplicate ID %q", ErrGraph, o.ID)
	}
	m[o.ID] = v
	return nil
}

// Seal takes ownership of a deep copy, resolves references once, and exposes only immutable objects.
func Seal(data Data) (*Firewall, error) {
	if data.Metadata.Device == "" || data.Metadata.Vendor == "" {
		return nil, fmt.Errorf("%w: device and vendor required", ErrGraph)
	}
	sourceHash := sha256.Sum256([]byte(data.Raw))
	sourceDigest := hex.EncodeToString(sourceHash[:])
	if data.Metadata.SourceDigest != "" && data.Metadata.SourceDigest != sourceDigest {
		return nil, fmt.Errorf("%w: source checksum mismatch", ErrGraph)
	}
	if data.Raw != "" {
		data.Metadata.SourceDigest = sourceDigest
	}
	f := &Firewall{data: data.Clone(), diagnostics: slices.Clone(data.Diagnostics)}
	f.zones = make(map[ID]*Zone)
	for _, r := range f.data.Zones {
		if err := add(f.zones, r.Object, &Zone{record: r}); err != nil {
			return nil, err
		}
		for _, reason := range r.Unsupported {
			f.issue(r.ID, "unsupported", reason)
		}
	}
	f.interfaces = make(map[ID]*Interface)
	for _, r := range f.data.Interfaces {
		if err := add(f.interfaces, r.Object, &Interface{record: r}); err != nil {
			return nil, err
		}
		for _, reason := range r.Unsupported {
			f.issue(r.ID, "unsupported", reason)
		}
	}
	f.routes = make(map[ID]*Route)
	for _, r := range f.data.Routes {
		if err := add(f.routes, r.Object, &Route{record: r}); err != nil {
			return nil, err
		}
		for _, reason := range r.Unsupported {
			f.issue(r.ID, "unsupported", reason)
		}
	}
	f.addresses = make(map[ID]*Address)
	for _, r := range f.data.Addresses {
		if err := add(f.addresses, r.Object, &Address{record: r}); err != nil {
			return nil, err
		}
		for _, reason := range r.Unsupported {
			f.issue(r.ID, "unsupported", reason)
		}
	}
	f.addressGroups = make(map[ID]*AddressGroup)
	for _, r := range f.data.AddressGroups {
		if err := add(f.addressGroups, r.Object, &AddressGroup{record: r}); err != nil {
			return nil, err
		}
		for _, reason := range r.Unsupported {
			f.issue(r.ID, "unsupported", reason)
		}
	}
	f.services = make(map[ID]*Service)
	for _, r := range f.data.Services {
		if err := add(f.services, r.Object, &Service{record: r}); err != nil {
			return nil, err
		}
		for _, reason := range r.Unsupported {
			f.issue(r.ID, "unsupported", reason)
		}
	}
	f.serviceGroups = make(map[ID]*ServiceGroup)
	for _, r := range f.data.ServiceGroups {
		if err := add(f.serviceGroups, r.Object, &ServiceGroup{record: r}); err != nil {
			return nil, err
		}
		for _, reason := range r.Unsupported {
			f.issue(r.ID, "unsupported", reason)
		}
	}
	f.schedules = make(map[ID]*Schedule)
	for _, r := range f.data.Schedules {
		if err := add(f.schedules, r.Object, &Schedule{record: r}); err != nil {
			return nil, err
		}
		for _, reason := range r.Unsupported {
			f.issue(r.ID, "unsupported", reason)
		}
	}
	f.rules = make(map[ID]*Rule)
	for _, r := range f.data.Rules {
		if err := add(f.rules, r.Object, &Rule{record: r}); err != nil {
			return nil, err
		}
		for _, reason := range r.Unsupported {
			f.issue(r.ID, "unsupported", reason)
		}
	}
	f.ruleBindings = make(map[ID]*RuleBinding)
	for _, r := range f.data.RuleBindings {
		if err := add(f.ruleBindings, r.Object, &RuleBinding{record: r}); err != nil {
			return nil, err
		}
		for _, reason := range r.Unsupported {
			f.issue(r.ID, "unsupported", reason)
		}
	}
	f.staticNATs = make(map[ID]*StaticNAT)
	for _, r := range f.data.StaticNATs {
		if err := add(f.staticNATs, r.Object, &StaticNAT{record: r}); err != nil {
			return nil, err
		}
		for _, reason := range r.Unsupported {
			f.issue(r.ID, "unsupported", reason)
		}
	}
	f.dynamicNATs = make(map[ID]*DynamicNAT)
	for _, r := range f.data.DynamicNATs {
		if err := add(f.dynamicNATs, r.Object, &DynamicNAT{record: r}); err != nil {
			return nil, err
		}
		for _, reason := range r.Unsupported {
			f.issue(r.ID, "unsupported", reason)
		}
	}
	f.natPools = make(map[ID]*NATPool)
	for _, r := range f.data.NATPools {
		if err := add(f.natPools, r.Object, &NATPool{record: r}); err != nil {
			return nil, err
		}
		for _, reason := range r.Unsupported {
			f.issue(r.ID, "unsupported", reason)
		}
	}
	for _, e := range f.data.Evidence {
		if e.State == Pending {
			f.diagnostics = append(f.diagnostics, Diagnostic{Code: "unparsed", Message: fmt.Sprintf("unparsed source lines %d-%d", e.Span.First, e.Span.Last), Span: e.Span})
		}
	}
	for _, a := range f.Addresses() {
		set, err := flow.NewSet(a.record.Ranges...)
		if err != nil {
			return nil, err
		}
		a.set = set
		if a.record.FQDN != "" {
			f.issue(a.record.ID, "unresolved-fqdn", a.record.FQDN)
		}
	}
	for _, z := range f.Zones() {
		if _, err := flow.NewSet(z.record.Networks...); err != nil {
			return nil, err
		}
	}
	for _, i := range f.Interfaces() {
		if i.record.Zone != "" {
			i.zone = f.zones[i.record.Zone]
			if i.zone == nil {
				f.issue(i.record.ID, "missing-zone", string(i.record.Zone))
			} else {
				i.zone.interfaces = append(i.zone.interfaces, i)
			}
		}
		for _, p := range i.record.Addresses {
			if !p.IsValid() {
				return nil, fmt.Errorf("%w: invalid interface prefix", ErrGraph)
			}
		}
	}
	for _, r := range f.Routes() {
		if err := f.bindRoute(r); err != nil {
			return nil, err
		}
	}
	f.bindGroups()
	for _, s := range f.Services() {
		for _, term := range s.record.Terms {
			if err := validateService(term); err != nil {
				return nil, err
			}
		}
	}
	for _, s := range f.Schedules() {
		for _, w := range s.record.Windows {
			if w.Start.IsZero() || !w.Start.Before(w.End) {
				return nil, fmt.Errorf("%w: schedule window", ErrGraph)
			}
		}
		if len(s.record.Recurring) > 0 {
			f.issue(s.record.ID, "recurring-schedule", "native recurrence requires evaluation")
		}
	}
	for _, r := range f.Rules() {
		r.sources, r.sourceGroups = f.addressRefs(r.record.ID, r.record.Match.Sources)
		r.destinations, r.destinationGroups = f.addressRefs(r.record.ID, r.record.Match.Destinations)
		r.services, r.serviceGroups = f.serviceRefs(r.record.ID, r.record.Match.Services)
		if id := r.record.Match.Schedule; id != "" {
			r.schedule = f.schedules[id]
			if r.schedule == nil {
				f.issue(r.record.ID, "missing-schedule", string(id))
			}
		}
		f.validateMatch(r.record.ID, r.record.Match)
		if !r.record.Action.Valid() {
			f.issue(r.record.ID, "unknown-action", "unknown rule action")
		}
	}
	for _, b := range f.RuleBindings() {
		b.iface = f.interfaces[b.record.Interface]
		b.zone = f.zones[b.record.Zone]
		if b.record.Interface != "" && b.iface == nil || b.record.Zone != "" && b.zone == nil {
			f.issue(b.record.ID, "missing-binding", "unresolved rule binding")
		}
	}
	for _, p := range f.NATPools() {
		if _, err := flow.NewSet(p.record.Ranges...); err != nil {
			return nil, err
		}
		p.iface = f.interfaces[p.record.Interface]
		if p.record.Interface != "" && p.iface == nil {
			f.issue(p.record.ID, "missing-interface", string(p.record.Interface))
		}
	}
	for _, n := range f.StaticNATs() {
		r := n.record
		n.iface = f.interfaces[r.Interface]
		if r.Interface != "" && n.iface == nil {
			f.issue(r.ID, "missing-interface", string(r.Interface))
		}
		for _, mappings := range [][]Mapping{r.Source, r.Destination} {
			if err := f.validateMappings(r.ID, mappings); err != nil {
				return nil, err
			}
		}
		if err := f.validatePorts(r.ID, append(slices.Clone(r.SourcePorts), r.DestinationPorts...)); err != nil {
			return nil, err
		}
		f.validateMatch(r.ID, r.Match)
		n.match = f.matchObjects(r.ID, r.Match)
		f.sequence = append(f.sequence, NATEntry{Kind: StaticNATObject, ID: r.ID, Order: r.Order, Scope: r.Scope})
	}
	for _, n := range f.DynamicNATs() {
		r := n.record
		n.rule = f.rules[r.Rule]
		if r.Rule != "" {
			if n.rule == nil {
				f.issue(r.ID, "missing-rule", string(r.Rule))
			} else if owner := n.rule.record; !sameMatch(owner.Match, r.Match) || owner.Scope != r.Scope || owner.Disabled != r.Disabled || owner.Action != Permit {
				f.issue(r.ID, "policy-nat-mismatch", "translation must retain its owning permit policy's complete match and state")
			}
		}
		n.sourcePool = f.natPools[r.SourcePool]
		n.destinationPool = f.natPools[r.DestinationPool]
		n.iface = f.interfaces[r.Interface]
		if r.SourcePool != "" && n.sourcePool == nil || r.DestinationPool != "" && n.destinationPool == nil {
			f.issue(r.ID, "missing-pool", "unresolved dynamic NAT pool")
		}
		if r.Interface != "" && n.iface == nil {
			f.issue(r.ID, "missing-interface", string(r.Interface))
		}
		if r.SourceMode == UnknownTranslation || r.DestinationMode == UnknownTranslation {
			f.issue(r.ID, "unknown-translation", "unknown dynamic NAT mode")
		}
		if (r.SourceMode == DynamicIP || r.SourceMode == DynamicIPPort || r.SourceMode == StaticIP) && n.sourcePool == nil && n.iface == nil {
			f.issue(r.ID, "missing-allocation", "source translation has no pool or interface")
		}
		if r.SourceMode == InterfaceIP && n.iface == nil {
			f.issue(r.ID, "missing-allocation", "interface translation has no interface")
		}
		if r.DestinationMode != NoTranslation && r.DestinationMode != UnknownTranslation && n.destinationPool == nil && len(r.Destination) == 0 {
			f.issue(r.ID, "missing-allocation", "destination translation has no target")
		}
		if err := f.validateMappings(r.ID, r.Destination); err != nil {
			return nil, err
		}
		if err := f.validatePorts(r.ID, append(slices.Clone(r.SourcePorts), r.DestinationPorts...)); err != nil {
			return nil, err
		}
		f.validateMatch(r.ID, r.Match)
		n.match = f.matchObjects(r.ID, r.Match)
		f.sequence = append(f.sequence, NATEntry{Kind: DynamicNATObject, ID: r.ID, Order: r.Order, Scope: r.Scope})
	}
	slices.SortFunc(f.sequence, func(a, b NATEntry) int {
		if c := strings.Compare(a.Scope, b.Scope); c != 0 {
			return c
		}
		if a.Order.Stage != b.Order.Stage {
			return cmpInt(a.Order.Stage, b.Order.Stage)
		}
		if a.Order.Position != b.Order.Position {
			return cmpInt(a.Order.Position, b.Order.Position)
		}
		if a.Kind != b.Kind {
			return int(a.Kind) - int(b.Kind)
		}
		return strings.Compare(string(a.ID), string(b.ID))
	})
	var err error
	f.digest, err = semanticDigest(f.data)
	if err != nil {
		return nil, fmt.Errorf("%w: canonical declaration: %v", ErrGraph, err)
	}
	return f, nil
}
func cmpInt(a, b int) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}
func (f *Firewall) bindRoute(r *Route) error {
	if !r.record.Destination.IsValid() {
		return fmt.Errorf("%w: invalid route prefix", ErrGraph)
	}
	if r.record.Interface != "" {
		i := f.interfaces[r.record.Interface]
		if i != nil && i.record.Scope == r.record.Scope {
			r.iface = i
		} else {
			f.issue(r.record.ID, "missing-interface", "route interface missing or outside VRF")
		}
	} else if r.record.NextHop.IsValid() {
		best := -1
		var matches []*Interface
		for _, i := range f.Interfaces() {
			if i.record.Scope != r.record.Scope || i.record.Disabled {
				continue
			}
			local := -1
			for _, p := range i.record.Addresses {
				if p.Contains(r.record.NextHop) && p.Bits() > local {
					local = p.Bits()
				}
			}
			if local < 0 {
				continue
			}
			if local > best {
				best = local
				matches = []*Interface{i}
			} else if local == best {
				matches = append(matches, i)
			}
		}
		if len(matches) == 1 {
			r.iface = matches[0]
		} else {
			f.issue(r.record.ID, "unresolved-route", "next hop has no unique longest-prefix interface")
		}
	} else {
		f.issue(r.record.ID, "unresolved-route", "route lacks an interface or next hop")
	}
	if r.iface != nil {
		r.iface.routes = append(r.iface.routes, r)
	}
	return nil
}
func (f *Firewall) addressRefs(owner ID, refs []AddressRef) (as []*Address, gs []*AddressGroup) {
	for _, ref := range refs {
		switch ref.Kind {
		case AddressObject:
			if a := f.addresses[ref.ID]; a != nil {
				as = append(as, a)
			} else {
				f.issue(owner, "missing-address", string(ref.ID))
			}
		case AddressGroupObject:
			if g := f.addressGroups[ref.ID]; g != nil {
				gs = append(gs, g)
			} else {
				f.issue(owner, "missing-address-group", string(ref.ID))
			}
		default:
			f.issue(owner, "unknown-reference", "invalid address reference kind")
		}
	}
	return
}
func (f *Firewall) serviceRefs(owner ID, refs []ServiceRef) (ss []*Service, gs []*ServiceGroup) {
	for _, ref := range refs {
		switch ref.Kind {
		case ServiceObject:
			if s := f.services[ref.ID]; s != nil {
				ss = append(ss, s)
			} else {
				f.issue(owner, "missing-service", string(ref.ID))
			}
		case ServiceGroupObject:
			if g := f.serviceGroups[ref.ID]; g != nil {
				gs = append(gs, g)
			} else {
				f.issue(owner, "missing-service-group", string(ref.ID))
			}
		default:
			f.issue(owner, "unknown-reference", "invalid service reference kind")
		}
	}
	return
}
func (f *Firewall) bindGroups() {
	for _, g := range f.AddressGroups() {
		g.addresses, g.groups = f.addressRefs(g.record.ID, g.record.Members)
	}
	for _, g := range f.ServiceGroups() {
		g.services, g.groups = f.serviceRefs(g.record.ID, g.record.Members)
	}
	states := make(map[ID]uint8)
	var visit func(*AddressGroup)
	visit = func(g *AddressGroup) {
		if states[g.record.ID] == 1 {
			f.issue(g.record.ID, "group-cycle", "cyclic address group")
			return
		}
		if states[g.record.ID] == 2 {
			return
		}
		states[g.record.ID] = 1
		for _, child := range g.groups {
			visit(child)
		}
		states[g.record.ID] = 2
	}
	for _, g := range f.AddressGroups() {
		visit(g)
	}
	states = make(map[ID]uint8)
	var serviceVisit func(*ServiceGroup)
	serviceVisit = func(g *ServiceGroup) {
		if states[g.record.ID] == 1 {
			f.issue(g.record.ID, "group-cycle", "cyclic service group")
			return
		}
		if states[g.record.ID] == 2 {
			return
		}
		states[g.record.ID] = 1
		for _, child := range g.groups {
			serviceVisit(child)
		}
		states[g.record.ID] = 2
	}
	for _, g := range f.ServiceGroups() {
		serviceVisit(g)
	}
}
func (f *Firewall) validateMatch(owner ID, m Match) {
	if m.ZoneRelation != AnyZoneRelation && m.ZoneRelation != SameZone && m.ZoneRelation != DifferentZones {
		f.issue(owner, "unsupported-match", "unknown zone relation")
	}
	for _, id := range append(slices.Clone(m.FromZones), m.ToZones...) {
		if f.zones[id] == nil {
			f.issue(owner, "missing-zone", string(id))
		}
	}
	for _, reason := range m.Unsupported {
		f.issue(owner, "unsupported-match", reason)
	}
	if len(m.Applications) > 0 || len(m.Users) > 0 {
		f.issue(owner, "extended-match", "application/user match needs native evidence")
	}
	if m.Schedule != "" && f.schedules[m.Schedule] == nil {
		f.issue(owner, "missing-schedule", string(m.Schedule))
	}
}
func validateService(t ServiceTerm) error {
	for i, r := range []flow.Interval{t.Protocol, t.SourcePort, t.DestinationPort, t.ICMPType, t.ICMPCode} {
		max := uint16(65535)
		if i == 0 || i > 2 {
			max = 255
		}
		if r.Low > r.High || r.High > max {
			return fmt.Errorf("%w: invalid service interval", ErrGraph)
		}
	}
	return nil
}
func distance(r flow.Range) *big.Int {
	first, last := r.First.As16(), r.Last.As16()
	return new(big.Int).Sub(new(big.Int).SetBytes(last[:]), new(big.Int).SetBytes(first[:]))
}
func (f *Firewall) validateMappings(owner ID, mappings []Mapping) error {
	for i, a := range mappings {
		for _, b := range mappings[:i] {
			overlap, ok := a.Original.Intersection(b.Original)
			if !ok || a.Mode == UnknownMapping || b.Mode == UnknownMapping {
				continue
			}
			if !a.Translated.Valid() || !b.Translated.Valid() {
				continue
			}
			for _, endpoint := range []netip.Addr{overlap.First, overlap.Last} {
				if mappedNumber(a, endpoint).Cmp(mappedNumber(b, endpoint)) != 0 {
					return fmt.Errorf("%w: conflicting static mappings", ErrGraph)
				}
			}
		}
	}
	for _, m := range mappings {
		if !m.Original.Valid() || !m.Translated.Valid() || m.Original.First.BitLen() != m.Translated.First.BitLen() {
			return fmt.Errorf("%w: invalid NAT address interval", ErrGraph)
		}
		switch m.Mode {
		case UnknownMapping:
			f.issue(owner, "unknown-mapping", "NAT relation not declared")
		case Identity:
			if m.Original != m.Translated {
				return fmt.Errorf("%w: identity relation changes addresses", ErrGraph)
			}
		case Offset:
			if distance(m.Original).Cmp(distance(m.Translated)) != 0 {
				return fmt.Errorf("%w: unequal offset mapping sizes", ErrGraph)
			}
		case Constant:
			if m.Translated.First != m.Translated.Last {
				return fmt.Errorf("%w: constant relation requires single target", ErrGraph)
			}
		default:
			return fmt.Errorf("%w: invalid NAT mapping mode", ErrGraph)
		}
	}
	return nil
}
func (f *Firewall) validatePorts(owner ID, mappings []PortMapping) error {
	for _, m := range mappings {
		if m.Original.Low > m.Original.High || m.Translated.Low > m.Translated.High {
			return fmt.Errorf("%w: invalid NAT port interval", ErrGraph)
		}
		switch m.Mode {
		case UnknownMapping:
			f.issue(owner, "unknown-port-mapping", "port relation not declared")
		case Identity:
			if m.Original != m.Translated {
				return fmt.Errorf("%w: nonidentity port mapping", ErrGraph)
			}
		case Offset:
			if m.Original.High-m.Original.Low != m.Translated.High-m.Translated.Low {
				return fmt.Errorf("%w: unequal port offset sizes", ErrGraph)
			}
		case Constant:
			if m.Translated.Low != m.Translated.High {
				return fmt.Errorf("%w: port constant is not singular", ErrGraph)
			}
		default:
			return fmt.Errorf("%w: unknown port mapping enum", ErrGraph)
		}
	}
	return nil
}
func semanticDigest(d Data) (string, error) {
	d = d.Clone()
	d.Raw = ""
	d.Evidence = nil
	d.Diagnostics = nil
	d.Metadata.CapturedAt = time.Time{}
	d.Metadata.SourceDigest = ""
	for i := range d.Zones {
		d.Zones[i].Spans = nil
	}
	slices.SortFunc(d.Zones, func(a, b ZoneRecord) int { return strings.Compare(string(a.ID), string(b.ID)) })
	for i := range d.Interfaces {
		d.Interfaces[i].Spans = nil
	}
	slices.SortFunc(d.Interfaces, func(a, b InterfaceRecord) int { return strings.Compare(string(a.ID), string(b.ID)) })
	for i := range d.Routes {
		d.Routes[i].Spans = nil
	}
	slices.SortFunc(d.Routes, func(a, b RouteRecord) int { return strings.Compare(string(a.ID), string(b.ID)) })
	for i := range d.Addresses {
		d.Addresses[i].Spans = nil
	}
	slices.SortFunc(d.Addresses, func(a, b AddressRecord) int { return strings.Compare(string(a.ID), string(b.ID)) })
	for i := range d.AddressGroups {
		d.AddressGroups[i].Spans = nil
	}
	slices.SortFunc(d.AddressGroups, func(a, b AddressGroupRecord) int { return strings.Compare(string(a.ID), string(b.ID)) })
	for i := range d.Services {
		d.Services[i].Spans = nil
	}
	slices.SortFunc(d.Services, func(a, b ServiceRecord) int { return strings.Compare(string(a.ID), string(b.ID)) })
	for i := range d.ServiceGroups {
		d.ServiceGroups[i].Spans = nil
	}
	slices.SortFunc(d.ServiceGroups, func(a, b ServiceGroupRecord) int { return strings.Compare(string(a.ID), string(b.ID)) })
	for i := range d.Schedules {
		d.Schedules[i].Spans = nil
	}
	slices.SortFunc(d.Schedules, func(a, b ScheduleRecord) int { return strings.Compare(string(a.ID), string(b.ID)) })
	for i := range d.Rules {
		d.Rules[i].Spans = nil
	}
	slices.SortFunc(d.Rules, func(a, b RuleRecord) int { return strings.Compare(string(a.ID), string(b.ID)) })
	for i := range d.RuleBindings {
		d.RuleBindings[i].Spans = nil
	}
	slices.SortFunc(d.RuleBindings, func(a, b RuleBindingRecord) int { return strings.Compare(string(a.ID), string(b.ID)) })
	for i := range d.StaticNATs {
		d.StaticNATs[i].Spans = nil
	}
	slices.SortFunc(d.StaticNATs, func(a, b StaticNATRecord) int { return strings.Compare(string(a.ID), string(b.ID)) })
	for i := range d.DynamicNATs {
		d.DynamicNATs[i].Spans = nil
	}
	slices.SortFunc(d.DynamicNATs, func(a, b DynamicNATRecord) int { return strings.Compare(string(a.ID), string(b.ID)) })
	for i := range d.NATPools {
		d.NATPools[i].Spans = nil
	}
	slices.SortFunc(d.NATPools, func(a, b NATPoolRecord) int { return strings.Compare(string(a.ID), string(b.ID)) })
	b, err := json.Marshal(d)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func mappedNumber(m Mapping, addr netip.Addr) *big.Int {
	first, target, input := m.Original.First.As16(), m.Translated.First.As16(), addr.As16()
	n := new(big.Int).SetBytes(target[:])
	if m.Mode == Constant {
		return n
	}
	return n.Add(n, new(big.Int).Sub(new(big.Int).SetBytes(input[:]), new(big.Int).SetBytes(first[:])))
}

func (f *Firewall) matchObjects(owner ID, m Match) MatchObjects {
	var refs MatchObjects
	refs.sources, refs.sourceGroups = f.addressRefs(owner, m.Sources)
	refs.destinations, refs.destinationGroups = f.addressRefs(owner, m.Destinations)
	refs.services, refs.serviceGroups = f.serviceRefs(owner, m.Services)
	refs.schedule = f.schedules[m.Schedule]
	for _, id := range m.FromZones {
		if zone := f.zones[id]; zone != nil {
			refs.fromZones = append(refs.fromZones, zone)
		}
	}
	for _, id := range m.ToZones {
		if zone := f.zones[id]; zone != nil {
			refs.toZones = append(refs.toZones, zone)
		}
	}
	return refs
}
