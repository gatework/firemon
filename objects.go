package firemon

import (
	"iter"
	"slices"
	"time"

	"github.com/gatework/firemon/flow"
)

type Zone struct {
	record     ZoneRecord
	interfaces []*Interface
}

func (o *Zone) Record() ZoneRecord       { return o.record.clone() }
func (o *Zone) Interfaces() []*Interface { return slices.Clone(o.interfaces) }

type Interface struct {
	record InterfaceRecord
	zone   *Zone
	routes []*Route
}

func (o *Interface) Record() InterfaceRecord { return o.record.clone() }
func (o *Interface) Zone() *Zone             { return o.zone }
func (o *Interface) Routes() []*Route        { return slices.Clone(o.routes) }

type Route struct {
	record RouteRecord
	iface  *Interface
}

func (o *Route) Record() RouteRecord   { return o.record.clone() }
func (o *Route) Interface() *Interface { return o.iface }

type Address struct {
	record        AddressRecord
	set           flow.AddressSet
	vipStaticNAT  *StaticNAT
	vipDynamicNAT *DynamicNAT
}

func (o *Address) Record() AddressRecord { return o.record.clone() }
func (o *Address) Set() flow.AddressSet  { return o.set }

// FQDN returns the declared unresolved hostname without copying address ranges.
func (o *Address) FQDN() string { return o.record.FQDN }

// VIP returns the declared translation reference, including unresolved targets.
func (o *Address) VIP() NATRef { return o.record.VIP }

// VIPStaticNAT and VIPDynamicNAT expose the declared VIP's concrete target.
// Both are nil for an ordinary address or an unresolved VIP reference.
func (o *Address) VIPStaticNAT() *StaticNAT   { return o.vipStaticNAT }
func (o *Address) VIPDynamicNAT() *DynamicNAT { return o.vipDynamicNAT }

type AddressGroup struct {
	record    AddressGroupRecord
	addresses []*Address
	groups    []*AddressGroup
}

func (o *AddressGroup) Record() AddressGroupRecord { return o.record.clone() }
func (o *AddressGroup) Addresses() []*Address      { return slices.Clone(o.addresses) }
func (o *AddressGroup) Groups() []*AddressGroup    { return slices.Clone(o.groups) }

// Members visits declared references as values, retaining unresolved members.
func (o *AddressGroup) Members() iter.Seq[AddressRef] {
	return func(yield func(AddressRef) bool) {
		for _, member := range o.record.Members {
			if !yield(member) {
				return
			}
		}
	}
}

type Service struct{ record ServiceRecord }

func (o *Service) Record() ServiceRecord { return o.record.clone() }

// Terms visits complete service tuples without copying the declaration container.
func (o *Service) Terms() iter.Seq[ServiceTerm] {
	return func(yield func(ServiceTerm) bool) {
		for _, term := range o.record.Terms {
			if !yield(term) {
				return
			}
		}
	}
}

type ServiceGroup struct {
	record   ServiceGroupRecord
	services []*Service
	groups   []*ServiceGroup
}

func (o *ServiceGroup) Record() ServiceGroupRecord { return o.record.clone() }
func (o *ServiceGroup) Services() []*Service       { return slices.Clone(o.services) }
func (o *ServiceGroup) Groups() []*ServiceGroup    { return slices.Clone(o.groups) }

// Members visits declared references as values, retaining unresolved members.
func (o *ServiceGroup) Members() iter.Seq[ServiceRef] {
	return func(yield func(ServiceRef) bool) {
		for _, member := range o.record.Members {
			if !yield(member) {
				return
			}
		}
	}
}

type Schedule struct {
	record        ScheduleRecord
	location      *time.Location
	isKnown       bool
	weeklyWindows int
}

func (s *Schedule) Record() ScheduleRecord { return s.record.clone() }

type Rule struct {
	record RuleRecord
	match  MatchObjects
}

func (o *Rule) Record() RuleRecord { return o.record.clone() }

// DeclarationSize counts the rule and its nested declaration values without
// copying them, for consumers that must bound owned Record views before reading.
func (o *Rule) DeclarationSize() int {
	var count declarationCounter
	count.object(o.record.Object)
	count.match(o.record.Match)
	return int(count)
}

func (o *Rule) Match() MatchObjects                { return o.match }
func (o *Rule) Sources() []*Address                { return o.match.Sources() }
func (o *Rule) Destinations() []*Address           { return o.match.Destinations() }
func (o *Rule) SourceGroups() []*AddressGroup      { return o.match.SourceGroups() }
func (o *Rule) DestinationGroups() []*AddressGroup { return o.match.DestinationGroups() }
func (o *Rule) Services() []*Service               { return o.match.Services() }
func (o *Rule) ServiceGroups() []*ServiceGroup     { return o.match.ServiceGroups() }
func (o *Rule) Schedule() *Schedule                { return o.match.Schedule() }
func (o *Rule) Position() int                      { return o.record.Position }
func (o *Rule) Chain() PolicyChain                 { return o.record.Chain() }

type RuleBinding struct {
	record RuleBindingRecord
	iface  *Interface
	zone   *Zone
}

func (o *RuleBinding) Record() RuleBindingRecord { return o.record.clone() }
func (o *RuleBinding) Interface() *Interface     { return o.iface }
func (o *RuleBinding) Zone() *Zone               { return o.zone }

type StaticNAT struct {
	match     MatchObjects
	record    StaticNATRecord
	iface     *Interface
	sourceVIP *Address
}

func (o *StaticNAT) Record() StaticNATRecord { return o.record.clone() }
func (o *StaticNAT) Interface() *Interface   { return o.iface }
func (o *StaticNAT) SourceVIP() *Address     { return o.sourceVIP }

type DynamicNAT struct {
	match                       MatchObjects
	record                      DynamicNATRecord
	rule                        *Rule
	sourcePool, destinationPool *NATPool
	iface                       *Interface
}

func (o *DynamicNAT) Record() DynamicNATRecord  { return o.record.clone() }
func (o *DynamicNAT) Rule() *Rule               { return o.rule }
func (o *DynamicNAT) SourcePool() *NATPool      { return o.sourcePool }
func (o *DynamicNAT) DestinationPool() *NATPool { return o.destinationPool }
func (o *DynamicNAT) Interface() *Interface     { return o.iface }

type NATPool struct {
	record NATPoolRecord
	iface  *Interface
}

func (o *NATPool) Record() NATPoolRecord { return o.record.clone() }
func (o *NATPool) Interface() *Interface { return o.iface }

// MatchObjects exposes resolved references while keeping each rule or NAT's native declaration intact.
// Container accessors return copies; all referenced domain objects are immutable and shared.
type MatchObjects struct {
	sources, destinations           []*Address
	sourceGroups, destinationGroups []*AddressGroup
	services                        []*Service
	serviceGroups                   []*ServiceGroup
	fromZones, toZones              []*Zone
	schedule                        *Schedule
}

func (m MatchObjects) Sources() []*Address                { return slices.Clone(m.sources) }
func (m MatchObjects) Destinations() []*Address           { return slices.Clone(m.destinations) }
func (m MatchObjects) SourceGroups() []*AddressGroup      { return slices.Clone(m.sourceGroups) }
func (m MatchObjects) DestinationGroups() []*AddressGroup { return slices.Clone(m.destinationGroups) }
func (m MatchObjects) Services() []*Service               { return slices.Clone(m.services) }
func (m MatchObjects) ServiceGroups() []*ServiceGroup     { return slices.Clone(m.serviceGroups) }
func (m MatchObjects) FromZones() []*Zone                 { return slices.Clone(m.fromZones) }
func (m MatchObjects) ToZones() []*Zone                   { return slices.Clone(m.toZones) }
func (m MatchObjects) Schedule() *Schedule                { return m.schedule }
func (o *StaticNAT) Match() MatchObjects                  { return o.match }
func (o *DynamicNAT) Match() MatchObjects                 { return o.match }

func (o *Zone) ID() ID        { return o.record.ID }
func (o *Zone) Name() string  { return o.record.Name }
func (o *Zone) Scope() string { return o.record.Scope }

func (o *Interface) ID() ID        { return o.record.ID }
func (o *Interface) Name() string  { return o.record.Name }
func (o *Interface) Scope() string { return o.record.Scope }

func (o *Route) ID() ID        { return o.record.ID }
func (o *Route) Name() string  { return o.record.Name }
func (o *Route) Scope() string { return o.record.Scope }

func (o *Address) ID() ID        { return o.record.ID }
func (o *Address) Name() string  { return o.record.Name }
func (o *Address) Scope() string { return o.record.Scope }

func (o *AddressGroup) ID() ID        { return o.record.ID }
func (o *AddressGroup) Name() string  { return o.record.Name }
func (o *AddressGroup) Scope() string { return o.record.Scope }

func (o *Service) ID() ID        { return o.record.ID }
func (o *Service) Name() string  { return o.record.Name }
func (o *Service) Scope() string { return o.record.Scope }

func (o *ServiceGroup) ID() ID        { return o.record.ID }
func (o *ServiceGroup) Name() string  { return o.record.Name }
func (o *ServiceGroup) Scope() string { return o.record.Scope }

func (s *Schedule) ID() ID        { return s.record.ID }
func (s *Schedule) Name() string  { return s.record.Name }
func (s *Schedule) Scope() string { return s.record.Scope }

func (o *Rule) ID() ID        { return o.record.ID }
func (o *Rule) Name() string  { return o.record.Name }
func (o *Rule) Scope() string { return o.record.Scope }

func (o *RuleBinding) ID() ID        { return o.record.ID }
func (o *RuleBinding) Name() string  { return o.record.Name }
func (o *RuleBinding) Scope() string { return o.record.Scope }

func (o *StaticNAT) ID() ID        { return o.record.ID }
func (o *StaticNAT) Name() string  { return o.record.Name }
func (o *StaticNAT) Scope() string { return o.record.Scope }

func (o *DynamicNAT) ID() ID        { return o.record.ID }
func (o *DynamicNAT) Name() string  { return o.record.Name }
func (o *DynamicNAT) Scope() string { return o.record.Scope }

func (o *NATPool) ID() ID        { return o.record.ID }
func (o *NATPool) Name() string  { return o.record.Name }
func (o *NATPool) Scope() string { return o.record.Scope }

// HasUnsupported reports unmodeled declarations on this object, not completeness
// of its references or of the surrounding firewall graph.
func (o *Zone) HasUnsupported() bool         { return len(o.record.Unsupported) != 0 }
func (o *Interface) HasUnsupported() bool    { return len(o.record.Unsupported) != 0 }
func (o *Route) HasUnsupported() bool        { return len(o.record.Unsupported) != 0 }
func (o *Address) HasUnsupported() bool      { return len(o.record.Unsupported) != 0 }
func (o *AddressGroup) HasUnsupported() bool { return len(o.record.Unsupported) != 0 }
func (o *Service) HasUnsupported() bool      { return len(o.record.Unsupported) != 0 }
func (o *ServiceGroup) HasUnsupported() bool { return len(o.record.Unsupported) != 0 }
func (s *Schedule) HasUnsupported() bool     { return len(s.record.Unsupported) != 0 }
func (o *Rule) HasUnsupported() bool         { return len(o.record.Unsupported) != 0 }
func (o *RuleBinding) HasUnsupported() bool  { return len(o.record.Unsupported) != 0 }
func (o *StaticNAT) HasUnsupported() bool    { return len(o.record.Unsupported) != 0 }
func (o *DynamicNAT) HasUnsupported() bool   { return len(o.record.Unsupported) != 0 }
func (o *NATPool) HasUnsupported() bool      { return len(o.record.Unsupported) != 0 }
func (o *Rule) Disabled() bool               { return o.record.Disabled }
func (o *Interface) Disabled() bool          { return o.record.Disabled }
func (o *StaticNAT) Disabled() bool          { return o.record.Disabled }
func (o *DynamicNAT) Disabled() bool         { return o.record.Disabled }
func (o *Rule) Builtin() bool                { return o.record.Builtin }
func (o *Rule) Action() Action               { return o.record.Action }
