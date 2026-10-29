package firemon

import (
	"slices"

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
	set           flow.Set
	vipStaticNAT  *StaticNAT
	vipDynamicNAT *DynamicNAT
}

func (o *Address) Record() AddressRecord { return o.record.clone() }
func (o *Address) Set() flow.Set         { return o.set }

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

type Service struct{ record ServiceRecord }

func (o *Service) Record() ServiceRecord { return o.record.clone() }

type ServiceGroup struct {
	record   ServiceGroupRecord
	services []*Service
	groups   []*ServiceGroup
}

func (o *ServiceGroup) Record() ServiceGroupRecord { return o.record.clone() }
func (o *ServiceGroup) Services() []*Service       { return slices.Clone(o.services) }
func (o *ServiceGroup) Groups() []*ServiceGroup    { return slices.Clone(o.groups) }

type Schedule struct{ record ScheduleRecord }

func (o *Schedule) Record() ScheduleRecord { return o.record.clone() }

type Rule struct {
	record RuleRecord
	match  MatchObjects
}

func (o *Rule) Record() RuleRecord                 { return o.record.clone() }
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
func (n *StaticNAT) Match() MatchObjects                  { return n.match }
func (n *DynamicNAT) Match() MatchObjects                 { return n.match }

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

func (o *Schedule) ID() ID        { return o.record.ID }
func (o *Schedule) Name() string  { return o.record.Name }
func (o *Schedule) Scope() string { return o.record.Scope }

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
func (o *Schedule) HasUnsupported() bool     { return len(o.record.Unsupported) != 0 }
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
