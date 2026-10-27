package firemon

import (
	"github.com/gatework/firemon/flow"
	"slices"
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
	record AddressRecord
	set    flow.Set
}

func (o *Address) Record() AddressRecord { return o.record.clone() }
func (o *Address) Set() flow.Set         { return o.set }

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
	record                          RuleRecord
	sources, destinations           []*Address
	sourceGroups, destinationGroups []*AddressGroup
	services                        []*Service
	serviceGroups                   []*ServiceGroup
	schedule                        *Schedule
}

func (o *Rule) Record() RuleRecord                 { return o.record.clone() }
func (o *Rule) Sources() []*Address                { return slices.Clone(o.sources) }
func (o *Rule) Destinations() []*Address           { return slices.Clone(o.destinations) }
func (o *Rule) SourceGroups() []*AddressGroup      { return slices.Clone(o.sourceGroups) }
func (o *Rule) DestinationGroups() []*AddressGroup { return slices.Clone(o.destinationGroups) }
func (o *Rule) Services() []*Service               { return slices.Clone(o.services) }
func (o *Rule) ServiceGroups() []*ServiceGroup     { return slices.Clone(o.serviceGroups) }
func (o *Rule) Schedule() *Schedule                { return o.schedule }

type RuleBinding struct {
	record RuleBindingRecord
	iface  *Interface
	zone   *Zone
}

func (o *RuleBinding) Record() RuleBindingRecord { return o.record.clone() }
func (o *RuleBinding) Interface() *Interface     { return o.iface }
func (o *RuleBinding) Zone() *Zone               { return o.zone }

type StaticNAT struct {
	match  MatchObjects
	record StaticNATRecord
	iface  *Interface
}

func (o *StaticNAT) Record() StaticNATRecord { return o.record.clone() }
func (o *StaticNAT) Interface() *Interface   { return o.iface }

type DynamicNAT struct {
	match                       MatchObjects
	record                      DynamicNATRecord
	sourcePool, destinationPool *NATPool
	iface                       *Interface
}

func (o *DynamicNAT) Record() DynamicNATRecord  { return o.record.clone() }
func (o *DynamicNAT) SourcePool() *NATPool      { return o.sourcePool }
func (o *DynamicNAT) DestinationPool() *NATPool { return o.destinationPool }
func (o *DynamicNAT) Interface() *Interface     { return o.iface }

type NATPool struct {
	record NATPoolRecord
	iface  *Interface
}

func (o *NATPool) Record() NATPoolRecord { return o.record.clone() }
func (o *NATPool) Interface() *Interface { return o.iface }

// MatchObjects exposes resolved references while keeping each NAT's native declaration intact.
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
