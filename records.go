// Package firemon owns immutable firewall configuration graphs.
package firemon

import (
	"github.com/gatework/firemon/flow"
	"net/netip"
	"slices"
	"time"
)

type ID string
type Kind uint8

const (
	UnknownObject Kind = iota
	AddressObject
	AddressGroupObject
	ServiceObject
	ServiceGroupObject
	StaticNATObject
	DynamicNATObject
)

type Status uint8

const (
	Unknown Status = iota
	Known
	Irrelevant
)

type Action uint8

const (
	UnknownAction Action = iota
	Permit
	Deny
	Reject
	Drop
	ResetClient
	ResetServer
	ResetBoth
)

func (a Action) Valid() bool { return a >= Permit && a <= ResetBoth }

type MappingMode uint8

const (
	UnknownMapping MappingMode = iota
	Identity
	Offset
	Constant
)

type TranslationMode uint8

const (
	UnknownTranslation TranslationMode = iota
	NoTranslation
	StaticIP
	DynamicIP
	DynamicIPPort
	InterfaceIP
)

type LineState uint8

const (
	Pending LineState = iota
	Parsed
	Ignored
)

// Span uses one-based physical line numbers. Optional byte offsets are zero-based
// and half-open; they distinguish XML fields on the same physical line.
type Span struct {
	First, Last        int
	StartByte, EndByte int
}
type Diagnostic struct {
	Code, Message string
	Object        ID
	Span          Span
}
type Evidence struct {
	Span   Span
	State  LineState
	Reason string
}
type Metadata struct {
	Device, Vendor, Software, ParserVersion, SourceDigest string
	// Context identifies the selected native configuration domain, such as a VDOM.
	Context    string
	CapturedAt time.Time
}

// Object IDs are unique within their typed catalog. Scope retains the native VRF/vsys/context.
type Object struct {
	ID          ID
	Name, Scope string
	// Inline identifies a value materialized from native inline syntax. It has
	// no independent native declaration once its final reference is removed.
	Inline      bool
	Spans       []Span
	Unsupported []string
}

func (o Object) clone() Object {
	o.Spans = slices.Clone(o.Spans)
	o.Unsupported = slices.Clone(o.Unsupported)
	return o
}

type AddressRef struct {
	Kind Kind
	ID   ID
}
type ServiceRef struct {
	Kind Kind
	ID   ID
}
type ZoneRecord struct {
	Object
	Networks []flow.Range
	// AddressScope is the native address-book namespace attached to this zone.
	// Empty means the global namespace; it is independent of a routing context.
	AddressScope string
}
type InterfaceRecord struct {
	Object
	Zone      ID
	Addresses []netip.Prefix
	Disabled  bool
	// Native security-level policy is meaningful only with explicit evidence.
	SecurityLevel      uint8
	SecurityLevelKnown bool
}
type RouteRecord struct {
	Object
	Destination netip.Prefix
	NextHop     netip.Addr
	Interface   ID
	Metric      uint32
	Direct      bool
	PolicyMatch []flow.Box
}
type AddressRecord struct {
	Object
	Ranges []flow.Range
	FQDN   string
}
type AddressGroupRecord struct {
	Object
	Members []AddressRef
}
type ServiceTerm struct{ Protocol, SourcePort, DestinationPort, ICMPType, ICMPCode flow.Interval }
type ServiceRecord struct {
	Object
	Terms []ServiceTerm
}
type ServiceGroupRecord struct {
	Object
	Members []ServiceRef
}
type TimeWindow struct{ Start, End time.Time }
type ScheduleRecord struct {
	Object
	Windows   []TimeWindow
	Timezone  string
	Recurring []string
}
type Match struct {
	Sources, Destinations []AddressRef
	Services              []ServiceRef
	FromZones, ToZones    []ID
	// Explicit wildcard flags distinguish any from empty and unresolved lists.
	AnySource, AnyDestination, AnyService, AnyFromZone, AnyToZone bool
	Schedule                                                      ID
	Applications, Users                                           []string
	Unsupported                                                   []string
	ZoneRelation                                                  ZoneRelation
}

type ZoneRelation uint8

const (
	AnyZoneRelation ZoneRelation = iota
	SameZone
	DifferentZones
)

func (m Match) clone() Match {
	m.Sources = slices.Clone(m.Sources)
	m.Destinations = slices.Clone(m.Destinations)
	m.Services = slices.Clone(m.Services)
	m.FromZones = slices.Clone(m.FromZones)
	m.ToZones = slices.Clone(m.ToZones)
	m.Applications = slices.Clone(m.Applications)
	m.Users = slices.Clone(m.Users)
	m.Unsupported = slices.Clone(m.Unsupported)
	return m
}

type RuleRecord struct {
	Object
	Match            Match
	Action           Action
	Position         int
	RuleSet          string
	Disabled         bool
	Log              Status
	LogStart, LogEnd Status
	// MatchVIP records native VIP matching for deny policies: Known enables it,
	// Irrelevant disables it, Unknown means the captured default is not established.
	MatchVIP    Status
	Builtin     bool
	Description string
}
type RuleBindingRecord struct {
	Object
	RuleSet         string
	Interface, Zone ID
	Direction       string
}
type NATOrder struct {
	Stage, Position int
	Section         string
}

// Mapping is an explicitly declared relation, never inferred from coincidentally equal set sizes.
type Mapping struct {
	Original, Translated flow.Range
	Mode                 MappingMode
}
type PortMapping struct {
	Original, Translated flow.Interval
	Mode                 MappingMode
}
type StaticNATRecord struct {
	Object
	Match                         Match
	Order                         NATOrder
	Source, Destination           []Mapping
	SourcePorts, DestinationPorts []PortMapping
	Interface                     ID
	Bidirectional, Disabled       bool
}
type NATPoolRecord struct {
	Object
	Ranges    []flow.Range
	Ports     flow.Interval
	Interface ID
}
type DynamicNATRecord struct {
	Object
	// Rule is the owning security policy for native policy-based translation.
	// Empty identifies an independent NAT declaration.
	Rule                                   ID
	Match                                  Match
	Order                                  NATOrder
	SourceMode, DestinationMode            TranslationMode
	SourcePool, DestinationPool, Interface ID
	// InterfaceAddress selects one configured host for InterfaceIP allocation.
	// Its zero value leaves selection to the established native interface mode.
	InterfaceAddress              netip.Addr
	Destination                   []Mapping
	SourcePorts, DestinationPorts []PortMapping
	Disabled                      bool
}

// NATEntry is an execution reference to either typed catalog, not a substitute NAT domain object.
type NATEntry struct {
	Kind  Kind
	ID    ID
	Order NATOrder
	Scope string
}

// Data is a concrete transport/construction representation. It contains no sessions, callbacks or interfaces.
type Data struct {
	Metadata      Metadata
	Raw           string
	Evidence      []Evidence
	Diagnostics   []Diagnostic
	Zones         []ZoneRecord
	Interfaces    []InterfaceRecord
	Routes        []RouteRecord
	Addresses     []AddressRecord
	AddressGroups []AddressGroupRecord
	Services      []ServiceRecord
	ServiceGroups []ServiceGroupRecord
	Schedules     []ScheduleRecord
	Rules         []RuleRecord
	RuleBindings  []RuleBindingRecord
	StaticNATs    []StaticNATRecord
	DynamicNATs   []DynamicNATRecord
	NATPools      []NATPoolRecord
}

func cloneRecords[T any](in []T, fn func(T) T) []T {
	out := make([]T, len(in))
	for i, v := range in {
		out[i] = fn(v)
	}
	return out
}
func (r ZoneRecord) clone() ZoneRecord {
	r.Object = r.Object.clone()
	r.Networks = slices.Clone(r.Networks)
	return r
}
func (r InterfaceRecord) clone() InterfaceRecord {
	r.Object = r.Object.clone()
	r.Addresses = slices.Clone(r.Addresses)
	return r
}
func (r RouteRecord) clone() RouteRecord {
	r.Object = r.Object.clone()
	r.PolicyMatch = slices.Clone(r.PolicyMatch)
	return r
}
func (r AddressRecord) clone() AddressRecord {
	r.Object = r.Object.clone()
	r.Ranges = slices.Clone(r.Ranges)
	return r
}
func (r AddressGroupRecord) clone() AddressGroupRecord {
	r.Object = r.Object.clone()
	r.Members = slices.Clone(r.Members)
	return r
}
func (r ServiceRecord) clone() ServiceRecord {
	r.Object = r.Object.clone()
	r.Terms = slices.Clone(r.Terms)
	return r
}
func (r ServiceGroupRecord) clone() ServiceGroupRecord {
	r.Object = r.Object.clone()
	r.Members = slices.Clone(r.Members)
	return r
}
func (r ScheduleRecord) clone() ScheduleRecord {
	r.Object = r.Object.clone()
	r.Windows = slices.Clone(r.Windows)
	r.Recurring = slices.Clone(r.Recurring)
	return r
}
func (r RuleRecord) clone() RuleRecord {
	r.Object = r.Object.clone()
	r.Match = r.Match.clone()
	return r
}
func (r RuleBindingRecord) clone() RuleBindingRecord { r.Object = r.Object.clone(); return r }
func (r StaticNATRecord) clone() StaticNATRecord {
	r.Object = r.Object.clone()
	r.Match = r.Match.clone()
	r.Source = slices.Clone(r.Source)
	r.Destination = slices.Clone(r.Destination)
	r.SourcePorts = slices.Clone(r.SourcePorts)
	r.DestinationPorts = slices.Clone(r.DestinationPorts)
	return r
}
func (r DynamicNATRecord) clone() DynamicNATRecord {
	r.Object = r.Object.clone()
	r.Match = r.Match.clone()
	r.Destination = slices.Clone(r.Destination)
	r.SourcePorts = slices.Clone(r.SourcePorts)
	r.DestinationPorts = slices.Clone(r.DestinationPorts)
	return r
}
func (r NATPoolRecord) clone() NATPoolRecord {
	r.Object = r.Object.clone()
	r.Ranges = slices.Clone(r.Ranges)
	return r
}
func (d Data) Clone() Data {
	d.Evidence = slices.Clone(d.Evidence)
	d.Diagnostics = slices.Clone(d.Diagnostics)
	d.Zones = cloneRecords(d.Zones, ZoneRecord.clone)
	d.Interfaces = cloneRecords(d.Interfaces, InterfaceRecord.clone)
	d.Routes = cloneRecords(d.Routes, RouteRecord.clone)
	d.Addresses = cloneRecords(d.Addresses, AddressRecord.clone)
	d.AddressGroups = cloneRecords(d.AddressGroups, AddressGroupRecord.clone)
	d.Services = cloneRecords(d.Services, ServiceRecord.clone)
	d.ServiceGroups = cloneRecords(d.ServiceGroups, ServiceGroupRecord.clone)
	d.Schedules = cloneRecords(d.Schedules, ScheduleRecord.clone)
	d.Rules = cloneRecords(d.Rules, RuleRecord.clone)
	d.RuleBindings = cloneRecords(d.RuleBindings, RuleBindingRecord.clone)
	d.StaticNATs = cloneRecords(d.StaticNATs, StaticNATRecord.clone)
	d.DynamicNATs = cloneRecords(d.DynamicNATs, DynamicNATRecord.clone)
	d.NATPools = cloneRecords(d.NATPools, NATPoolRecord.clone)
	return d
}
