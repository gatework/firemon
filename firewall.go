package firemon

import (
	"errors"
	"iter"
	"slices"
)

var ErrGraph = errors.New("invalid firewall graph")

type Firewall struct {
	data            Data
	orderedRules    []*Rule
	diagnostics     []Diagnostic
	sequence        []NATEntry
	digest          string
	declarationSize int
	zones           map[ID]*Zone
	interfaces      map[ID]*Interface
	routes          map[ID]*Route
	addresses       map[ID]*Address
	addressGroups   map[ID]*AddressGroup
	services        map[ID]*Service
	serviceGroups   map[ID]*ServiceGroup
	schedules       map[ID]*Schedule
	rules           map[ID]*Rule
	ruleBindings    map[ID]*RuleBinding
	staticNATs      map[ID]*StaticNAT
	dynamicNATs     map[ID]*DynamicNAT
	natPools        map[ID]*NATPool
}

func (f *Firewall) Zone(id ID) *Zone { return f.zones[id] }

func (f *Firewall) Zones() []*Zone { return views(f.data.Zones, f.zones) }

func (f *Firewall) Interface(id ID) *Interface { return f.interfaces[id] }

func (f *Firewall) Interfaces() []*Interface { return views(f.data.Interfaces, f.interfaces) }

func (f *Firewall) Route(id ID) *Route { return f.routes[id] }

func (f *Firewall) Routes() []*Route { return views(f.data.Routes, f.routes) }

func (f *Firewall) Address(id ID) *Address { return f.addresses[id] }

func (f *Firewall) Addresses() []*Address { return views(f.data.Addresses, f.addresses) }

func (f *Firewall) AddressGroup(id ID) *AddressGroup { return f.addressGroups[id] }

func (f *Firewall) AddressGroups() []*AddressGroup {
	return views(f.data.AddressGroups, f.addressGroups)
}

func (f *Firewall) Service(id ID) *Service { return f.services[id] }

func (f *Firewall) Services() []*Service { return views(f.data.Services, f.services) }

func (f *Firewall) ServiceGroup(id ID) *ServiceGroup { return f.serviceGroups[id] }

func (f *Firewall) ServiceGroups() []*ServiceGroup {
	return views(f.data.ServiceGroups, f.serviceGroups)
}

func (f *Firewall) Schedule(id ID) *Schedule { return f.schedules[id] }

func (f *Firewall) Schedules() []*Schedule { return views(f.data.Schedules, f.schedules) }

func (f *Firewall) Rule(id ID) *Rule { return f.rules[id] }

// RuleCount returns the number of declarations without copying the rule view.
func (f *Firewall) RuleCount() int { return len(f.data.Rules) }

// ZoneCount returns the number of zones without copying their view.
func (f *Firewall) ZoneCount() int { return len(f.data.Zones) }

// ScheduleCount returns the number of schedules without copying their view.
func (f *Firewall) ScheduleCount() int { return len(f.data.Schedules) }

func (f *Firewall) Rules() []*Rule { return views(f.data.Rules, f.rules) }

// DeclaredRules visits immutable rules in source declaration order without
// copying their view. OrderedRules instead follows native evaluation position.
func (f *Firewall) DeclaredRules() iter.Seq[*Rule] {
	return func(yield func(*Rule) bool) {
		for _, r := range f.data.Rules {
			if !yield(f.rules[r.ID]) {
				return
			}
		}
	}
}

func (f *Firewall) RuleBinding(id ID) *RuleBinding { return f.ruleBindings[id] }

func (f *Firewall) RuleBindings() []*RuleBinding { return views(f.data.RuleBindings, f.ruleBindings) }

func (f *Firewall) StaticNAT(id ID) *StaticNAT { return f.staticNATs[id] }

// StaticNATCount returns the number of static translations without copying their view.
func (f *Firewall) StaticNATCount() int { return len(f.data.StaticNATs) }

func (f *Firewall) StaticNATs() []*StaticNAT { return views(f.data.StaticNATs, f.staticNATs) }

func (f *Firewall) DynamicNAT(id ID) *DynamicNAT { return f.dynamicNATs[id] }

// DynamicNATCount returns the number of dynamic translations without copying their view.
func (f *Firewall) DynamicNATCount() int { return len(f.data.DynamicNATs) }

func (f *Firewall) DynamicNATs() []*DynamicNAT { return views(f.data.DynamicNATs, f.dynamicNATs) }

func (f *Firewall) NATPool(id ID) *NATPool { return f.natPools[id] }

func (f *Firewall) NATPools() []*NATPool { return views(f.data.NATPools, f.natPools) }

func (f *Firewall) Metadata() Metadata { return f.data.Metadata }

// Raw returns the immutable original configuration capture.
func (f *Firewall) Raw() string { return f.data.Raw }

// RecordCount counts top-level domain and source-evidence records without
// materializing their views. It counts records, not bytes or nested members.
func (f *Firewall) RecordCount() int {
	d := &f.data
	return len(d.Zones) + len(d.Interfaces) + len(d.Routes) + len(d.Addresses) + len(d.AddressGroups) + len(d.Services) + len(d.ServiceGroups) + len(d.Schedules) + len(d.Rules) + len(d.RuleBindings) + len(d.StaticNATs) + len(d.DynamicNATs) + len(d.NATPools) + len(d.Evidence) + len(d.Diagnostics)
}

// DeclarationSize counts records and nested structural elements without
// exporting or allocating a copy. It is a conservative work estimate for proof
// preflights; retained raw text and scalar string bytes are not counted.
func (f *Firewall) DeclarationSize() int { return f.declarationSize }

func (f *Firewall) Export() Data { return f.data.Clone() }

func (f *Firewall) Complete() bool { return len(f.diagnostics) == 0 }

func (f *Firewall) Diagnostics() []Diagnostic { return slices.Clone(f.diagnostics) }

// DiagnosticCount allows bounded consumers to charge before copying evidence.
func (f *Firewall) DiagnosticCount() int { return len(f.diagnostics) }

func (f *Firewall) NATSequence() []NATEntry { return slices.Clone(f.sequence) }

func (f *Firewall) SemanticDigest() string { return f.digest }

// views returns the sealed objects for records in declaration order.
func views[R any, P catalogRecord[R], T any](records []R, index map[ID]*T) []*T {
	out := make([]*T, 0, len(records))
	for i := range records {
		out = append(out, index[P(&records[i]).object().ID])
	}
	return out
}

func (f *Firewall) issue(id ID, code, message string) {
	f.diagnostics = append(f.diagnostics, Diagnostic{Object: id, Code: code, Message: message})
}

// unsupported reports each unmodeled declaration retained by o.
func (f *Firewall) unsupported(o Object) {
	for _, reason := range o.Unsupported {
		f.issue(o.ID, "unsupported", reason)
	}
}

// OrderedRules visits immutable rules by native position and stable identity.
// Rules retains source declaration order; neither view exposes index storage.
func (f *Firewall) OrderedRules() iter.Seq[*Rule] {
	return func(yield func(*Rule) bool) {
		for _, rule := range f.orderedRules {
			if !yield(rule) {
				return
			}
		}
	}
}
