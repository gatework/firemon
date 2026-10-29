package firemon

import (
	"errors"
	"iter"
	"slices"
)

var ErrGraph = errors.New("invalid firewall graph")

type Firewall struct {
	data          Data
	orderedRules  []*Rule
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

// RuleCount returns the number of declarations without copying the rule view.
func (f *Firewall) RuleCount() int { return len(f.data.Rules) }

// ZoneCount returns the number of zones without copying their view.
func (f *Firewall) ZoneCount() int { return len(f.data.Zones) }

// ScheduleCount returns the number of schedules without copying their view.
func (f *Firewall) ScheduleCount() int { return len(f.data.Schedules) }

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

func (f *Firewall) Metadata() Metadata { return f.data.Metadata }

// Raw returns the immutable original configuration capture.
func (f *Firewall) Raw() string { return f.data.Raw }

// RecordCount counts top-level domain and source-evidence records without
// materializing their views. It counts records, not bytes or nested members.
func (f *Firewall) RecordCount() int {
	d := &f.data
	return len(d.Zones) + len(d.Interfaces) + len(d.Routes) + len(d.Addresses) + len(d.AddressGroups) + len(d.Services) + len(d.ServiceGroups) + len(d.Schedules) + len(d.Rules) + len(d.RuleBindings) + len(d.StaticNATs) + len(d.DynamicNATs) + len(d.NATPools) + len(d.Evidence) + len(d.Diagnostics)
}

func (f *Firewall) Export() Data { return f.data.Clone() }

func (f *Firewall) Complete() bool { return len(f.diagnostics) == 0 }

func (f *Firewall) Diagnostics() []Diagnostic { return slices.Clone(f.diagnostics) }

func (f *Firewall) NATSequence() []NATEntry { return slices.Clone(f.sequence) }

func (f *Firewall) SemanticDigest() string { return f.digest }

func (f *Firewall) issue(id ID, code, message string) {
	f.diagnostics = append(f.diagnostics, Diagnostic{Object: id, Code: code, Message: message})
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
