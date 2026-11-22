package firemon

import (
	"maps"
	"slices"
	"time"
)

// Diagnostic reports a configuration line the parser did not understand, or
// understood but cannot model. Line is one-based; zero means not tied to a line.
type Diagnostic struct {
	Line   int    `json:"line,omitempty"`
	Text   string `json:"text,omitempty"`
	Reason string `json:"reason"`
}

// ModelVersion numbers the shape of Config and what its fingerprint
// covers. It changes whenever either does: a configuration stored by an
// older version is parsed again from its text rather than trusted.
const ModelVersion = 6

// Config is the declarative configuration of one firewall as produced by a
// vendor parser. Order is significant for Rules, DynamicNATs and
// StaticNATs; other lists are kept in declaration order.
type Config struct {
	Vendor    Vendor    `json:"vendor"`
	Hostname  string    `json:"hostname,omitempty"`
	Version   string    `json:"version,omitempty"`
	Semantics Semantics `json:"semantics"`
	// Location is the device time zone for schedules; nil means UTC.
	Location *time.Location `json:"-"`
	// TimeZone is the IANA name of Location, kept so a stored configuration
	// can restore it.
	TimeZone string `json:"time_zone,omitempty"`

	VirtualRouters []VirtualRouter `json:"virtual_routers,omitempty"`
	Zones          []Zone          `json:"zones,omitempty"`
	Interfaces     []Interface     `json:"interfaces,omitempty"`
	Routes         []Route         `json:"routes,omitempty"`
	Addresses      []Address       `json:"addresses,omitempty"`
	AddressGroups  []AddressGroup  `json:"address_groups,omitempty"`
	Services       []Service       `json:"services,omitempty"`
	ServiceGroups  []ServiceGroup  `json:"service_groups,omitempty"`
	Schedules      []Schedule      `json:"schedules,omitempty"`
	Rules          []SecurityRule  `json:"rules,omitempty"`
	RuleGroups     []RuleGroup     `json:"rule_groups,omitempty"`
	StaticNATs     []StaticNAT     `json:"static_nats,omitempty"`
	DynamicNATs    []DynamicNAT    `json:"dynamic_nats,omitempty"`
	PolicyRoutes   []PolicyRoute   `json:"policy_routes,omitempty"`
	PolicyBindings []PolicyBinding `json:"policy_bindings,omitempty"`
	// ExternalUses are references from constructs the model does not
	// evaluate, such as QoS pipes.
	ExternalUses []ExternalUse `json:"external_uses,omitempty"`
	Diagnostics  []Diagnostic  `json:"diagnostics,omitempty"`
	// Applications maps lowercase application names to their default
	// ports, for application-default services and application queries.
	Applications ServiceBook `json:"applications,omitempty"`
	// Source holds the configuration text of each object as the device
	// writes it, by SourceKey: what a query shows for a rule it hits, with
	// the objects the rule names. It is not part of the fingerprint.
	Source map[string][]string `json:"source,omitempty"`
	// ApplicationGroups maps lowercase predefined application group names
	// to their members (applications or groups), for rules that name a group.
	ApplicationGroups map[string][]string `json:"application_groups,omitempty"`
}

// Clone returns a deep copy of c that shares no slices with it.
func (c *Config) Clone() *Config {
	out := *c
	out.VirtualRouters = slices.Clone(c.VirtualRouters)
	out.Zones = slices.Clone(c.Zones)
	out.Interfaces = cloneEach(c.Interfaces, func(i Interface) Interface {
		i.Addresses, i.AddressObjects = slices.Clone(i.Addresses), slices.Clone(i.AddressObjects)
		return i
	})
	out.Routes = cloneEach(c.Routes, func(r Route) Route {
		r.Objects = slices.Clone(r.Objects)
		return r
	})
	out.Addresses = cloneEach(c.Addresses, func(a Address) Address {
		a.Entries, a.Invalid = slices.Clone(a.Entries), slices.Clone(a.Invalid)
		return a
	})
	out.AddressGroups = cloneEach(c.AddressGroups, func(g AddressGroup) AddressGroup {
		g.Members, g.Entries, g.Invalid = slices.Clone(g.Members), slices.Clone(g.Entries), slices.Clone(g.Invalid)
		return g
	})
	out.Services = cloneEach(c.Services, func(s Service) Service {
		s.Entries, s.Invalid = slices.Clone(s.Entries), slices.Clone(s.Invalid)
		return s
	})
	out.ServiceGroups = cloneEach(c.ServiceGroups, func(g ServiceGroup) ServiceGroup {
		g.Members = slices.Clone(g.Members)
		return g
	})
	out.Schedules = cloneEach(c.Schedules, func(s Schedule) Schedule {
		s.Windows = slices.Clone(s.Windows)
		s.Recurrences = cloneEach(s.Recurrences, func(r Recurrence) Recurrence {
			r.Days = slices.Clone(r.Days)
			r.MonthDays = slices.Clone(r.MonthDays)
			return r
		})
		return s
	})
	out.Rules = cloneEach(c.Rules, cloneRule)
	out.RuleGroups = slices.Clone(c.RuleGroups)
	out.StaticNATs = cloneEach(c.StaticNATs, func(n StaticNAT) StaticNAT {
		n.Zones, n.From = slices.Clone(n.Zones), slices.Clone(n.From)
		return n
	})
	out.DynamicNATs = cloneEach(c.DynamicNATs, func(n DynamicNAT) DynamicNAT {
		n.From, n.To = slices.Clone(n.From), slices.Clone(n.To)
		n.Source, n.Destination = slices.Clone(n.Source), slices.Clone(n.Destination)
		n.Services = slices.Clone(n.Services)
		n.TranslatedSource.Addresses = slices.Clone(n.TranslatedSource.Addresses)
		n.TranslatedDestination.Addresses = slices.Clone(n.TranslatedDestination.Addresses)
		n.Conditions = cloneConditions(n.Conditions)
		return n
	})
	out.PolicyRoutes = cloneEach(c.PolicyRoutes, func(p PolicyRoute) PolicyRoute {
		p.Source, p.Destination = slices.Clone(p.Source), slices.Clone(p.Destination)
		p.Services, p.Conditions = slices.Clone(p.Services), cloneConditions(p.Conditions)
		return p
	})
	out.PolicyBindings = slices.Clone(c.PolicyBindings)
	out.ExternalUses = slices.Clone(c.ExternalUses)
	out.Diagnostics = slices.Clone(c.Diagnostics)
	out.Applications = c.Applications.With(nil)
	out.ApplicationGroups = maps.Clone(c.ApplicationGroups)
	out.Source = maps.Clone(c.Source)
	return &out
}

func cloneRule(r SecurityRule) SecurityRule {
	r.From, r.To = slices.Clone(r.From), slices.Clone(r.To)
	r.Source, r.Destination = slices.Clone(r.Source), slices.Clone(r.Destination)
	r.Services = slices.Clone(r.Services)
	r.ServiceEntries = slices.Clone(r.ServiceEntries)
	r.Conditions = cloneConditions(r.Conditions)
	r.Inspection = slices.Clone(r.Inspection)
	return r
}

func cloneConditions(conds []Condition) []Condition {
	return cloneEach(conds, func(c Condition) Condition {
		c.Values = slices.Clone(c.Values)
		return c
	})
}

func cloneEach[T any](in []T, clone func(T) T) []T {
	if in == nil {
		return nil
	}
	out := make([]T, len(in))
	for i, v := range in {
		out[i] = clone(v)
	}
	return out
}

// Source kinds, the first part of a SourceKey.
const (
	SourceAddress      = "address"
	SourceAddressGroup = "address-group"
	SourceService      = "service"
	SourceServiceGroup = "service-group"
	SourceSchedule     = "schedule"
	SourceRule         = "rule"
)

// SourceKey names an object in Config.Source.
func SourceKey(kind, name string) string { return kind + ":" + name }

// AddSource appends the configuration lines of an object.
func (c *Config) AddSource(kind, name string, lines ...string) {
	if c.Source == nil {
		c.Source = map[string][]string{}
	}
	key := SourceKey(kind, name)
	c.Source[key] = append(c.Source[key], lines...)
}
