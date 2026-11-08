package config

import (
	"context"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"time"

	fm "github.com/gatework/firemon"
)

// Builder owns the ordered, typed records for one parse. It is local to a single
// Parse invocation: readers get copies, and only successful transactions mutate
// records and source evidence. Native merge and name-resolution rules stay in
// the vendor parser.
type Builder struct {
	content       *Content
	metadata      fm.Metadata
	diagnostics   []fm.Diagnostic
	sealed        *fm.Firewall
	phase         *phaseFrame
	undo          []func()
	evidenceUndo  []evidenceUndo
	zones         recordTable[fm.ZoneRecord]
	interfaces    recordTable[fm.InterfaceRecord]
	routes        recordTable[fm.RouteRecord]
	addresses     recordTable[fm.AddressRecord]
	addressGroups recordTable[fm.AddressGroupRecord]
	services      recordTable[fm.ServiceRecord]
	serviceGroups recordTable[fm.ServiceGroupRecord]
	schedules     recordTable[fm.ScheduleRecord]
	rules         recordTable[fm.RuleRecord]
	ruleBindings  recordTable[fm.RuleBindingRecord]
	staticNATs    recordTable[fm.StaticNATRecord]
	dynamicNATs   recordTable[fm.DynamicNATRecord]
	natPools      recordTable[fm.NATPoolRecord]

	serviceTermCount int
}

type phaseFrame struct{ parent *phaseFrame }
type evidenceUndo struct {
	index    int
	previous fm.Evidence
}

type recordTable[T any] struct {
	records []T
	index   map[fm.ID]int
}

// NewBuilder gives one builder exclusive ownership of a content's claims.
func NewBuilder(c *Content, m fm.Metadata) (*Builder, error) {
	if c == nil || c.text == nil || c.owner != nil {
		return nil, ErrInvalid
	}
	sum := c.text.Digest()
	m.SourceDigest = hex.EncodeToString(sum[:])
	if c.source.ScheduleClock != nil {
		clock := *c.source.ScheduleClock
		if err := clock.Validate(m); err != nil {
			return nil, err
		}
		c.source.ScheduleClock = &clock
	}
	b := &Builder{content: c, metadata: m}
	c.owner = b
	return b, nil
}

func (b *Builder) Content() *Content     { return b.content }
func (b *Builder) Metadata() fm.Metadata { return b.metadata }
func (b *Builder) AddressCount() int     { return len(b.addresses.records) }

// Data returns a deep copy of the accepted records, raw source and evidence.
// Normal parsing uses typed lookups instead of repeatedly copying this view.
func (b *Builder) Data() fm.Data { return b.data().Clone() }

func (b *Builder) data() fm.Data {
	d := fm.Data{Metadata: b.metadata, Raw: b.content.source.Text, Evidence: b.content.evidence, Diagnostics: b.diagnostics,
		Zones:         b.zones.records,
		Interfaces:    b.interfaces.records,
		Routes:        b.routes.records,
		Addresses:     b.addresses.records,
		AddressGroups: b.addressGroups.records,
		Services:      b.services.records,
		ServiceGroups: b.serviceGroups.records,
		Schedules:     b.schedules.records,
		Rules:         b.rules.records,
		RuleBindings:  b.ruleBindings.records,
		StaticNATs:    b.staticNATs.records,
		DynamicNATs:   b.dynamicNATs.records,
		NATPools:      b.natPools.records,
	}
	if !b.content.source.Complete {
		d.Diagnostics = append(slices.Clone(d.Diagnostics), fm.Diagnostic{Code: "incomplete-source", Message: "capture completeness was not established"})
	}
	return d
}

// Seal returns an immutable graph, reusing it until records or claims change.
// Seal itself makes the ownership copy; a preceding Data copy is unnecessary.
func (b *Builder) Seal() (*fm.Firewall, error) {
	if b == nil || b.content == nil {
		return nil, ErrInvalid
	}
	if b.sealed != nil {
		return b.sealed, nil
	}
	graph, err := fm.Seal(b.data())
	if err != nil {
		return nil, err
	}
	b.sealed = graph
	return graph, nil
}

// Phase runs an explicitly ordered native parse phase. A failed or canceled
// phase restores records, identity indexes and source claims.
// Nested phases keep their undo records until the outer phase succeeds.
func (b *Builder) Phase(ctx context.Context, name string, run func(context.Context, *Builder) error) (err error) {
	if err = ctx.Err(); err != nil {
		return err
	}
	if b == nil || b.content == nil || strings.TrimSpace(name) == "" || run == nil {
		return ErrInvalid
	}
	frame := &phaseFrame{parent: b.phase}
	b.phase = frame
	undoStart, evidenceStart := len(b.undo), len(b.evidenceUndo)
	diagnosticsStart := len(b.diagnostics)
	cached := b.sealed
	zonesStart := len(b.zones.records)
	interfacesStart := len(b.interfaces.records)
	routesStart := len(b.routes.records)
	addressesStart := len(b.addresses.records)
	addressGroupsStart := len(b.addressGroups.records)
	servicesStart := len(b.services.records)
	serviceTermsStart := b.serviceTermCount
	serviceGroupsStart := len(b.serviceGroups.records)
	schedulesStart := len(b.schedules.records)
	rulesStart := len(b.rules.records)
	ruleBindingsStart := len(b.ruleBindings.records)
	staticNATsStart := len(b.staticNATs.records)
	dynamicNATsStart := len(b.dynamicNATs.records)
	natPoolsStart := len(b.natPools.records)
	success := false
	defer func() {
		if !success {
			for i := len(b.undo) - 1; i >= undoStart; i-- {
				b.undo[i]()
			}
			truncateRecords(&b.zones, zonesStart, func(r fm.ZoneRecord) fm.ID { return r.ID })
			truncateRecords(&b.interfaces, interfacesStart, func(r fm.InterfaceRecord) fm.ID { return r.ID })
			truncateRecords(&b.routes, routesStart, func(r fm.RouteRecord) fm.ID { return r.ID })
			truncateRecords(&b.addresses, addressesStart, func(r fm.AddressRecord) fm.ID { return r.ID })
			truncateRecords(&b.addressGroups, addressGroupsStart, func(r fm.AddressGroupRecord) fm.ID { return r.ID })
			truncateRecords(&b.services, servicesStart, func(r fm.ServiceRecord) fm.ID { return r.ID })
			b.serviceTermCount = serviceTermsStart
			truncateRecords(&b.serviceGroups, serviceGroupsStart, func(r fm.ServiceGroupRecord) fm.ID { return r.ID })
			truncateRecords(&b.schedules, schedulesStart, func(r fm.ScheduleRecord) fm.ID { return r.ID })
			truncateRecords(&b.rules, rulesStart, func(r fm.RuleRecord) fm.ID { return r.ID })
			truncateRecords(&b.ruleBindings, ruleBindingsStart, func(r fm.RuleBindingRecord) fm.ID { return r.ID })
			truncateRecords(&b.staticNATs, staticNATsStart, func(r fm.StaticNATRecord) fm.ID { return r.ID })
			truncateRecords(&b.dynamicNATs, dynamicNATsStart, func(r fm.DynamicNATRecord) fm.ID { return r.ID })
			truncateRecords(&b.natPools, natPoolsStart, func(r fm.NATPoolRecord) fm.ID { return r.ID })
			b.diagnostics = b.diagnostics[:diagnosticsStart]
			for i := len(b.evidenceUndo) - 1; i >= evidenceStart; i-- {
				u := b.evidenceUndo[i]
				b.content.evidence[u.index] = u.previous
			}
			b.evidenceUndo = b.evidenceUndo[:evidenceStart]
			clear(b.undo[undoStart:])
			b.undo = b.undo[:undoStart]
			b.sealed = cached
		}
		b.phase = frame.parent
		if b.phase == nil {
			b.undo = nil
			b.evidenceUndo = nil
		}
	}()
	if err = run(ctx, b); err == nil {
		err = ctx.Err()
	}
	if err != nil {
		return fmt.Errorf("phase %s: %w", name, err)
	}
	success = true
	return nil
}

func truncateRecords[T any](table *recordTable[T], length int, id func(T) fm.ID) {
	for _, r := range table.records[length:] {
		delete(table.index, id(r))
	}
	clear(table.records[length:])
	table.records = table.records[:length]
}

// Typed accessors return isolated records; their maps are lookup indexes only.
func (b *Builder) Zones() []fm.ZoneRecord {
	return (fm.Data{Zones: b.zones.records}).Clone().Zones
}
func (b *Builder) Zone(id fm.ID) (fm.ZoneRecord, bool) {
	i, ok := b.zones.index[id]
	if !ok {
		return fm.ZoneRecord{}, false
	}
	d := (fm.Data{Zones: []fm.ZoneRecord{b.zones.records[i]}}).Clone()
	return d.Zones[0], true
}
func (b *Builder) Interfaces() []fm.InterfaceRecord {
	return (fm.Data{Interfaces: b.interfaces.records}).Clone().Interfaces
}
func (b *Builder) Interface(id fm.ID) (fm.InterfaceRecord, bool) {
	i, ok := b.interfaces.index[id]
	if !ok {
		return fm.InterfaceRecord{}, false
	}
	d := (fm.Data{Interfaces: []fm.InterfaceRecord{b.interfaces.records[i]}}).Clone()
	return d.Interfaces[0], true
}
func (b *Builder) Routes() []fm.RouteRecord {
	return (fm.Data{Routes: b.routes.records}).Clone().Routes
}
func (b *Builder) Route(id fm.ID) (fm.RouteRecord, bool) {
	i, ok := b.routes.index[id]
	if !ok {
		return fm.RouteRecord{}, false
	}
	d := (fm.Data{Routes: []fm.RouteRecord{b.routes.records[i]}}).Clone()
	return d.Routes[0], true
}
func (b *Builder) Addresses() []fm.AddressRecord {
	return (fm.Data{Addresses: b.addresses.records}).Clone().Addresses
}
func (b *Builder) Address(id fm.ID) (fm.AddressRecord, bool) {
	i, ok := b.addresses.index[id]
	if !ok {
		return fm.AddressRecord{}, false
	}
	d := (fm.Data{Addresses: []fm.AddressRecord{b.addresses.records[i]}}).Clone()
	return d.Addresses[0], true
}
func (b *Builder) AddressGroups() []fm.AddressGroupRecord {
	return (fm.Data{AddressGroups: b.addressGroups.records}).Clone().AddressGroups
}
func (b *Builder) AddressGroup(id fm.ID) (fm.AddressGroupRecord, bool) {
	i, ok := b.addressGroups.index[id]
	if !ok {
		return fm.AddressGroupRecord{}, false
	}
	d := (fm.Data{AddressGroups: []fm.AddressGroupRecord{b.addressGroups.records[i]}}).Clone()
	return d.AddressGroups[0], true
}
func (b *Builder) Services() []fm.ServiceRecord {
	return (fm.Data{Services: b.services.records}).Clone().Services
}
func (b *Builder) Service(id fm.ID) (fm.ServiceRecord, bool) {
	i, ok := b.services.index[id]
	if !ok {
		return fm.ServiceRecord{}, false
	}
	d := (fm.Data{Services: []fm.ServiceRecord{b.services.records[i]}}).Clone()
	return d.Services[0], true
}
func (b *Builder) ServiceGroups() []fm.ServiceGroupRecord {
	return (fm.Data{ServiceGroups: b.serviceGroups.records}).Clone().ServiceGroups
}
func (b *Builder) ServiceGroup(id fm.ID) (fm.ServiceGroupRecord, bool) {
	i, ok := b.serviceGroups.index[id]
	if !ok {
		return fm.ServiceGroupRecord{}, false
	}
	d := (fm.Data{ServiceGroups: []fm.ServiceGroupRecord{b.serviceGroups.records[i]}}).Clone()
	return d.ServiceGroups[0], true
}
func (b *Builder) Schedules() []fm.ScheduleRecord {
	return (fm.Data{Schedules: b.schedules.records}).Clone().Schedules
}
func (b *Builder) Schedule(id fm.ID) (fm.ScheduleRecord, bool) {
	i, ok := b.schedules.index[id]
	if !ok {
		return fm.ScheduleRecord{}, false
	}
	d := (fm.Data{Schedules: []fm.ScheduleRecord{b.schedules.records[i]}}).Clone()
	return d.Schedules[0], true
}
func (b *Builder) Rules() []fm.RuleRecord {
	return (fm.Data{Rules: b.rules.records}).Clone().Rules
}
func (b *Builder) Rule(id fm.ID) (fm.RuleRecord, bool) {
	i, ok := b.rules.index[id]
	if !ok {
		return fm.RuleRecord{}, false
	}
	d := (fm.Data{Rules: []fm.RuleRecord{b.rules.records[i]}}).Clone()
	return d.Rules[0], true
}
func (b *Builder) RuleBindings() []fm.RuleBindingRecord {
	return (fm.Data{RuleBindings: b.ruleBindings.records}).Clone().RuleBindings
}
func (b *Builder) RuleBinding(id fm.ID) (fm.RuleBindingRecord, bool) {
	i, ok := b.ruleBindings.index[id]
	if !ok {
		return fm.RuleBindingRecord{}, false
	}
	d := (fm.Data{RuleBindings: []fm.RuleBindingRecord{b.ruleBindings.records[i]}}).Clone()
	return d.RuleBindings[0], true
}
func (b *Builder) StaticNATs() []fm.StaticNATRecord {
	return (fm.Data{StaticNATs: b.staticNATs.records}).Clone().StaticNATs
}
func (b *Builder) StaticNAT(id fm.ID) (fm.StaticNATRecord, bool) {
	i, ok := b.staticNATs.index[id]
	if !ok {
		return fm.StaticNATRecord{}, false
	}
	d := (fm.Data{StaticNATs: []fm.StaticNATRecord{b.staticNATs.records[i]}}).Clone()
	return d.StaticNATs[0], true
}
func (b *Builder) DynamicNATs() []fm.DynamicNATRecord {
	return (fm.Data{DynamicNATs: b.dynamicNATs.records}).Clone().DynamicNATs
}
func (b *Builder) DynamicNAT(id fm.ID) (fm.DynamicNATRecord, bool) {
	i, ok := b.dynamicNATs.index[id]
	if !ok {
		return fm.DynamicNATRecord{}, false
	}
	d := (fm.Data{DynamicNATs: []fm.DynamicNATRecord{b.dynamicNATs.records[i]}}).Clone()
	return d.DynamicNATs[0], true
}
func (b *Builder) NATPools() []fm.NATPoolRecord {
	return (fm.Data{NATPools: b.natPools.records}).Clone().NATPools
}
func (b *Builder) NATPool(id fm.ID) (fm.NATPoolRecord, bool) {
	i, ok := b.natPools.index[id]
	if !ok {
		return fm.NATPoolRecord{}, false
	}
	d := (fm.Data{NATPools: []fm.NATPoolRecord{b.natPools.records[i]}}).Clone()
	return d.NATPools[0], true
}

// Membership queries avoid copying records when a native lookup only needs kind.
func (b *Builder) HasAddress(id fm.ID) bool      { _, ok := b.addresses.index[id]; return ok }
func (b *Builder) HasAddressGroup(id fm.ID) bool { _, ok := b.addressGroups.index[id]; return ok }
func (b *Builder) HasService(id fm.ID) bool      { _, ok := b.services.index[id]; return ok }
func (b *Builder) HasServiceGroup(id fm.ID) bool { _, ok := b.serviceGroups.index[id]; return ok }

// ScheduleWindow interprets native times only using this capture's verified clock.
// A missing clock leaves the schedule unresolved; it is never host-local time.
func (b *Builder) ScheduleWindow(layout, start, end string) (fm.TimeWindow, string, error) {
	if b.content.source.ScheduleClock == nil {
		return fm.TimeWindow{}, "", fm.ErrScheduleTime
	}
	clock := *b.content.source.ScheduleClock
	w, err := clock.ParseWindow(layout, start, end)
	return w, clock.Timezone, err
}

// ScheduleBound interprets an optional date bound using capture-bound evidence.
func (b *Builder) ScheduleBound(layout, value string, end bool) (time.Time, string, error) {
	if b.content.source.ScheduleClock == nil {
		return time.Time{}, "", fm.ErrScheduleTime
	}
	clock := *b.content.source.ScheduleClock
	at, err := clock.ParseBound(layout, value, end)
	return at, clock.Timezone, err
}

// ScheduleWeekly requires verified native civil-calendar and endpoint semantics.
func (b *Builder) ScheduleWeekly(days []time.Weekday, start, end string) ([]fm.WeeklyWindow, string, error) {
	if b.content.source.ScheduleClock == nil {
		return nil, "", fm.ErrScheduleTime
	}
	clock := *b.content.source.ScheduleClock
	windows, err := clock.ParseWeekly(days, start, end)
	return windows, clock.Timezone, err
}

// ScheduleWeeklySpan parses one continuous native interval across weekdays.
func (b *Builder) ScheduleWeeklySpan(startDay, endDay time.Weekday, start, end string) ([]fm.WeeklyWindow, string, error) {
	if b.content.source.ScheduleClock == nil {
		return nil, "", fm.ErrScheduleTime
	}
	clock := *b.content.source.ScheduleClock
	windows, err := clock.ParseWeeklySpan(startDay, endDay, start, end)
	return windows, clock.Timezone, err
}
