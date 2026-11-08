package config

import (
	"fmt"
	"strings"

	fm "github.com/gatework/firemon"
)

// Transaction collects independent record and source claims. Emit introduces
// native identities; Replace explicitly continues identities already accepted.
// Neither operation chooses a vendor's append/replace semantics implicitly.
type Transaction struct {
	owner               *Builder
	phase               *phaseFrame
	checkpoint          Checkpoint
	claims              []fm.Evidence
	draft               fm.Data
	replacements        fm.Data
	pendingServiceTerms int
	err                 error
	closed              bool
}

func (b *Builder) Begin() *Transaction {
	if b == nil || b.content == nil {
		return &Transaction{}
	}
	return &Transaction{owner: b, phase: b.phase, checkpoint: b.content.Checkpoint()}
}
func (t *Transaction) Parse(lines ...int) {
	if t == nil || t.closed || t.err != nil {
		return
	}
	for _, n := range lines {
		t.claims = append(t.claims, fm.Evidence{Span: fm.Span{First: n, Last: n}, State: fm.Parsed})
	}
}
func (t *Transaction) Ignore(reason string, lines ...int) {
	if t == nil || t.closed || t.err != nil {
		return
	}
	for _, n := range lines {
		t.claims = append(t.claims, fm.Evidence{Span: fm.Span{First: n, Last: n}, State: fm.Ignored, Reason: reason})
	}
}
func (t *Transaction) Emit(d fm.Data) {
	if t.accept(d) {
		appendData(&t.draft, d.Clone())
	}
}
func (t *Transaction) Replace(d fm.Data) {
	if t.accept(d) {
		appendData(&t.replacements, d.Clone())
	}
}

// Pending capacity is checked before ownership copies. The final catalog is
// checked at commit, after all replacements are known, regardless of call order.
func (t *Transaction) accept(d fm.Data) bool {
	if t == nil || t.closed || t.err != nil || t.owner == nil || t.owner.content == nil {
		return false
	}
	count, err := countServiceTerms(d.Services, t.pendingServiceTerms, t.owner.content.limits.MaxServiceTerms)
	if err != nil {
		t.err = err
		return false
	}
	t.pendingServiceTerms = count
	return true
}
func (t *Transaction) Rollback() {
	if t == nil || t.closed {
		return
	}
	if t.owner != nil && t.phase == t.owner.phase {
		_ = t.owner.content.Restore(t.checkpoint)
	}
	t.close()
}
func (t *Transaction) close() {
	t.closed = true
	t.draft = fm.Data{}
	t.replacements = fm.Data{}
	t.claims = nil
	t.pendingServiceTerms = 0
	t.err = nil
}

// Commit validates every identity and source claim before publishing any change.
func (b *Builder) Commit(t *Transaction) error {
	if b == nil || b.content == nil {
		return ErrInvalid
	}
	if t == nil || t.owner != b {
		return ErrClaim
	}
	if t.closed {
		return ErrClosed
	}
	if t.phase != b.phase {
		return ErrClaim
	}
	fail := func(err error) error { t.Rollback(); return err }
	if t.err != nil {
		return fail(t.err)
	}
	seen := make(map[int]bool, len(t.claims))
	for _, e := range t.claims {
		n := e.Span.First
		if n < 1 || n > len(b.content.evidence) || seen[n] || b.content.evidence[n-1].State != fm.Pending || e.State == fm.Ignored && strings.TrimSpace(e.Reason) == "" {
			return fail(fmt.Errorf("%w at claim %d", ErrClaim, n))
		}
		seen[n] = true
	}
	if err := validateRecords(b.zones, t.draft.Zones, t.replacements.Zones, func(r fm.ZoneRecord) fm.ID { return r.ID }, "Zones"); err != nil {
		return fail(err)
	}
	if err := validateRecords(b.interfaces, t.draft.Interfaces, t.replacements.Interfaces, func(r fm.InterfaceRecord) fm.ID { return r.ID }, "Interfaces"); err != nil {
		return fail(err)
	}
	if err := validateRecords(b.routes, t.draft.Routes, t.replacements.Routes, func(r fm.RouteRecord) fm.ID { return r.ID }, "Routes"); err != nil {
		return fail(err)
	}
	if err := validateRecords(b.addresses, t.draft.Addresses, t.replacements.Addresses, func(r fm.AddressRecord) fm.ID { return r.ID }, "Addresses"); err != nil {
		return fail(err)
	}
	if err := validateRecords(b.addressGroups, t.draft.AddressGroups, t.replacements.AddressGroups, func(r fm.AddressGroupRecord) fm.ID { return r.ID }, "AddressGroups"); err != nil {
		return fail(err)
	}
	if err := validateRecords(b.services, t.draft.Services, t.replacements.Services, func(r fm.ServiceRecord) fm.ID { return r.ID }, "Services"); err != nil {
		return fail(err)
	}
	if err := validateRecords(b.serviceGroups, t.draft.ServiceGroups, t.replacements.ServiceGroups, func(r fm.ServiceGroupRecord) fm.ID { return r.ID }, "ServiceGroups"); err != nil {
		return fail(err)
	}
	if err := validateRecords(b.schedules, t.draft.Schedules, t.replacements.Schedules, func(r fm.ScheduleRecord) fm.ID { return r.ID }, "Schedules"); err != nil {
		return fail(err)
	}
	if err := validateRecords(b.rules, t.draft.Rules, t.replacements.Rules, func(r fm.RuleRecord) fm.ID { return r.ID }, "Rules"); err != nil {
		return fail(err)
	}
	if err := validateRecords(b.ruleBindings, t.draft.RuleBindings, t.replacements.RuleBindings, func(r fm.RuleBindingRecord) fm.ID { return r.ID }, "RuleBindings"); err != nil {
		return fail(err)
	}
	if err := validateRecords(b.staticNATs, t.draft.StaticNATs, t.replacements.StaticNATs, func(r fm.StaticNATRecord) fm.ID { return r.ID }, "StaticNATs"); err != nil {
		return fail(err)
	}
	if err := validateRecords(b.dynamicNATs, t.draft.DynamicNATs, t.replacements.DynamicNATs, func(r fm.DynamicNATRecord) fm.ID { return r.ID }, "DynamicNATs"); err != nil {
		return fail(err)
	}
	if err := validateRecords(b.natPools, t.draft.NATPools, t.replacements.NATPools, func(r fm.NATPoolRecord) fm.ID { return r.ID }, "NATPools"); err != nil {
		return fail(err)
	}
	serviceTerms := b.serviceTermCount
	for _, record := range t.replacements.Services {
		serviceTerms -= len(b.services.records[b.services.index[record.ID]].Terms)
	}
	for _, records := range [][]fm.ServiceRecord{t.draft.Services, t.replacements.Services} {
		var err error
		serviceTerms, err = countServiceTerms(records, serviceTerms, b.content.limits.MaxServiceTerms)
		if err != nil {
			return fail(err)
		}
	}
	// All validation precedes this synchronous ownership transfer.
	applyRecords(b, &b.zones, t.draft.Zones, t.replacements.Zones, func(r fm.ZoneRecord) fm.ID { return r.ID })
	applyRecords(b, &b.interfaces, t.draft.Interfaces, t.replacements.Interfaces, func(r fm.InterfaceRecord) fm.ID { return r.ID })
	applyRecords(b, &b.routes, t.draft.Routes, t.replacements.Routes, func(r fm.RouteRecord) fm.ID { return r.ID })
	applyRecords(b, &b.addresses, t.draft.Addresses, t.replacements.Addresses, func(r fm.AddressRecord) fm.ID { return r.ID })
	applyRecords(b, &b.addressGroups, t.draft.AddressGroups, t.replacements.AddressGroups, func(r fm.AddressGroupRecord) fm.ID { return r.ID })
	applyRecords(b, &b.services, t.draft.Services, t.replacements.Services, func(r fm.ServiceRecord) fm.ID { return r.ID })
	b.serviceTermCount = serviceTerms
	applyRecords(b, &b.serviceGroups, t.draft.ServiceGroups, t.replacements.ServiceGroups, func(r fm.ServiceGroupRecord) fm.ID { return r.ID })
	applyRecords(b, &b.schedules, t.draft.Schedules, t.replacements.Schedules, func(r fm.ScheduleRecord) fm.ID { return r.ID })
	applyRecords(b, &b.rules, t.draft.Rules, t.replacements.Rules, func(r fm.RuleRecord) fm.ID { return r.ID })
	applyRecords(b, &b.ruleBindings, t.draft.RuleBindings, t.replacements.RuleBindings, func(r fm.RuleBindingRecord) fm.ID { return r.ID })
	applyRecords(b, &b.staticNATs, t.draft.StaticNATs, t.replacements.StaticNATs, func(r fm.StaticNATRecord) fm.ID { return r.ID })
	applyRecords(b, &b.dynamicNATs, t.draft.DynamicNATs, t.replacements.DynamicNATs, func(r fm.DynamicNATRecord) fm.ID { return r.ID })
	applyRecords(b, &b.natPools, t.draft.NATPools, t.replacements.NATPools, func(r fm.NATPoolRecord) fm.ID { return r.ID })
	b.diagnostics = append(b.diagnostics, t.draft.Diagnostics...)
	b.diagnostics = append(b.diagnostics, t.replacements.Diagnostics...)
	for _, e := range t.claims {
		index := e.Span.First - 1
		if b.phase != nil {
			b.evidenceUndo = append(b.evidenceUndo, evidenceUndo{index, b.content.evidence[index]})
		}
		e.Span = b.content.evidence[index].Span
		b.content.evidence[index] = e
	}
	b.sealed = nil
	t.close()
	return nil
}

func countServiceTerms(records []fm.ServiceRecord, count, limit int) (int, error) {
	for _, record := range records {
		if len(record.Terms) > limit-count {
			return count, fmt.Errorf("%w: service terms exceed limit %d", ErrSource, limit)
		}
		count += len(record.Terms)
	}
	return count, nil
}

func validateRecords[T any](table recordTable[T], added, replaced []T, id func(T) fm.ID, name string) error {
	if len(added)+len(replaced) == 0 {
		return nil
	}
	seen := make(map[fm.ID]bool, len(added)+len(replaced))
	for _, r := range added {
		key := id(r)
		_, exists := table.index[key]
		if strings.TrimSpace(string(key)) == "" || exists || seen[key] {
			return fmt.Errorf("%w: %s duplicate or empty ID %q", fm.ErrGraph, name, key)
		}
		seen[key] = true
	}
	for _, r := range replaced {
		key := id(r)
		_, exists := table.index[key]
		if strings.TrimSpace(string(key)) == "" || !exists || seen[key] {
			return fmt.Errorf("%w: %s replacement requires one existing ID %q", fm.ErrGraph, name, key)
		}
		seen[key] = true
	}
	return nil
}

func applyRecords[T any](b *Builder, table *recordTable[T], added, replaced []T, id func(T) fm.ID) {
	for _, r := range replaced {
		i := table.index[id(r)]
		if b.phase != nil {
			old := table.records[i]
			b.undo = append(b.undo, func() { table.records[i] = old })
		}
		table.records[i] = r
	}
	if len(added) > 0 && table.index == nil {
		table.index = make(map[fm.ID]int, len(added))
	}
	for _, r := range added {
		table.index[id(r)] = len(table.records)
		table.records = append(table.records, r)
	}
}

func appendData(dst *fm.Data, d fm.Data) {
	dst.Diagnostics = append(dst.Diagnostics, d.Diagnostics...)
	dst.Zones = append(dst.Zones, d.Zones...)
	dst.Interfaces = append(dst.Interfaces, d.Interfaces...)
	dst.Routes = append(dst.Routes, d.Routes...)
	dst.Addresses = append(dst.Addresses, d.Addresses...)
	dst.AddressGroups = append(dst.AddressGroups, d.AddressGroups...)
	dst.Services = append(dst.Services, d.Services...)
	dst.ServiceGroups = append(dst.ServiceGroups, d.ServiceGroups...)
	dst.Schedules = append(dst.Schedules, d.Schedules...)
	dst.Rules = append(dst.Rules, d.Rules...)
	dst.RuleBindings = append(dst.RuleBindings, d.RuleBindings...)
	dst.StaticNATs = append(dst.StaticNATs, d.StaticNATs...)
	dst.DynamicNATs = append(dst.DynamicNATs, d.DynamicNATs...)
	dst.NATPools = append(dst.NATPools, d.NATPools...)
}
