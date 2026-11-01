package plan

import (
	"fmt"
	"maps"

	fm "github.com/gatework/firemon"
)

// NativeKind separates catalogs whose native IDs may have the same spelling.
type NativeKind string

const (
	NativeRule       NativeKind = "rule"
	NativeAddress    NativeKind = "address"
	NativeService    NativeKind = "service"
	NativeStaticNAT  NativeKind = "static_nat"
	NativeDynamicNAT NativeKind = "dynamic_nat"
	NativePool       NativeKind = "nat_pool"
	NativeSchedule   NativeKind = "schedule"
)

type NativeIdentity struct {
	Kind NativeKind
	ID   fm.ID
}

func (r Readback) CreatedIDs() map[NativeIdentity]fm.ID { return maps.Clone(r.createdIDs) }

// Native names and scopes identify newly allocated typed objects. Full contents
// and relative order are still compared after reference remapping; ambiguity is
// rejected rather than choosing the first matching name.
func mapNativeRecords[T any](kind NativeKind, expected []T, actual []T, object func(*T) *fm.Object, ids map[NativeIdentity]fm.ID, keys ...func(T) string) error {
	keyOf := func(r T) string { return nativeNameKey(*object(&r)) }
	if len(keys) > 0 {
		keyOf = keys[0]
	}
	index := make(map[string][]int, len(actual))
	for j := range actual {
		key := keyOf(actual[j])
		index[key] = append(index[key], j)
	}
	for _, want := range expected {
		target := *object(&want)
		matches := index[keyOf(want)]
		if len(matches) != 1 {
			return fmt.Errorf("%w: missing or ambiguous %s %s", ErrReadback, kind, target.ID)
		}
		obj := object(&actual[matches[0]])
		ids[NativeIdentity{kind, target.ID}] = obj.ID
		obj.ID = target.ID
		delete(index, keyOf(want))
	}
	return nil
}
func (p *Plan) remapNative(actual *fm.Data) (map[NativeIdentity]fm.ID, error) {
	ids := map[NativeIdentity]fm.ID{}
	a := p.nativeChanges.Additions
	if err := mapNativeRecords(NativeSchedule, a.Schedules, actual.Schedules, func(r *fm.ScheduleRecord) *fm.Object { return &r.Object }, ids); err != nil {
		return nil, err
	}
	if err := mapNativeRecords(NativeAddress, a.Addresses, actual.Addresses, func(r *fm.AddressRecord) *fm.Object { return &r.Object }, ids); err != nil {
		return nil, err
	}
	if err := mapNativeRecords(NativeService, a.Services, actual.Services, func(r *fm.ServiceRecord) *fm.Object { return &r.Object }, ids); err != nil {
		return nil, err
	}
	if err := mapNativeRecords(NativePool, a.NATPools, actual.NATPools, func(r *fm.NATPoolRecord) *fm.Object { return &r.Object }, ids); err != nil {
		return nil, err
	}
	if err := mapNativeRecords(NativeStaticNAT, a.StaticNATs, actual.StaticNATs, func(r *fm.StaticNATRecord) *fm.Object { return &r.Object }, ids, func(r fm.StaticNATRecord) string {
		return nativeNATKey(p.after.Metadata().Vendor, r.Object, r.Order, r.SourceVIP != (fm.AddressRef{}))
	}); err != nil {
		return nil, err
	}
	if err := mapNativeRecords(NativeDynamicNAT, a.DynamicNATs, actual.DynamicNATs, func(r *fm.DynamicNATRecord) *fm.Object { return &r.Object }, ids, func(r fm.DynamicNATRecord) string {
		return nativeNATKey(p.after.Metadata().Vendor, r.Object, r.Order, false)
	}); err != nil {
		return nil, err
	}
	reverse := map[NativeIdentity]fm.ID{}
	for planned, observed := range ids {
		key := NativeIdentity{planned.Kind, observed}
		if reverse[key] != "" {
			return nil, ErrReadback
		}
		reverse[key] = planned.ID
	}
	remap := func(kind NativeKind, id fm.ID) fm.ID {
		if v := reverse[NativeIdentity{kind, id}]; v != "" {
			return v
		}
		return id
	}
	address := func(r *fm.AddressRef) {
		if r.Kind == fm.AddressObject {
			r.ID = remap(NativeAddress, r.ID)
		}
	}
	match := func(m *fm.Match) {
		m.Schedule = remap(NativeSchedule, m.Schedule)
		for i := range m.Sources {
			address(&m.Sources[i])
		}
		for i := range m.Destinations {
			address(&m.Destinations[i])
		}
		for i := range m.Services {
			if m.Services[i].Kind == fm.ServiceObject {
				m.Services[i].ID = remap(NativeService, m.Services[i].ID)
			}
		}
	}
	for i := range actual.Addresses {
		r := &actual.Addresses[i]
		if r.VIP.Kind == fm.StaticNATObject {
			r.VIP.ID = remap(NativeStaticNAT, r.VIP.ID)
		} else if r.VIP.Kind == fm.DynamicNATObject {
			r.VIP.ID = remap(NativeDynamicNAT, r.VIP.ID)
		}
	}
	for i := range actual.AddressGroups {
		for j := range actual.AddressGroups[i].Members {
			address(&actual.AddressGroups[i].Members[j])
		}
	}
	for i := range actual.ServiceGroups {
		for j := range actual.ServiceGroups[i].Members {
			r := &actual.ServiceGroups[i].Members[j]
			if r.Kind == fm.ServiceObject {
				r.ID = remap(NativeService, r.ID)
			}
		}
	}
	for i := range actual.Rules {
		match(&actual.Rules[i].Match)
	}
	for i := range actual.StaticNATs {
		r := &actual.StaticNATs[i]
		match(&r.Match)
		address(&r.SourceVIP)
	}
	for i := range actual.DynamicNATs {
		r := &actual.DynamicNATs[i]
		match(&r.Match)
		r.SourcePool = remap(NativePool, r.SourcePool)
		r.DestinationPool = remap(NativePool, r.DestinationPool)
	}
	return ids, nil
}
