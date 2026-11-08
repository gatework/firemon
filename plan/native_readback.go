package plan

import (
	"fmt"
	"maps"
	"net/url"
	"slices"

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
	dynamic := a.DynamicNATs
	if p.after.Metadata().Vendor == "netscreen" {
		// ScreenOS policy NAT identity derives from its device-allocated owner.
		// Its native name cannot be matched before that rule is established.
		dynamic = slices.DeleteFunc(slices.Clone(dynamic), func(r fm.DynamicNATRecord) bool { return r.Rule != "" })
	}
	if err := mapNativeRecords(NativeDynamicNAT, dynamic, actual.DynamicNATs, func(r *fm.DynamicNATRecord) *fm.Object { return &r.Object }, ids, func(r fm.DynamicNATRecord) string {
		return nativeNATKey(p.after.Metadata().Vendor, r.Object, r.Order, false)
	}); err != nil {
		return nil, err
	}
	reverse, err := reverseNativeIDs(ids)
	if err != nil {
		return nil, err
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

func reverseNativeIDs(ids map[NativeIdentity]fm.ID) (map[NativeIdentity]fm.ID, error) {
	reverse := make(map[NativeIdentity]fm.ID, len(ids))
	for planned, observed := range ids {
		key := NativeIdentity{planned.Kind, observed}
		if reverse[key] != "" {
			return nil, ErrReadback
		}
		reverse[key] = planned.ID
	}
	return reverse, nil
}

// remapNativeOwners runs after every created rule has one signature match.
// Only ScreenOS policy NAT has an owner-derived ID and name; ordinary native
// names retain the strict scope/name matching performed by remapNative.
func (p *Plan) remapNativeOwners(actual *fm.Data, ruleIDs map[fm.ID]fm.ID, ids map[NativeIdentity]fm.ID) error {
	for planned, observed := range ruleIDs {
		ids[NativeIdentity{NativeRule, planned}] = observed
	}
	if p.after.Metadata().Vendor == "netscreen" {
		type ownerKey struct {
			scope string
			rule  fm.ID
		}
		index := make(map[ownerKey][]int)
		for i, r := range actual.DynamicNATs {
			if r.Rule != "" {
				key := ownerKey{r.Scope, r.Rule}
				index[key] = append(index[key], i)
			}
		}
		for _, want := range p.nativeChanges.Additions.DynamicNATs {
			if want.Rule == "" {
				continue
			}
			owner := p.after.Rule(want.Rule)
			observed := ruleIDs[want.Rule]
			if owner == nil || owner.Scope() != want.Scope || p.before.Rule(want.Rule) != nil || observed == "" || !screenOSPolicyIdentity(want) {
				return fmt.Errorf("%w: invalid policy NAT owner %s", ErrReadback, want.ID)
			}
			key := ownerKey{want.Scope, observed}
			matches := index[key]
			if len(matches) != 1 {
				return fmt.Errorf("%w: missing or ambiguous policy NAT for rule %s", ErrReadback, observed)
			}
			got := &actual.DynamicNATs[matches[0]]
			if !screenOSPolicyIdentity(*got) || p.before.DynamicNAT(got.ID) != nil {
				return fmt.Errorf("%w: invalid native policy NAT identity %s", ErrReadback, got.ID)
			}
			ids[NativeIdentity{NativeDynamicNAT, want.ID}] = got.ID
			got.ID, got.Name = want.ID, want.Name
			delete(index, key)
		}
	}
	reverse, err := reverseNativeIDs(ids)
	if err != nil {
		return err
	}
	for i := range actual.DynamicNATs {
		if planned := reverse[NativeIdentity{NativeRule, actual.DynamicNATs[i].Rule}]; planned != "" {
			actual.DynamicNATs[i].Rule = planned
		}
	}
	// Delay all dynamic VIP references until both ordinary and policy-owned NAT
	// identities are known. Each reference is rewritten exactly once.
	for i := range actual.Addresses {
		ref := &actual.Addresses[i].VIP
		if ref.Kind == fm.DynamicNATObject {
			if planned := reverse[NativeIdentity{NativeDynamicNAT, ref.ID}]; planned != "" {
				ref.ID = planned
			}
		}
	}
	return nil
}

func screenOSPolicyIdentity(r fm.DynamicNATRecord) bool {
	return r.Rule != "" && r.ID == fm.ID("policy:"+url.PathEscape(string(r.Rule))) && r.Name == string(r.Rule) && r.Order.Stage == 1 && r.Order.Section == "policy"
}
