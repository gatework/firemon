package firemon

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"slices"
	"sort"
	"time"
)

// semanticDigest hashes the canonical declaration. It copies only record
// slices: canonicalization replaces record fields, reorders and trims records,
// and normalizes schedule windows, while every other nested value is read-only.
func semanticDigest(d Data) (string, error) {
	d = d.recordCopy()
	trimUnreferencedInline(&d)
	d.Raw = ""
	d.Evidence = nil
	d.Diagnostics = nil
	d.Metadata.CapturedAt = time.Time{}
	d.Metadata.SourceDigest = ""
	canonicalRecords(d.Zones)
	canonicalRecords(d.Interfaces)
	canonicalRecords(d.Routes)
	canonicalRecords(d.Addresses)
	canonicalRecords(d.AddressGroups)
	canonicalRecords(d.Services)
	canonicalRecords(d.ServiceGroups)
	for i := range d.Schedules {
		d.Schedules[i].Windows = normalizeWindows(slices.Clone(d.Schedules[i].Windows))
	}
	canonicalRecords(d.Schedules)
	canonicalRecords(d.Rules)
	canonicalRecords(d.RuleBindings)
	canonicalRecords(d.StaticNATs)
	canonicalRecords(d.DynamicNATs)
	canonicalRecords(d.NATPools)
	// Streaming with the v1 defaults hashes exactly the bytes of json.Marshal.
	h := sha256.New()
	if err := jsonv2.MarshalWrite(h, d, json.DefaultOptionsV1()); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// recordCopy copies each top-level catalog slice and shares all nested values,
// including evidence and diagnostics, which digesting discards.
func (d Data) recordCopy() Data {
	d.Zones = slices.Clone(d.Zones)
	d.Interfaces = slices.Clone(d.Interfaces)
	d.Routes = slices.Clone(d.Routes)
	d.Addresses = slices.Clone(d.Addresses)
	d.AddressGroups = slices.Clone(d.AddressGroups)
	d.Services = slices.Clone(d.Services)
	d.ServiceGroups = slices.Clone(d.ServiceGroups)
	d.Schedules = slices.Clone(d.Schedules)
	d.Rules = slices.Clone(d.Rules)
	d.RuleBindings = slices.Clone(d.RuleBindings)
	d.StaticNATs = slices.Clone(d.StaticNATs)
	d.DynamicNATs = slices.Clone(d.DynamicNATs)
	d.NATPools = slices.Clone(d.NATPools)
	return d
}

// normalizeWindows converts absolute windows to UTC and merges overlapping or
// adjacent windows. The caller owns the slice.
func normalizeWindows(windows []TimeWindow) []TimeWindow {
	for i := range windows {
		windows[i].Start, windows[i].End = windows[i].Start.UTC(), windows[i].End.UTC()
	}
	slices.SortFunc(windows, func(a, b TimeWindow) int {
		return cmp.Or(a.Start.Compare(b.Start), a.End.Compare(b.End))
	})
	merged := windows[:0]
	for _, window := range windows {
		if n := len(merged); n != 0 && !window.Start.After(merged[n-1].End) {
			if window.End.After(merged[n-1].End) {
				merged[n-1].End = window.End
			}
		} else {
			merged = append(merged, window)
		}
	}
	return merged
}

// canonicalRecords drops source positions and orders records by identity.
// Seal has already proven identities unique, so the order is total.
func canonicalRecords[R any, P catalogRecord[R]](records []R) {
	for i := range records {
		P(&records[i]).object().Spans = nil
	}
	sort.Sort(byObjectID[R, P](records))
}

// byObjectID compares records in place. A comparator taking records by value
// would copy, and through the generic dictionary heap-allocate, each operand.
type byObjectID[R any, P catalogRecord[R]] []R

func (s byObjectID[R, P]) Len() int { return len(s) }
func (s byObjectID[R, P]) Less(i, j int) bool {
	return P(&s[i]).object().ID < P(&s[j]).object().ID
}
func (s byObjectID[R, P]) Swap(i, j int) { s[i], s[j] = s[j], s[i] }

// Inline values belong to their references. Keeping an orphan in an in-memory
// draft must not make deletion of its last policy fail independent readback.
// Named declarations and any value still referenced by a group or NAT remain.
func trimUnreferencedInline(d *Data) {
	addresses, services := make(map[ID]bool), make(map[ID]bool)
	addressRefs := func(refs []AddressRef) {
		for _, r := range refs {
			if r.Kind == AddressObject {
				addresses[r.ID] = true
			}
		}
	}
	serviceRefs := func(refs []ServiceRef) {
		for _, r := range refs {
			if r.Kind == ServiceObject {
				services[r.ID] = true
			}
		}
	}
	match := func(m Match) { addressRefs(m.Sources); addressRefs(m.Destinations); serviceRefs(m.Services) }
	for _, g := range d.AddressGroups {
		addressRefs(g.Members)
	}
	for _, g := range d.ServiceGroups {
		serviceRefs(g.Members)
	}
	for _, r := range d.Rules {
		match(r.Match)
	}
	for _, n := range d.StaticNATs {
		match(n.Match)
		addressRefs([]AddressRef{n.SourceVIP})
	}
	for _, n := range d.DynamicNATs {
		match(n.Match)
	}
	d.Addresses = slices.DeleteFunc(d.Addresses, func(a AddressRecord) bool { return a.Inline && !addresses[a.ID] && len(a.Unsupported) == 0 })
	d.Services = slices.DeleteFunc(d.Services, func(s ServiceRecord) bool { return s.Inline && !services[s.ID] && len(s.Unsupported) == 0 })
}
