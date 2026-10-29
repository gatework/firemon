package firemon

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"
	"time"
)

func semanticDigest(d Data) (string, error) {
	d = d.Clone()
	trimUnreferencedInline(&d)
	d.Raw = ""
	d.Evidence = nil
	d.Diagnostics = nil
	d.Metadata.CapturedAt = time.Time{}
	d.Metadata.SourceDigest = ""
	for i := range d.Zones {
		d.Zones[i].Spans = nil
	}
	slices.SortFunc(d.Zones, func(a, b ZoneRecord) int { return strings.Compare(string(a.ID), string(b.ID)) })
	for i := range d.Interfaces {
		d.Interfaces[i].Spans = nil
	}
	slices.SortFunc(d.Interfaces, func(a, b InterfaceRecord) int { return strings.Compare(string(a.ID), string(b.ID)) })
	for i := range d.Routes {
		d.Routes[i].Spans = nil
	}
	slices.SortFunc(d.Routes, func(a, b RouteRecord) int { return strings.Compare(string(a.ID), string(b.ID)) })
	for i := range d.Addresses {
		d.Addresses[i].Spans = nil
	}
	slices.SortFunc(d.Addresses, func(a, b AddressRecord) int { return strings.Compare(string(a.ID), string(b.ID)) })
	for i := range d.AddressGroups {
		d.AddressGroups[i].Spans = nil
	}
	slices.SortFunc(d.AddressGroups, func(a, b AddressGroupRecord) int { return strings.Compare(string(a.ID), string(b.ID)) })
	for i := range d.Services {
		d.Services[i].Spans = nil
	}
	slices.SortFunc(d.Services, func(a, b ServiceRecord) int { return strings.Compare(string(a.ID), string(b.ID)) })
	for i := range d.ServiceGroups {
		d.ServiceGroups[i].Spans = nil
	}
	slices.SortFunc(d.ServiceGroups, func(a, b ServiceGroupRecord) int { return strings.Compare(string(a.ID), string(b.ID)) })
	for i := range d.Schedules {
		d.Schedules[i].Spans = nil
	}
	slices.SortFunc(d.Schedules, func(a, b ScheduleRecord) int { return strings.Compare(string(a.ID), string(b.ID)) })
	for i := range d.Rules {
		d.Rules[i].Spans = nil
	}
	slices.SortFunc(d.Rules, func(a, b RuleRecord) int { return strings.Compare(string(a.ID), string(b.ID)) })
	for i := range d.RuleBindings {
		d.RuleBindings[i].Spans = nil
	}
	slices.SortFunc(d.RuleBindings, func(a, b RuleBindingRecord) int { return strings.Compare(string(a.ID), string(b.ID)) })
	for i := range d.StaticNATs {
		d.StaticNATs[i].Spans = nil
	}
	slices.SortFunc(d.StaticNATs, func(a, b StaticNATRecord) int { return strings.Compare(string(a.ID), string(b.ID)) })
	for i := range d.DynamicNATs {
		d.DynamicNATs[i].Spans = nil
	}
	slices.SortFunc(d.DynamicNATs, func(a, b DynamicNATRecord) int { return strings.Compare(string(a.ID), string(b.ID)) })
	for i := range d.NATPools {
		d.NATPools[i].Spans = nil
	}
	slices.SortFunc(d.NATPools, func(a, b NATPoolRecord) int { return strings.Compare(string(a.ID), string(b.ID)) })
	b, err := json.Marshal(d)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

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
