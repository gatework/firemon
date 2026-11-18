package migrate

import (
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/design"
	"github.com/gatework/firemon/traffic"
)

// addresses translates address objects and groups.
func (tr *translator) addresses() {
	for _, a := range tr.src.Addresses {
		if a.Predefined {
			continue
		}
		tr.address(a.Name, a.Description, a.Entries, len(a.Invalid) > 0)
	}
	groups := orderGroups(tr.src.AddressGroups)
	for _, g := range groups {
		if !g.Predefined {
			tr.addressGroup(g)
		}
	}
}

// address translates one object's entries under a source name.
func (tr *translator) address(name, description string, entries []firemon.AddressEntry, invalid bool) {
	switch {
	case invalid:
		tr.markBroken(nsAddress, name, "the source object has lines that were not parsed")
	case slices.ContainsFunc(entries, isWildcard) && !tr.caps.WildcardFQDN:
		tr.markBroken(nsAddress, name, "wildcard domain names have no address object form; use a URL category")
	case len(entries) == 0 && !tr.caps.MixedAddressObjects:
		tr.markBroken(nsAddress, name, "an empty object has no form on the target")
	}
	if reason, bad := tr.broken[nsAddress][name]; bad {
		tr.item(ItemKindAddress, name, FidelityUntranslatable, reason)
		return
	}
	entries, reason, ok := tr.expressible(name, entries)
	if !ok {
		tr.markBroken(nsAddress, name, reason)
		tr.item(ItemKindAddress, name, FidelityUntranslatable, reason)
		return
	}
	target := tr.names.name(nsAddress, name)
	if len(entries) <= 1 || tr.caps.MixedAddressObjects {
		a := firemon.Address{Name: target, Description: description, Entries: entries}
		tr.out.Addresses = append(tr.out.Addresses, a)
		tr.changes.addresses = append(tr.changes.addresses, design.AddAddress{Address: a})
		tr.item(ItemKindAddress, name, FidelityExact, reason, target)
		return
	}
	// One entry per object: the name becomes a group of the parts.
	g := firemon.AddressGroup{Name: target, Description: description}
	for i, e := range entries {
		part := tr.names.fresh(nsAddress, target+"_"+strconv.Itoa(i+1))
		a := firemon.Address{Name: part, Entries: []firemon.AddressEntry{e}}
		tr.out.Addresses = append(tr.out.Addresses, a)
		tr.changes.addresses = append(tr.changes.addresses, design.AddAddress{Address: a})
		g.Members = append(g.Members, part)
	}
	tr.out.AddressGroups = append(tr.out.AddressGroups, g)
	tr.changes.groups = append(tr.changes.groups, design.AddAddressGroup{Group: g})
	tr.item(ItemKindAddress, name, FidelityExact, "split into one object per entry, grouped under the same name", target)
}

// expressible rewrites entries the target cannot hold: exclusions become
// the explicit remaining ranges.
func (tr *translator) expressible(name string, entries []firemon.AddressEntry) ([]firemon.AddressEntry, string, bool) {
	if tr.caps.ExcludeEntries || !slices.ContainsFunc(entries, func(e firemon.AddressEntry) bool { return e.Exclude }) {
		return entries, "", true
	}
	if slices.ContainsFunc(entries, func(e firemon.AddressEntry) bool { return e.Kind == firemon.AddressKindFQDN }) {
		return nil, "exclusions together with domain names cannot be computed", false
	}
	set, ok := tr.fw.Address(name)
	if !ok {
		return nil, "the object cannot be resolved exactly", false
	}
	return entriesOf(set), "exclusions computed into the remaining ranges", true
}

// addressGroup translates a group; inline entries become member objects
// where the target needs them.
func (tr *translator) addressGroup(g firemon.AddressGroup) {
	fail := func(reason string) {
		tr.markBroken(nsAddress, g.Name, reason)
		tr.item(ItemKindAddressGroup, g.Name, FidelityUntranslatable, reason)
	}
	switch {
	case len(g.Invalid) > 0:
		fail("the source group has lines that were not parsed")
		return
	case g.Filter != "" && tr.t.Vendor != firemon.VendorPaloAlto:
		fail("dynamic address groups have no static form")
		return
	}
	for _, m := range g.Members {
		if reason, bad := tr.broken[nsAddress][m]; bad {
			fail("member " + m + ": " + reason)
			return
		}
	}
	excludes := slices.ContainsFunc(g.Entries, func(e firemon.AddressEntry) bool { return e.Exclude })
	if (len(g.Entries) > 0 && !tr.caps.GroupEntries) || (excludes && !tr.caps.ExcludeEntries) {
		tr.flatGroup(g)
		return
	}
	target := tr.names.name(nsAddress, g.Name)
	out := firemon.AddressGroup{Name: target, Description: g.Description, Entries: g.Entries, Filter: g.Filter}
	for _, m := range g.Members {
		out.Members = append(out.Members, tr.names.name(nsAddress, m))
	}
	tr.out.AddressGroups = append(tr.out.AddressGroups, out)
	tr.changes.groups = append(tr.changes.groups, design.AddAddressGroup{Group: out})
	tr.item(ItemKindAddressGroup, g.Name, FidelityExact, "", target)
}

// flatGroup turns a group with inline entries or exclusions into one
// object of its resolved addresses.
func (tr *translator) flatGroup(g firemon.AddressGroup) {
	set, ok := tr.fw.Address(g.Name)
	if !ok {
		tr.markBroken(nsAddress, g.Name, "the group cannot be resolved exactly")
		tr.item(ItemKindAddressGroup, g.Name, FidelityUntranslatable, "the group cannot be resolved exactly")
		return
	}
	tr.address(g.Name, g.Description, entriesOf(set), false)
	tr.items[len(tr.items)-1].Kind = ItemKindAddressGroup
	tr.items[len(tr.items)-1].Reason = "inline entries and exclusions resolved into addresses"
}

// orderGroups lists groups after the groups they contain.
func orderGroups(groups []firemon.AddressGroup) []firemon.AddressGroup {
	byName := map[string]firemon.AddressGroup{}
	for _, g := range groups {
		byName[g.Name] = g
	}
	var out []firemon.AddressGroup
	seen := map[string]bool{}
	var visit func(g firemon.AddressGroup)
	visit = func(g firemon.AddressGroup) {
		if seen[g.Name] {
			return
		}
		seen[g.Name] = true
		for _, m := range g.Members {
			if mg, ok := byName[m]; ok {
				visit(mg)
			}
		}
		out = append(out, g)
	}
	for _, g := range groups {
		visit(g)
	}
	return out
}

func isWildcard(e firemon.AddressEntry) bool {
	return e.Kind == firemon.AddressKindFQDN && strings.ContainsAny(e.FQDN, "*?")
}

// entriesOf writes a set as prefixes where they are whole, ranges else.
func entriesOf(s traffic.AddressSet) []firemon.AddressEntry {
	var out []firemon.AddressEntry
	for _, r := range s.Ranges() {
		if p, ok := r.Prefix(); ok {
			out = append(out, firemon.PrefixEntry(netip.PrefixFrom(p.Addr(), p.Bits())))
			continue
		}
		out = append(out, firemon.RangeEntry(r.From(), r.To()))
	}
	return out
}

// services translates service objects and groups; predefined source
// services are translated where rules use them.
func (tr *translator) services() {
	for _, s := range tr.src.Services {
		if !s.Predefined {
			tr.service(s.Name, s.Description, s.Entries, len(s.Invalid) > 0)
		}
	}
	for _, g := range tr.src.ServiceGroups {
		if g.Predefined {
			continue
		}
		var members []string
		reason := ""
		for _, m := range g.Members {
			name, why, ok := tr.serviceName(m)
			if !ok {
				reason = "member " + m + ": " + why
				break
			}
			members = append(members, name)
		}
		if reason != "" {
			tr.markBroken(nsService, g.Name, reason)
			tr.item(ItemKindServiceGroup, g.Name, FidelityUntranslatable, reason)
			continue
		}
		target := tr.names.name(nsService, g.Name)
		out := firemon.ServiceGroup{Name: target, Description: g.Description, Members: members}
		tr.out.ServiceGroups = append(tr.out.ServiceGroups, out)
		tr.changes.svcGroups = append(tr.changes.svcGroups, design.AddServiceGroup{Group: out})
		tr.item(ItemKindServiceGroup, g.Name, FidelityExact, "", target)
	}
}

// service translates one service under a source name.
func (tr *translator) service(name, description string, entries []firemon.ServiceEntry, invalid bool) {
	if invalid {
		tr.markBroken(nsService, name, "the source service has lines that were not parsed")
		tr.item(ItemKindService, name, FidelityUntranslatable, "the source service has lines that were not parsed")
		return
	}
	parts, reason, ok := tr.serviceParts(entries)
	if !ok {
		tr.markBroken(nsService, name, reason)
		tr.item(ItemKindService, name, FidelityUntranslatable, reason)
		return
	}
	target := tr.names.name(nsService, name)
	if len(parts) == 1 {
		s := firemon.Service{Name: target, Description: description, Entries: parts[0]}
		tr.out.Services = append(tr.out.Services, s)
		tr.changes.services = append(tr.changes.services, design.AddService{Service: s})
		tr.item(ItemKindService, name, FidelityExact, "", target)
		return
	}
	g := firemon.ServiceGroup{Name: target, Description: description}
	for i, p := range parts {
		part := tr.names.fresh(nsService, target+"_"+strconv.Itoa(i+1))
		s := firemon.Service{Name: part, Entries: p}
		tr.out.Services = append(tr.out.Services, s)
		tr.changes.services = append(tr.changes.services, design.AddService{Service: s})
		g.Members = append(g.Members, part)
	}
	tr.out.ServiceGroups = append(tr.out.ServiceGroups, g)
	tr.changes.svcGroups = append(tr.changes.svcGroups, design.AddServiceGroup{Group: g})
	tr.item(ItemKindService, name, FidelityExact, "split into one service per protocol, grouped under the same name", target)
}

// serviceParts splits entries into the services the target can hold: on
// port-only targets, one protocol and source port range per service.
func (tr *translator) serviceParts(entries []firemon.ServiceEntry) ([][]firemon.ServiceEntry, string, bool) {
	if tr.caps.MultiProtocolServices {
		return [][]firemon.ServiceEntry{entries}, "", true
	}
	type key struct {
		p   traffic.Protocol
		src traffic.PortRange
	}
	var order []key
	parts := map[key][]firemon.ServiceEntry{}
	for _, e := range entries {
		if e.AnyProtocol || !e.Protocol.HasPorts() {
			return nil, "only TCP, UDP and SCTP ports are services on the target; use an application such as icmp or ping", false
		}
		k := key{e.Protocol, e.Src}
		if _, ok := parts[k]; !ok {
			order = append(order, k)
		}
		parts[k] = append(parts[k], e)
	}
	out := make([][]firemon.ServiceEntry, 0, len(order))
	for _, k := range order {
		out = append(out, parts[k])
	}
	return out, "", len(out) > 0
}

// serviceName returns the target name for a source service name: a
// translated custom service, a mapped or equal predefined one, or a new
// custom service with the predefined one's ports.
func (tr *translator) serviceName(name string) (string, string, bool) {
	if reason, bad := tr.broken[nsService][name]; bad {
		return "", reason, false
	}
	if t, ok := tr.names.lookup(nsService, name); ok {
		return t, "", true
	}
	set, ok := tr.fw.Service(name)
	if !ok {
		return "", "the service cannot be resolved", false
	}
	if t, ok := tr.m.Services[name]; ok {
		if want, known := tr.t.Services.Lookup(t); known && !want.Equal(set) {
			return t, fmt.Sprintf("mapped to %s, whose ports differ (%s vs %s)", t, want, set), true
		}
		return t, "", true
	}
	for _, n := range tr.t.Services.Names() {
		if s, _ := tr.t.Services.Lookup(n); s.Equal(set) {
			return n, "", true
		}
	}
	var entries []firemon.ServiceEntry
	for r := range set.All() {
		for p := int(r.ProtocolLow); p <= int(r.ProtocolHigh); p++ {
			entries = append(entries, firemon.ServiceEntry{Protocol: traffic.Protocol(p), Src: r.Src, Dst: r.Dst})
		}
	}
	tr.service(name, "predefined "+name+" on the source", entries, false)
	if reason, bad := tr.broken[nsService][name]; bad {
		return "", reason, false
	}
	t, _ := tr.names.lookup(nsService, name)
	return t, "", true
}

// schedules translates schedules: PAN-OS holds either windows or one kind
// of recurrence and counts in minutes.
func (tr *translator) schedules() {
	for _, s := range tr.src.Schedules {
		out, reason, f := tr.schedule(s)
		if f == FidelityUntranslatable {
			tr.markBroken(nsSchedule, s.Name, reason)
			tr.item(ItemKindSchedule, s.Name, f, reason)
			continue
		}
		out.Name = tr.names.name(nsSchedule, s.Name)
		tr.out.Schedules = append(tr.out.Schedules, out)
		tr.changes.schedules = append(tr.changes.schedules, design.AddSchedule{Schedule: out})
		tr.item(ItemKindSchedule, s.Name, f, reason, out.Name)
	}
}

func (tr *translator) schedule(s firemon.Schedule) (firemon.Schedule, string, Fidelity) {
	if s.Unsupported != "" {
		return firemon.Schedule{}, "unsupported period " + s.Unsupported, FidelityUntranslatable
	}
	if tr.t.Vendor != firemon.VendorPaloAlto {
		return s, "", FidelityExact
	}
	daily, weekly := false, false
	for _, r := range s.Recurrences {
		daily, weekly = daily || len(r.Days) == 0, weekly || len(r.Days) > 0
	}
	if (len(s.Windows) > 0 && len(s.Recurrences) > 0) || (daily && weekly) {
		return firemon.Schedule{}, "mixes kinds of periods, which one PAN-OS schedule cannot", FidelityUntranslatable
	}
	out := firemon.Schedule{Description: s.Description}
	rounded := false
	ceil := func(d time.Duration) time.Duration {
		c := d.Truncate(time.Minute)
		if c < d {
			c += time.Minute
			rounded = true
		}
		return c
	}
	for _, w := range s.Windows {
		if w.Start.IsZero() {
			return firemon.Schedule{}, "a window without a start", FidelityUntranslatable
		}
		end := w.End.Truncate(time.Minute)
		if end.Before(w.End) {
			end, rounded = end.Add(time.Minute), true
		}
		out.Windows = append(out.Windows, firemon.TimeWindow{Start: w.Start.Truncate(time.Minute), End: end})
	}
	for _, r := range s.Recurrences {
		out.Recurrences = append(out.Recurrences, firemon.Recurrence{Days: r.Days, Start: r.Start.Truncate(time.Minute), End: min(ceil(r.End), 24*time.Hour)})
	}
	if rounded {
		return out, "ends rounded up to the minute (PAN-OS counts minutes)", FidelityApproximate
	}
	return out, "", FidelityExact
}
