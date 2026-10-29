package firemon

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/gatework/firemon/flow"
)

func add[T any](m map[ID]*T, o Object, v *T) error {
	if strings.TrimSpace(string(o.ID)) == "" {
		return fmt.Errorf("%w: empty object ID", ErrGraph)
	}
	if _, ok := m[o.ID]; ok {
		return fmt.Errorf("%w: duplicate ID %q", ErrGraph, o.ID)
	}
	m[o.ID] = v
	return nil
}

// Seal takes ownership of a deep copy, resolves references once, and exposes only immutable objects.
func Seal(data Data) (*Firewall, error) {
	if data.Metadata.Device == "" || data.Metadata.Vendor == "" {
		return nil, fmt.Errorf("%w: device and vendor required", ErrGraph)
	}
	sourceHash := sha256.Sum256([]byte(data.Raw))
	sourceDigest := hex.EncodeToString(sourceHash[:])
	if data.Metadata.SourceDigest != "" && data.Metadata.SourceDigest != sourceDigest {
		return nil, fmt.Errorf("%w: source checksum mismatch", ErrGraph)
	}
	if data.Raw != "" {
		data.Metadata.SourceDigest = sourceDigest
	}
	f := &Firewall{data: data.Clone(), diagnostics: slices.Clone(data.Diagnostics)}
	f.zones = make(map[ID]*Zone)
	for _, r := range f.data.Zones {
		if err := add(f.zones, r.Object, &Zone{record: r}); err != nil {
			return nil, err
		}
		for _, reason := range r.Unsupported {
			f.issue(r.ID, "unsupported", reason)
		}
	}
	f.interfaces = make(map[ID]*Interface)
	for _, r := range f.data.Interfaces {
		if err := add(f.interfaces, r.Object, &Interface{record: r}); err != nil {
			return nil, err
		}
		for _, reason := range r.Unsupported {
			f.issue(r.ID, "unsupported", reason)
		}
	}
	f.routes = make(map[ID]*Route)
	for _, r := range f.data.Routes {
		if err := add(f.routes, r.Object, &Route{record: r}); err != nil {
			return nil, err
		}
		for _, reason := range r.Unsupported {
			f.issue(r.ID, "unsupported", reason)
		}
	}
	f.addresses = make(map[ID]*Address)
	for _, r := range f.data.Addresses {
		if err := add(f.addresses, r.Object, &Address{record: r}); err != nil {
			return nil, err
		}
		for _, reason := range r.Unsupported {
			f.issue(r.ID, "unsupported", reason)
		}
	}
	f.addressGroups = make(map[ID]*AddressGroup)
	for _, r := range f.data.AddressGroups {
		if err := add(f.addressGroups, r.Object, &AddressGroup{record: r}); err != nil {
			return nil, err
		}
		for _, reason := range r.Unsupported {
			f.issue(r.ID, "unsupported", reason)
		}
	}
	f.services = make(map[ID]*Service)
	for _, r := range f.data.Services {
		if err := add(f.services, r.Object, &Service{record: r}); err != nil {
			return nil, err
		}
		for _, reason := range r.Unsupported {
			f.issue(r.ID, "unsupported", reason)
		}
	}
	f.serviceGroups = make(map[ID]*ServiceGroup)
	for _, r := range f.data.ServiceGroups {
		if err := add(f.serviceGroups, r.Object, &ServiceGroup{record: r}); err != nil {
			return nil, err
		}
		for _, reason := range r.Unsupported {
			f.issue(r.ID, "unsupported", reason)
		}
	}
	f.schedules = make(map[ID]*Schedule)
	for _, r := range f.data.Schedules {
		if err := add(f.schedules, r.Object, &Schedule{record: r}); err != nil {
			return nil, err
		}
		for _, reason := range r.Unsupported {
			f.issue(r.ID, "unsupported", reason)
		}
	}
	f.rules = make(map[ID]*Rule)
	for _, r := range f.data.Rules {
		if err := add(f.rules, r.Object, &Rule{record: r}); err != nil {
			return nil, err
		}
		for _, reason := range r.Unsupported {
			f.issue(r.ID, "unsupported", reason)
		}
	}
	f.ruleBindings = make(map[ID]*RuleBinding)
	for _, r := range f.data.RuleBindings {
		if err := add(f.ruleBindings, r.Object, &RuleBinding{record: r}); err != nil {
			return nil, err
		}
		for _, reason := range r.Unsupported {
			f.issue(r.ID, "unsupported", reason)
		}
	}
	f.staticNATs = make(map[ID]*StaticNAT)
	for _, r := range f.data.StaticNATs {
		if err := add(f.staticNATs, r.Object, &StaticNAT{record: r}); err != nil {
			return nil, err
		}
		for _, reason := range r.Unsupported {
			f.issue(r.ID, "unsupported", reason)
		}
	}
	f.dynamicNATs = make(map[ID]*DynamicNAT)
	for _, r := range f.data.DynamicNATs {
		if err := add(f.dynamicNATs, r.Object, &DynamicNAT{record: r}); err != nil {
			return nil, err
		}
		for _, reason := range r.Unsupported {
			f.issue(r.ID, "unsupported", reason)
		}
	}
	f.natPools = make(map[ID]*NATPool)
	for _, r := range f.data.NATPools {
		if err := add(f.natPools, r.Object, &NATPool{record: r}); err != nil {
			return nil, err
		}
		for _, reason := range r.Unsupported {
			f.issue(r.ID, "unsupported", reason)
		}
	}
	for _, e := range f.data.Evidence {
		if e.State == Pending {
			f.diagnostics = append(f.diagnostics, Diagnostic{Code: "unparsed", Message: fmt.Sprintf("unparsed source lines %d-%d", e.Span.First, e.Span.Last), Span: e.Span})
		}
	}
	for _, a := range f.Addresses() {
		set, err := flow.NewAddressSet(a.record.Ranges...)
		if err != nil {
			return nil, err
		}
		a.set = set
		if a.record.FQDN != "" {
			f.issue(a.record.ID, "unresolved-fqdn", a.record.FQDN)
		}
	}
	for _, z := range f.Zones() {
		if _, err := flow.NewAddressSet(z.record.Networks...); err != nil {
			return nil, err
		}
	}
	for _, i := range f.Interfaces() {
		if i.record.Zone != "" {
			i.zone = f.zones[i.record.Zone]
			if i.zone == nil {
				f.issue(i.record.ID, "missing-zone", string(i.record.Zone))
			} else {
				i.zone.interfaces = append(i.zone.interfaces, i)
			}
		}
		for _, p := range i.record.Addresses {
			if !p.IsValid() {
				return nil, fmt.Errorf("%w: invalid interface prefix", ErrGraph)
			}
		}
	}
	for _, r := range f.Routes() {
		if err := f.bindRoute(r); err != nil {
			return nil, err
		}
	}
	f.bindGroups()
	for _, s := range f.Services() {
		for _, term := range s.record.Terms {
			if err := validateService(term); err != nil {
				return nil, err
			}
		}
	}
	for _, s := range f.Schedules() {
		for _, w := range s.record.Windows {
			if w.Start.IsZero() || !w.Start.Before(w.End) {
				return nil, fmt.Errorf("%w: schedule window", ErrGraph)
			}
		}
		if len(s.record.Recurring) > 0 {
			f.issue(s.record.ID, "recurring-schedule", "native recurrence requires evaluation")
		}
	}
	for _, r := range f.Rules() {
		r.match = f.matchObjects(r.record.ID, r.record.Match)
		if id := r.record.Match.Schedule; id != "" && r.match.schedule == nil {
			f.issue(r.record.ID, "missing-schedule", string(id))
		}
		f.validateMatch(r.record.ID, r.record.Match)
		if !r.record.Action.Valid() {
			f.issue(r.record.ID, "unknown-action", "unknown rule action")
		}
	}
	for _, b := range f.RuleBindings() {
		b.iface = f.interfaces[b.record.Interface]
		b.zone = f.zones[b.record.Zone]
		if b.record.Interface != "" && b.iface == nil || b.record.Zone != "" && b.zone == nil {
			f.issue(b.record.ID, "missing-binding", "unresolved rule binding")
		}
	}
	for _, p := range f.NATPools() {
		if _, err := flow.NewAddressSet(p.record.Ranges...); err != nil {
			return nil, err
		}
		p.iface = f.interfaces[p.record.Interface]
		if p.record.Interface != "" && p.iface == nil {
			f.issue(p.record.ID, "missing-interface", string(p.record.Interface))
		}
	}
	for _, n := range f.StaticNATs() {
		r := n.record
		n.iface = f.interfaces[r.Interface]
		if r.Interface != "" && n.iface == nil {
			f.issue(r.ID, "missing-interface", string(r.Interface))
		}
		for _, mappings := range [][]Mapping{r.Source, r.Destination} {
			if err := f.validateMappings(r.ID, mappings); err != nil {
				return nil, err
			}
		}
		if err := f.validatePorts(r.ID, append(slices.Clone(r.SourcePorts), r.DestinationPorts...)); err != nil {
			return nil, err
		}
		f.validateMatch(r.ID, r.Match)
		n.match = f.matchObjects(r.ID, r.Match)
		f.sequence = append(f.sequence, NATEntry{Kind: StaticNATObject, ID: r.ID, Order: r.Order, Scope: r.Scope})
	}
	for _, n := range f.DynamicNATs() {
		r := n.record
		n.rule = f.rules[r.Rule]
		if r.Rule != "" {
			if n.rule == nil {
				f.issue(r.ID, "missing-rule", string(r.Rule))
			} else if owner := n.rule.record; !sameMatch(owner.Match, r.Match) || owner.Scope != r.Scope || owner.Disabled != r.Disabled || owner.Action != Permit {
				f.issue(r.ID, "policy-nat-mismatch", "translation must retain its owning permit policy's complete match and state")
			}
		}
		n.sourcePool = f.natPools[r.SourcePool]
		n.destinationPool = f.natPools[r.DestinationPool]
		n.iface = f.interfaces[r.Interface]
		if r.SourcePool != "" && n.sourcePool == nil || r.DestinationPool != "" && n.destinationPool == nil {
			f.issue(r.ID, "missing-pool", "unresolved dynamic NAT pool")
		}
		if r.Interface != "" && n.iface == nil {
			f.issue(r.ID, "missing-interface", string(r.Interface))
		}
		if r.SourceMode == UnknownTranslation || r.DestinationMode == UnknownTranslation {
			f.issue(r.ID, "unknown-translation", "unknown dynamic NAT mode")
		}
		if (r.SourceMode == DynamicIP || r.SourceMode == DynamicIPPort || r.SourceMode == StaticIP) && n.sourcePool == nil && n.iface == nil {
			f.issue(r.ID, "missing-allocation", "source translation has no pool or interface")
		}
		if r.SourceMode == InterfaceIP && n.iface == nil {
			f.issue(r.ID, "missing-allocation", "interface translation has no interface")
		}
		if r.InterfaceAddress.IsValid() {
			known := r.SourceMode == InterfaceIP && r.SourcePool == "" && n.iface != nil && r.InterfaceAddress.Zone() == "" && !r.InterfaceAddress.IsUnspecified()
			if known {
				iface := n.iface.record
				known = !iface.Disabled && len(iface.Unsupported) == 0 && slices.ContainsFunc(iface.Addresses, func(prefix netip.Prefix) bool {
					return prefix.Addr() == r.InterfaceAddress
				})
			}
			if !known {
				f.issue(r.ID, "invalid-interface-selection", "selected NAT source must be one known host assigned to its allocation interface")
			}
		}
		if r.DestinationMode != NoTranslation && r.DestinationMode != UnknownTranslation && n.destinationPool == nil && len(r.Destination) == 0 {
			f.issue(r.ID, "missing-allocation", "destination translation has no target")
		}
		if err := f.validateMappings(r.ID, r.Destination); err != nil {
			return nil, err
		}
		if err := f.validatePorts(r.ID, append(slices.Clone(r.SourcePorts), r.DestinationPorts...)); err != nil {
			return nil, err
		}
		f.validateMatch(r.ID, r.Match)
		n.match = f.matchObjects(r.ID, r.Match)
		f.sequence = append(f.sequence, NATEntry{Kind: DynamicNATObject, ID: r.ID, Order: r.Order, Scope: r.Scope})
	}
	f.bindVIPReferences()
	slices.SortFunc(f.sequence, func(a, b NATEntry) int {
		if c := strings.Compare(a.Scope, b.Scope); c != 0 {
			return c
		}
		if a.Order.Stage != b.Order.Stage {
			return cmpInt(a.Order.Stage, b.Order.Stage)
		}
		if a.Order.Position != b.Order.Position {
			return cmpInt(a.Order.Position, b.Order.Position)
		}
		if a.Kind != b.Kind {
			return int(a.Kind) - int(b.Kind)
		}
		return strings.Compare(string(a.ID), string(b.ID))
	})
	f.orderedRules = f.Rules()
	slices.SortStableFunc(f.orderedRules, func(a, b *Rule) int {
		if a.Position() != b.Position() {
			return cmpInt(a.Position(), b.Position())
		}
		return strings.Compare(string(a.ID()), string(b.ID()))
	})
	var err error
	f.digest, err = semanticDigest(f.data)
	if err != nil {
		return nil, fmt.Errorf("%w: canonical declaration: %v", ErrGraph, err)
	}
	return f, nil
}
