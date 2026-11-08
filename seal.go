package firemon

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/gatework/firemon/flow"
)

func insertUnique[T any](m map[ID]*T, id ID, v *T) error {
	if strings.TrimSpace(string(id)) == "" {
		return fmt.Errorf("%w: empty object ID", ErrGraph)
	}
	if _, ok := m[id]; ok {
		return fmt.Errorf("%w: duplicate ID %q", ErrGraph, id)
	}
	m[id] = v
	return nil
}

// indexCatalog registers one sealed object per record in declaration order and
// reports each unsupported declaration as it is registered.
func indexCatalog[R any, P catalogRecord[R], T any](f *Firewall, records []R, view func(R) *T) (map[ID]*T, error) {
	index := make(map[ID]*T)
	for i := range records {
		o := P(&records[i]).object()
		if err := insertUnique(index, o.ID, view(records[i])); err != nil {
			return nil, err
		}
		f.unsupported(*o)
	}
	return index, nil
}

// Seal takes ownership of a deep copy, resolves references once, and exposes only immutable objects.
func Seal(data Data) (*Firewall, error) {
	if err := verifySource(&data); err != nil {
		return nil, err
	}
	f := &Firewall{data: data.Clone(), diagnostics: slices.Clone(data.Diagnostics)}
	if err := f.indexCatalogs(); err != nil {
		return nil, err
	}
	f.reportPendingEvidence()
	if err := f.bindAddressing(); err != nil {
		return nil, err
	}
	if err := f.bindPolicies(); err != nil {
		return nil, err
	}
	if err := f.bindNATs(); err != nil {
		return nil, err
	}
	f.order()
	if err := f.summarize(); err != nil {
		return nil, err
	}
	return f, nil
}

// verifySource requires capture identity and binds the raw capture's digest.
func verifySource(data *Data) error {
	if data.Metadata.Device == "" || data.Metadata.Vendor == "" {
		return fmt.Errorf("%w: device and vendor required", ErrGraph)
	}
	sourceHash := sha256.Sum256([]byte(data.Raw))
	sourceDigest := hex.EncodeToString(sourceHash[:])
	if data.Metadata.SourceDigest != "" && data.Metadata.SourceDigest != sourceDigest {
		return fmt.Errorf("%w: source checksum mismatch", ErrGraph)
	}
	if data.Raw != "" {
		data.Metadata.SourceDigest = sourceDigest
	}
	return nil
}

// indexCatalogs registers every typed catalog in a fixed order, so the first
// structural error and the unsupported diagnostics are deterministic.
func (f *Firewall) indexCatalogs() error {
	var err error
	if f.zones, err = indexCatalog(f, f.data.Zones, func(r ZoneRecord) *Zone { return &Zone{record: r} }); err != nil {
		return err
	}
	if f.interfaces, err = indexCatalog(f, f.data.Interfaces, func(r InterfaceRecord) *Interface { return &Interface{record: r} }); err != nil {
		return err
	}
	if f.routes, err = indexCatalog(f, f.data.Routes, func(r RouteRecord) *Route { return &Route{record: r} }); err != nil {
		return err
	}
	if f.addresses, err = indexCatalog(f, f.data.Addresses, func(r AddressRecord) *Address { return &Address{record: r} }); err != nil {
		return err
	}
	if f.addressGroups, err = indexCatalog(f, f.data.AddressGroups, func(r AddressGroupRecord) *AddressGroup { return &AddressGroup{record: r} }); err != nil {
		return err
	}
	if f.services, err = indexCatalog(f, f.data.Services, func(r ServiceRecord) *Service { return &Service{record: r} }); err != nil {
		return err
	}
	if f.serviceGroups, err = indexCatalog(f, f.data.ServiceGroups, func(r ServiceGroupRecord) *ServiceGroup { return &ServiceGroup{record: r} }); err != nil {
		return err
	}
	if err = f.indexSchedules(); err != nil {
		return err
	}
	if f.rules, err = indexCatalog(f, f.data.Rules, func(r RuleRecord) *Rule { return &Rule{record: r} }); err != nil {
		return err
	}
	if f.ruleBindings, err = indexCatalog(f, f.data.RuleBindings, func(r RuleBindingRecord) *RuleBinding { return &RuleBinding{record: r} }); err != nil {
		return err
	}
	if f.staticNATs, err = indexCatalog(f, f.data.StaticNATs, func(r StaticNATRecord) *StaticNAT { return &StaticNAT{record: r} }); err != nil {
		return err
	}
	if f.dynamicNATs, err = indexCatalog(f, f.data.DynamicNATs, func(r DynamicNATRecord) *DynamicNAT { return &DynamicNAT{record: r} }); err != nil {
		return err
	}
	f.natPools, err = indexCatalog(f, f.data.NATPools, func(r NATPoolRecord) *NATPool { return &NATPool{record: r} })
	return err
}

// indexSchedules normalizes each owned schedule record in place before it is
// registered; a malformed interval fails before its identity is checked.
func (f *Firewall) indexSchedules() error {
	f.schedules = make(map[ID]*Schedule)
	for i := range f.data.Schedules {
		r := &f.data.Schedules[i]
		if err := r.validateShape(); err != nil {
			return fmt.Errorf("%w: schedule interval", ErrGraph)
		}
		r.Weekly = normalizeWeeklyPeriods(r.Weekly)
		s := &Schedule{record: *r, known: r.Validate() == nil}
		for _, period := range r.Weekly {
			s.weeklyWindows += len(period.Windows)
		}
		if s.known && r.HasRecurrence() {
			s.location, _ = scheduleLocation(r.Timezone)
		}
		if err := insertUnique(f.schedules, r.ID, s); err != nil {
			return err
		}
		f.unsupported(r.Object)
	}
	return nil
}

func (f *Firewall) reportPendingEvidence() {
	for _, e := range f.data.Evidence {
		if e.State == Pending {
			f.diagnostics = append(f.diagnostics, Diagnostic{
				Code:    "unparsed",
				Message: fmt.Sprintf("unparsed source lines %d-%d", e.Span.First, e.Span.Last),
				Span:    e.Span,
			})
		}
	}
}

// bindAddressing resolves address sets, then interfaces to zones, then routes
// to interfaces, and finally group membership.
func (f *Firewall) bindAddressing() error {
	for _, a := range f.Addresses() {
		set, err := flow.NewAddressSet(a.record.Ranges...)
		if err != nil {
			return err
		}
		a.set = set
		if a.record.FQDN != "" {
			f.issue(a.record.ID, "unresolved-fqdn", a.record.FQDN)
		}
	}
	for _, z := range f.Zones() {
		if _, err := flow.NewAddressSet(z.record.Networks...); err != nil {
			return err
		}
	}
	for _, i := range f.Interfaces() {
		if err := f.bindInterface(i); err != nil {
			return err
		}
	}
	for _, r := range f.Routes() {
		if err := f.bindRoute(r); err != nil {
			return err
		}
	}
	f.bindGroups()
	return nil
}

func (f *Firewall) bindInterface(i *Interface) error {
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
			return fmt.Errorf("%w: invalid interface prefix", ErrGraph)
		}
	}
	return nil
}

// bindPolicies validates services and schedules, then resolves rule matches
// and rule bindings.
func (f *Firewall) bindPolicies() error {
	for _, s := range f.Services() {
		for _, term := range s.record.Terms {
			if err := validateService(term); err != nil {
				return err
			}
		}
	}
	for _, s := range f.Schedules() {
		if !s.known && len(s.record.Unsupported) == 0 {
			f.issue(s.record.ID, "unknown-schedule", "schedule intervals or civil calendar evidence are missing")
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
	return nil
}

// bindNATs resolves pools, then static and dynamic translations, and finally
// VIP references, which depend on both NAT catalogs.
func (f *Firewall) bindNATs() error {
	for _, p := range f.NATPools() {
		if _, err := flow.NewAddressSet(p.record.Ranges...); err != nil {
			return err
		}
		p.iface = f.interfaces[p.record.Interface]
		if p.record.Interface != "" && p.iface == nil {
			f.issue(p.record.ID, "missing-interface", string(p.record.Interface))
		}
	}
	for _, n := range f.StaticNATs() {
		if err := f.bindStaticNAT(n); err != nil {
			return err
		}
	}
	for _, n := range f.DynamicNATs() {
		if err := f.bindDynamicNAT(n); err != nil {
			return err
		}
	}
	f.bindVIPReferences()
	return nil
}

func (f *Firewall) bindStaticNAT(n *StaticNAT) error {
	r := n.record
	n.iface = f.interfaces[r.Interface]
	if r.Interface != "" && n.iface == nil {
		f.issue(r.ID, "missing-interface", string(r.Interface))
	}
	for _, mappings := range [][]Mapping{r.Source, r.Destination} {
		if err := f.validateMappings(r.ID, mappings); err != nil {
			return err
		}
	}
	if err := f.validatePorts(r.ID, append(slices.Clone(r.SourcePorts), r.DestinationPorts...)); err != nil {
		return err
	}
	f.validateMatch(r.ID, r.Match)
	n.match = f.matchObjects(r.ID, r.Match)
	f.sequence = append(f.sequence, NATEntry{Kind: StaticNATObject, ID: r.ID, Order: r.Order, Scope: r.Scope})
	return nil
}

func (f *Firewall) bindDynamicNAT(n *DynamicNAT) error {
	r := n.record
	n.rule = f.rules[r.Rule]
	if r.Rule != "" {
		if n.rule == nil {
			f.issue(r.ID, "missing-rule", string(r.Rule))
		} else if !ownsDynamicNAT(n.rule.record, r) {
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
	isPoolSource := r.SourceMode == DynamicIP || r.SourceMode == DynamicIPPort || r.SourceMode == StaticIP
	if isPoolSource && n.sourcePool == nil && n.iface == nil {
		f.issue(r.ID, "missing-allocation", "source translation has no pool or interface")
	}
	if r.SourceMode == InterfaceIP && n.iface == nil {
		f.issue(r.ID, "missing-allocation", "interface translation has no interface")
	}
	if r.InterfaceAddress.IsValid() && !n.selectsKnownInterfaceHost() {
		f.issue(r.ID, "invalid-interface-selection", "selected NAT source must be one known host assigned to its allocation interface")
	}
	isDestinationTranslated := r.DestinationMode != NoTranslation && r.DestinationMode != UnknownTranslation
	if isDestinationTranslated && n.destinationPool == nil && len(r.Destination) == 0 {
		f.issue(r.ID, "missing-allocation", "destination translation has no target")
	}
	if err := f.validateMappings(r.ID, r.Destination); err != nil {
		return err
	}
	if err := f.validatePorts(r.ID, append(slices.Clone(r.SourcePorts), r.DestinationPorts...)); err != nil {
		return err
	}
	f.validateMatch(r.ID, r.Match)
	n.match = f.matchObjects(r.ID, r.Match)
	f.sequence = append(f.sequence, NATEntry{Kind: DynamicNATObject, ID: r.ID, Order: r.Order, Scope: r.Scope})
	return nil
}

// ownsDynamicNAT reports whether a policy-based translation retains its owning
// permit policy's complete match and state.
func ownsDynamicNAT(owner RuleRecord, n DynamicNATRecord) bool {
	return sameMatch(owner.Match, n.Match) && owner.Scope == n.Scope && owner.Disabled == n.Disabled && owner.Action == Permit
}

// selectsKnownInterfaceHost reports whether the selected InterfaceIP source is
// one specific host assigned to an enabled, fully modeled allocation interface.
func (n *DynamicNAT) selectsKnownInterfaceHost() bool {
	r := n.record
	addr := r.InterfaceAddress
	if r.SourceMode != InterfaceIP || r.SourcePool != "" || n.iface == nil || addr.Zone() != "" || addr.IsUnspecified() {
		return false
	}
	iface := n.iface.record
	return !iface.Disabled && len(iface.Unsupported) == 0 && slices.ContainsFunc(iface.Addresses, func(prefix netip.Prefix) bool {
		return prefix.Addr() == addr
	})
}

// order fixes NAT execution order and native rule evaluation order.
func (f *Firewall) order() {
	slices.SortFunc(f.sequence, func(a, b NATEntry) int {
		return cmp.Or(
			strings.Compare(a.Scope, b.Scope),
			cmp.Compare(a.Order.Stage, b.Order.Stage),
			cmp.Compare(a.Order.Position, b.Order.Position),
			cmp.Compare(a.Kind, b.Kind),
			strings.Compare(string(a.ID), string(b.ID)),
		)
	})
	f.orderedRules = f.Rules()
	slices.SortStableFunc(f.orderedRules, func(a, b *Rule) int {
		return cmp.Or(
			cmp.Compare(a.Position(), b.Position()),
			strings.Compare(string(a.ID()), string(b.ID())),
		)
	})
}

// summarize computes the semantic digest and declaration size of the sealed data.
func (f *Firewall) summarize() error {
	digest, err := semanticDigest(f.data)
	if err != nil {
		return fmt.Errorf("%w: canonical declaration: %v", ErrGraph, err)
	}
	f.digest = digest
	f.declarationSize = declarationSize(f.data)
	return nil
}
