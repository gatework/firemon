package vendors

import (
	"fmt"
	"net/netip"
	"slices"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/plan"
)

func (c *natCompilation) compileDynamic(source fm.DynamicNATRecord) error {
	if source.Disabled || len(source.Unsupported) != 0 || len(source.SourcePorts) != 0 || source.SourceMode == fm.UnknownTranslation || source.DestinationMode == fm.UnknownTranslation {
		return natFailure(source.ID, "unsupported-nat", "disabled, unknown or explicit source-port translations have no supported target form")
	}
	if c.vendor == "fortinet" || c.vendor == "netscreen" {
		return c.compileOwned(source)
	}
	if c.vendor != "paloalto" && c.vendor != "huawei" && c.vendor != "srx" {
		return natFailure(source.ID, "native-nat-form", "selected translation has no implemented native target compiler")
	}
	contexts, err := c.contexts(source.Object, source.Match)
	if err != nil {
		return err
	}
	for _, pair := range contexts {
		if err := c.take(1); err != nil {
			return err
		}
		direction := "source"
		if source.DestinationMode != fm.NoTranslation {
			direction = "destination"
			if source.SourceMode != fm.NoTranslation && c.vendor != "paloalto" {
				return natFailure(source.ID, "compound-nat", "target native source and destination stages cannot retain this compound declaration")
			}
		}
		name := natName(source.ID, pair.Target, direction)
		r := fm.DynamicNATRecord{Object: fm.Object{ID: fm.ID(name), Name: name}, SourceMode: source.SourceMode, DestinationMode: source.DestinationMode}
		switch c.vendor {
		case "paloalto":
			r.Order = c.order(1, "")
		case "huawei":
			r.ID = fm.ID("policy:" + name)
			stage := 2
			if direction == "destination" {
				stage = 1
			}
			r.Order = c.order(stage, "nat-policy")
		case "srx":
			set := natName("", pair.Target, direction)
			r.ID = natIdentity("nat", direction, set, name)
			stage := 2
			if direction == "destination" {
				stage = 1
			}
			r.Order = c.order(stage, direction+":"+set)
		}
		r.Match, err = c.match(source.Match, r.ID, pair.Target)
		if err != nil {
			return err
		}
		if c.vendor == "srx" && direction == "destination" {
			// Destination NAT rule-sets select ingress only. Removing a concrete
			// source egress guard would broaden the relation before routing.
			if !source.Match.AnyToZone {
				return natFailure(source.ID, "nat-egress-guard", "SRX destination NAT cannot express the selected egress-zone guard")
			}
			r.Match.AnyToZone, r.Match.ToZones = true, nil
		}
		if source.Interface != "" {
			r.Interface, err = c.iface(source.Interface)
			if err != nil {
				return err
			}
		}
		if source.SourceMode == fm.InterfaceIP {
			if c.vendor == "srx" {
				return natFailure(source.ID, "interface-nat", "SRX interface allocation is outside the supported native compiler")
			}
			if err := c.interfaceAllocation(source, &r); err != nil {
				return err
			}
		} else if source.SourceMode == fm.DynamicIP || source.SourceMode == fm.DynamicIPPort {
			pool, err := c.sourcePool(source, name, r.ID, "")
			if err != nil {
				return err
			}
			r.SourcePool = pool.ID
			c.changes.Additions.NATPools = append(c.changes.Additions.NATPools, pool)
		} else if source.SourceMode != fm.NoTranslation || source.SourcePool != "" {
			return natFailure(source.ID, "nat-allocation-mode", "selected source allocation mode is not representable")
		}
		if source.DestinationMode == fm.StaticIP {
			if err := c.destination(source, &r, name); err != nil {
				return err
			}
		} else if source.DestinationMode != fm.NoTranslation || source.DestinationPool != "" || len(source.Destination)+len(source.DestinationPorts) != 0 {
			return natFailure(source.ID, "nat-destination-mode", "selected destination allocation mode is not representable")
		}
		if c.before.StaticNAT(r.ID) != nil || c.before.DynamicNAT(r.ID) != nil {
			return natFailure(source.ID, "nat-identity-collision", "target translation identity already exists")
		}
		c.changes.Additions.DynamicNATs = append(c.changes.Additions.DynamicNATs, r)
	}
	return nil
}

func (c *natCompilation) sourcePool(source fm.DynamicNATRecord, name string, owner, iface fm.ID) (fm.NATPoolRecord, error) {
	p := c.source.NATPool(source.SourcePool)
	if p == nil {
		return fm.NATPoolRecord{}, natFailure(source.ID, "nat-pool", "source allocation pool is unresolved")
	}
	v := p.Record()
	if len(v.Unsupported) != 0 || len(v.Ranges) == 0 {
		return fm.NATPoolRecord{}, natFailure(source.ID, "nat-pool", "source allocation pool has unknown contents")
	}
	if err := c.take(len(v.Ranges)); err != nil {
		return fm.NATPoolRecord{}, err
	}
	ports := v.Ports
	if source.SourceMode == fm.DynamicIPPort && ports == (flow.Interval{}) {
		ports.High = 65535
	}
	if source.SourceMode == fm.DynamicIP {
		ports = flow.Interval{}
	}
	var err error
	if v.Interface != "" {
		iface, err = c.iface(v.Interface)
		if err != nil {
			return fm.NATPoolRecord{}, err
		}
		if c.vendor != "fortinet" && c.vendor != "netscreen" {
			return fm.NATPoolRecord{}, natFailure(source.ID, "nat-pool-interface", "target pool cannot retain the native interface binding")
		}
	}
	result := fm.NATPoolRecord{Object: fm.Object{ID: fm.ID(name + "-pool"), Name: name + "-pool"}, Ranges: slices.Clone(v.Ranges)}
	switch c.vendor {
	case "paloalto":
		if source.SourceMode == fm.DynamicIPPort && ports != (flow.Interval{High: 65535}) {
			return fm.NATPoolRecord{}, natFailure(source.ID, "pat-port-domain", "PAN native pool cannot preserve this translated port range")
		}
		result.Object = fm.Object{ID: fm.ID("$nat:" + string(owner))}
	case "huawei":
		if source.SourceMode == fm.DynamicIPPort && ports != (flow.Interval{High: 65535}) {
			return fm.NATPoolRecord{}, natFailure(source.ID, "pat-port-domain", "Huawei native pool cannot preserve this translated port range")
		}
		result.ID = fm.ID("source:" + result.Name)
		result.Ports.High = 65535
	case "srx":
		if len(v.Ranges) != 1 || source.SourceMode == fm.DynamicIPPort && ports.Low < 1024 {
			return fm.NATPoolRecord{}, natFailure(source.ID, "pat-port-domain", "SRX pool requires one address range and translated ports at or above 1024")
		}
		result.ID = natIdentity("nat-pool", "source", result.Name)
		result.Ports = ports
	case "fortinet":
		if source.SourceMode != fm.DynamicIPPort || ports != (flow.Interval{High: 65535}) || len(v.Ranges) != 1 {
			return fm.NATPoolRecord{}, natFailure(source.ID, "pat-port-domain", "FortiOS overload pool cannot preserve this allocation domain")
		}
		result.Scope = c.before.Metadata().Context
		result.Ports = ports
		if v.Interface != "" {
			result.Interface = iface
		}
	case "netscreen":
		if len(v.Ranges) != 1 || source.SourceMode == fm.DynamicIPPort && ports != (flow.Interval{Low: 1024, High: 65535}) || iface == "" {
			return fm.NATPoolRecord{}, natFailure(source.ID, "pat-port-domain", "ScreenOS DIP requires one range, explicit interface and its native translated port range")
		}
		result.Name = c.nextDIP()
		if result.Name == "" {
			return fm.NATPoolRecord{}, natFailure(source.ID, "nat-pool-capacity", "ScreenOS DIP namespace is exhausted")
		}
		result.ID = natIdentity("dip", string(iface), result.Name)
		result.Interface, result.Ports = iface, ports
	}
	if c.before.NATPool(result.ID) != nil {
		return fm.NATPoolRecord{}, natFailure(source.ID, "nat-pool-collision", "target allocation pool identity already exists")
	}
	return result, nil
}

func (c *natCompilation) interfaceAllocation(source fm.DynamicNATRecord, target *fm.DynamicNATRecord) error {
	old, next := c.source.Interface(source.Interface), c.before.Interface(target.Interface)
	if old == nil || next == nil || old.Disabled() || old.HasUnsupported() || len(next.Record().Addresses) != 1 {
		return natFailure(source.ID, "interface-nat", "interface allocation requires one independently captured target address")
	}
	selected := source.InterfaceAddress
	if selected.IsValid() && !slices.ContainsFunc(old.Record().Addresses, func(p netip.Prefix) bool { return p.Addr() == selected }) {
		return natFailure(source.ID, "interface-nat-address", "source allocation selector is not a captured interface address")
	}
	if !selected.IsValid() {
		if len(old.Record().Addresses) != 1 {
			return natFailure(source.ID, "interface-nat", "source interface allocation is not a single established host")
		}
		selected = old.Record().Addresses[0].Addr()
	}
	if selected != next.Record().Addresses[0].Addr() {
		return natFailure(source.ID, "interface-nat-address", "mapped interface changes the translated address")
	}
	if c.source.Metadata().Vendor == "netscreen" && c.vendor != "netscreen" || c.source.Metadata().Vendor != "netscreen" && c.vendor == "netscreen" {
		return natFailure(source.ID, "pat-port-domain", "interface PAT translated port ranges differ across these vendors")
	}
	if c.vendor == "paloalto" && source.InterfaceAddress.IsValid() {
		target.InterfaceAddress = selected
	}
	return nil
}

func (c *natCompilation) destination(source fm.DynamicNATRecord, target *fm.DynamicNATRecord, name string) error {
	if len(source.Destination) == 0 {
		return natFailure(source.ID, "nat-destination-relation", "destination translation has no established mapping")
	}
	var translated flow.AddressRange
	var origins []flow.AddressRange
	for _, m := range source.Destination {
		if err := c.take(1); err != nil {
			return err
		}
		if m.Mode != fm.Constant && !(m.Mode == fm.Offset && m.Original.First == m.Original.Last) || m.Translated.First != m.Translated.Last || !m.Translated.First.Is4() {
			return natFailure(source.ID, "nat-destination-relation", "target form requires a fixed single-host destination")
		}
		if translated.Valid() && translated != m.Translated {
			return natFailure(source.ID, "nat-destination-relation", "destination relation has multiple translated targets")
		}
		translated = m.Translated
		origins = append(origins, m.Original)
	}
	originals, known, err := c.resolveAddresses(source.Match.Destinations, source.Match.AnyDestination)
	if err != nil {
		return err
	}
	coverage, err := flow.NewAddressSet(origins...)
	if err != nil || !known || originals.Empty() || !coverage.Contains(originals) {
		return natFailure(source.ID, "nat-destination-domain", "destination mapping does not cover the exact matched address domain")
	}
	var port flow.Interval
	if len(source.DestinationPorts) > 0 {
		terms, known, err := c.resolveServices(source.Match.Services, source.Match.AnyService)
		if err != nil {
			return err
		}
		if !known {
			return natFailure(source.ID, "nat-port-domain", "original destination port domain is unresolved")
		}
		for _, term := range terms {
			covered := false
			for _, m := range source.DestinationPorts {
				if err := c.take(1); err != nil {
					return err
				}
				if m.Mode != fm.Constant && !(m.Mode == fm.Offset && m.Original.Low == m.Original.High) || m.Translated.Low != m.Translated.High || m.Translated.Low == 0 {
					return natFailure(source.ID, "nat-port-relation", "target form requires one fixed translated destination port")
				}
				if port != (flow.Interval{}) && port != m.Translated {
					return natFailure(source.ID, "nat-port-relation", "destination port relation has multiple translated targets")
				}
				port = m.Translated
				covered = covered || m.Original.Low <= term.DestinationPort.Low && m.Original.High >= term.DestinationPort.High
			}
			if !covered {
				return natFailure(source.ID, "nat-port-domain", "destination port relation does not cover the matched service")
			}
			if c.vendor == "paloalto" {
				target.DestinationPorts = append(target.DestinationPorts, fm.PortMapping{Original: term.DestinationPort, Translated: port, Mode: fm.Constant})
			}
		}
	}
	if c.vendor == "paloalto" || c.vendor == "srx" {
		for _, r := range originals.Ranges() {
			if err := c.take(1); err != nil {
				return err
			}
			target.Destination = append(target.Destination, fm.Mapping{Original: r, Translated: translated, Mode: fm.Constant})
		}
	} else {
		all, _ := flow.PrefixRange(netip.MustParsePrefix("0.0.0.0/0"))
		target.Destination = []fm.Mapping{{Original: all, Translated: translated, Mode: fm.Constant}}
	}
	if c.vendor == "paloalto" {
		return nil
	}
	if port != (flow.Interval{}) {
		target.DestinationPorts = []fm.PortMapping{{Original: flow.Interval{High: 65535}, Translated: port, Mode: fm.Constant}}
	}
	p := fm.NATPoolRecord{Object: fm.Object{Name: name + "-pool"}, Ranges: []flow.AddressRange{translated}}
	if c.vendor == "srx" {
		p.ID = natIdentity("nat-pool", "destination", p.Name)
		p.Ports = port
	} else {
		p.ID = fm.ID("destination:" + p.Name)
		p.Ports.High = 65535
	}
	if c.before.NATPool(p.ID) != nil {
		return natFailure(source.ID, "nat-pool-collision", "target destination pool identity already exists")
	}
	target.DestinationPool = p.ID
	c.changes.Additions.NATPools = append(c.changes.Additions.NATPools, p)
	return nil
}

func (c *natCompilation) compileStatic(source fm.StaticNATRecord) error {
	if source.Disabled || source.Bidirectional || source.SourceVIP != (fm.AddressRef{}) || len(source.Unsupported) != 0 || len(source.SourcePorts) != 0 {
		return natFailure(source.ID, "static-nat-reverse", "selected static relation has reverse, owner or source-port semantics outside the target compiler")
	}
	if len(source.Source) == 0 {
		return c.compileDynamic(fm.DynamicNATRecord{Object: source.Object, Match: source.Match, Order: source.Order, Interface: source.Interface,
			SourceMode: fm.NoTranslation, DestinationMode: fm.StaticIP, Destination: source.Destination, DestinationPorts: source.DestinationPorts})
	}
	if c.vendor != "paloalto" || len(source.Source) != 1 || source.Source[0].Mode != fm.Offset || source.Interface != "" {
		return natFailure(source.ID, "static-source-form", "target cannot express the selected fixed source relation")
	}
	contexts, err := c.contexts(source.Object, source.Match)
	if err != nil {
		return err
	}
	for _, pair := range contexts {
		name := natName(source.ID, pair.Target, "static-source")
		r := fm.StaticNATRecord{Object: fm.Object{ID: fm.ID(name), Name: name}, Source: slices.Clone(source.Source), Order: c.order(1, "")}
		r.Match, err = c.match(source.Match, r.ID, pair.Target)
		if err != nil {
			return err
		}
		if len(source.Destination) > 0 {
			d := fm.DynamicNATRecord{Object: r.Object, Match: r.Match}
			if err := c.destination(fm.DynamicNATRecord{Object: source.Object, Match: source.Match, Destination: source.Destination, DestinationPorts: source.DestinationPorts}, &d, name); err != nil {
				return err
			}
			r.Destination, r.DestinationPorts = d.Destination, d.DestinationPorts
		}
		c.changes.Additions.StaticNATs = append(c.changes.Additions.StaticNATs, r)
	}
	return nil
}

func (c *natCompilation) nextDIP() string {
	used := make(map[string]bool)
	for _, p := range c.before.NATPools() {
		used[p.Name()] = true
	}
	for _, p := range c.changes.Additions.NATPools {
		used[p.Name] = true
	}
	for n := 4; n <= 255; n++ {
		name := fmt.Sprint(n)
		if !used[name] {
			return name
		}
	}
	return ""
}

func (c *natCompilation) compileOwned(source fm.DynamicNATRecord) error {
	if source.Rule == "" || source.DestinationMode != fm.NoTranslation || len(source.Destination)+len(source.DestinationPorts) != 0 || source.DestinationPool != "" {
		return natFailure(source.ID, "policy-owned-nat", "target native NAT requires a selected source policy owner and source-only translation")
	}
	var owners []fm.ID
	for _, mapping := range c.draft.Rules {
		if err := c.take(1, len(mapping.Targets)); err != nil {
			return err
		}
		if mapping.Source == source.Rule {
			owners = append(owners, mapping.Targets...)
		}
	}
	if len(owners) == 0 {
		return natFailure(source.ID, "policy-owned-nat", "source translation owner has no new target policy")
	}
	for _, id := range owners {
		var owner *fm.RuleRecord
		for i := range c.changes.Additions.Rules {
			if err := c.take(1); err != nil {
				return err
			}
			if c.changes.Additions.Rules[i].ID == id {
				owner = &c.changes.Additions.Rules[i]
				break
			}
		}
		if owner == nil || owner.Action != fm.Permit || owner.Disabled || len(owner.Match.ToZones) != 1 {
			return natFailure(source.ID, "policy-owned-nat", "target owner must be one new permit policy with an explicit egress zone")
		}
		r := fm.DynamicNATRecord{Object: fm.Object{ID: fm.ID("policy:" + string(id)), Name: owner.Name, Scope: owner.Scope}, Rule: id,
			Match: owner.Match, Order: c.order(1, "policy"), SourceMode: source.SourceMode, DestinationMode: fm.NoTranslation}
		if c.vendor == "netscreen" {
			r.ID, r.Name = natIdentity("policy", string(id)), string(id)
		}
		var iface fm.ID
		for _, pair := range c.draft.Input.Interfaces {
			if err := c.take(1); err != nil {
				return err
			}
			i := c.before.Interface(pair.Target)
			if i != nil && i.Zone() != nil && i.Zone().ID() == owner.Match.ToZones[0] {
				if iface != "" && iface != pair.Target {
					return natFailure(source.ID, "nat-interface-mapping", "policy egress does not identify one explicitly mapped target interface")
				}
				iface = pair.Target
			}
		}
		if source.SourceMode == fm.InterfaceIP {
			var err error
			r.Interface, err = c.iface(source.Interface)
			if err != nil {
				return err
			}
			if err := c.interfaceAllocation(source, &r); err != nil {
				return err
			}
		} else if source.SourceMode == fm.DynamicIP || source.SourceMode == fm.DynamicIPPort {
			p, err := c.sourcePool(source, natName(source.ID, plan.MigrationContext{FromZone: fm.ID(id)}, "owned"), r.ID, iface)
			if err != nil {
				return err
			}
			r.SourcePool = p.ID
			c.changes.Additions.NATPools = append(c.changes.Additions.NATPools, p)
		} else {
			return natFailure(source.ID, "policy-owned-nat", "target owner requires a supported native source allocation mode")
		}
		c.changes.Additions.DynamicNATs = append(c.changes.Additions.DynamicNATs, r)
	}
	return nil
}
