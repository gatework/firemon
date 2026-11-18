package migrate

import (
	"strconv"
	"strings"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/design"
)

// nat translates NAT in order. StoneOS keeps destination and source NAT
// in separate lists that both apply to a flow; PAN-OS keeps one list where
// the first matching rule decides both translations. Translating between
// them keeps each list's order, puts destination NAT first, and states
// where a flow could meet a rule of each kind.
func (tr *translator) nat() {
	var dnat, snat []firemon.DynamicNAT
	for _, n := range tr.src.DynamicNATs {
		d, s := n.TranslatedDestination.Mode, n.TranslatedSource.Mode
		translatesDst := d == firemon.TranslationModeAddress
		translatesSrc := s == firemon.TranslationModeAddress || s == firemon.TranslationModeInterface
		switch {
		case translatesDst && translatesSrc && tr.t.Vendor == firemon.VendorHillstone:
			dn, sn := n, n
			dn.TranslatedSource, sn.TranslatedDestination = firemon.Translation{}, firemon.Translation{}
			dnat, snat = append(dnat, dn), append(snat, sn)
		case translatesDst:
			dnat = append(dnat, n)
		default:
			snat = append(snat, n)
		}
	}
	both := len(dnat) > 0 && len(snat) > 0
	for _, n := range dnat {
		tr.dynamicNAT(n, both)
	}
	for _, m := range tr.src.StaticNATs {
		if !m.InboundOnly {
			tr.staticNAT(m)
		}
	}
	for _, n := range snat {
		tr.dynamicNAT(n, both)
	}
}

func (tr *translator) dynamicNAT(n firemon.DynamicNAT, both bool) {
	res := ruleResult{fidelity: FidelityExact}
	out := firemon.DynamicNAT{
		Name: n.Name, Description: n.Description, From: tr.zones(n.From), To: tr.zones(n.To), Disabled: n.Disabled,
		VirtualRouter: tr.vr(n.VirtualRouter),
	}
	if tr.t.Vendor == firemon.VendorPaloAlto {
		out.VirtualRouter = ""
	}
	if n.Egress != "" {
		out.Egress = tr.iface(n.Egress)
		if len(out.To) == 0 {
			out.To = tr.zoneOfInterface(n.Egress)
		}
	}
	out.Source = tr.single(tr.operands(&res, n.Source, false, nil, "source", n.ID), "nat-"+n.ID+"-src")
	out.Destination = tr.single(tr.operands(&res, n.Destination, false, nil, "destination", n.ID), "nat-"+n.ID+"-dst")
	for _, s := range n.Services {
		if set, ok := tr.fw.Service(s); ok && set.IsAny() {
			out.Services = nil
			break
		}
		name, why, ok := tr.serviceName(s)
		if !ok {
			res.untranslatable("service " + s + ": " + why)
			continue
		}
		out.Services = append(out.Services, name)
	}
	out.Services = tr.singleService(out.Services, "nat-"+n.ID+"-svc")
	out.TranslatedSource = tr.translation(&res, n.TranslatedSource)
	out.TranslatedDestination = tr.translation(&res, n.TranslatedDestination)
	for _, u := range n.Unsupported {
		res.untranslatable("criterion not translated: " + u)
	}
	if both && tr.src.Semantics.NATOrder != tr.t.Semantics.NATOrder {
		res.approximate("NAT lists differ: a flow matching destination and source NAT rules is translated by both on StoneOS and by the first only on PAN-OS")
	}
	if res.fidelity == FidelityUntranslatable {
		out.Disabled = true
		out.Description = "[migrate] " + out.Description
	}
	out.ID = tr.natID(n, design.NATSide(out))
	if tr.t.Vendor == firemon.VendorPaloAlto {
		out.Name = out.ID
	}
	tr.out.DynamicNATs = append(tr.out.DynamicNATs, out)
	if tr.t.Semantics.NATOrder == firemon.NATOrderSingle {
		for i := range tr.out.DynamicNATs {
			tr.out.DynamicNATs[i].Precedence = i + 1
		}
	}
	tr.changes.nat = append(tr.changes.nat, design.AddNAT{Rule: out})
	tr.item(ItemKindNAT, n.ID, res.fidelity, joinNotes(res.notes), out.ID)
}

// staticNAT translates a one-to-one mapping: StoneOS bnatrule, PAN-OS a
// bi-directional static-ip rule.
func (tr *translator) staticNAT(m firemon.StaticNAT) {
	res := ruleResult{fidelity: FidelityExact}
	realRef := tr.operands(&res, []firemon.AddressRef{m.Real}, false, nil, "real", m.ID)
	mappedRef := tr.operands(&res, []firemon.AddressRef{m.Mapped}, false, nil, "mapped", m.ID)
	if len(realRef) != 1 || len(mappedRef) != 1 {
		tr.item(ItemKindNAT, "static "+m.ID, FidelityUntranslatable, "the mapping's addresses cannot be translated")
		return
	}
	if tr.t.Vendor == firemon.VendorPaloAlto {
		r := firemon.DynamicNAT{
			From: tr.zones(m.From), To: tr.zones(m.Zones), Source: realRef, Disabled: m.Disabled,
			TranslatedSource: firemon.Translation{Mode: firemon.TranslationModeAddress, Addresses: mappedRef},
		}
		r.ID = tr.names.fresh(nsNAT, "static-"+m.ID)
		r.Name = r.ID
		tr.out.DynamicNATs = append(tr.out.DynamicNATs, r)
		tr.out.StaticNATs = append(tr.out.StaticNATs, firemon.StaticNAT{ID: r.ID, Name: r.ID, Real: realRef[0], Mapped: mappedRef[0], Zones: r.To, Disabled: r.Disabled, InboundOnly: true})
		for i := range tr.out.DynamicNATs {
			tr.out.DynamicNATs[i].Precedence = i + 1
		}
		tr.changes.nat = append(tr.changes.nat, design.AddNAT{Rule: r, Bidirectional: true})
		tr.item(ItemKindNAT, "static "+m.ID, res.fidelity, joinNotes(res.notes), r.ID)
		return
	}
	out := firemon.StaticNAT{ID: tr.staticID(), VirtualRouter: tr.vr(cmpVR(m.VirtualRouter, tr.src.Semantics.DefaultVirtualRouter)), Real: realRef[0], Mapped: mappedRef[0], Disabled: m.Disabled}
	tr.out.StaticNATs = append(tr.out.StaticNATs, out)
	tr.changes.nat = append(tr.changes.nat, design.AddStaticNAT{Mapping: out})
	tr.item(ItemKindNAT, "static "+m.ID, res.fidelity, joinNotes(res.notes), out.ID)
}

// translation maps a translated address or interface.
func (tr *translator) translation(res *ruleResult, t firemon.Translation) firemon.Translation {
	out := t
	switch t.Mode {
	case firemon.TranslationModeInterface:
		out.Interface = tr.iface(t.Interface)
	case firemon.TranslationModeAddress:
		out.Addresses = tr.operands(res, t.Addresses, false, nil, "translated address", "")
	case firemon.TranslationModeUnset, firemon.TranslationModeNone:
	}
	return out
}

// natID numbers StoneOS NAT rules per list, names PAN-OS ones.
func (tr *translator) natID(n firemon.DynamicNAT, side firemon.NATKind) string {
	if !tr.caps.NumericRuleIDs {
		return tr.names.fresh(nsNAT, cmpVR(n.Name, "nat-"+n.ID))
	}
	count := 0
	for _, o := range tr.out.DynamicNATs {
		if design.NATSide(o) == side {
			count++
		}
	}
	return strconv.Itoa(count + 1)
}

func (tr *translator) staticID() string { return strconv.Itoa(len(tr.out.StaticNATs) + 1) }

// zoneOfInterface returns the target zone of a source interface.
func (tr *translator) zoneOfInterface(name string) []string {
	for _, i := range tr.src.Interfaces {
		if i.Name == name && i.Zone != "" {
			return []string{tr.zone(i.Zone)}
		}
	}
	return nil
}

func cmpVR(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func joinNotes(notes []string) string { return strings.Join(notes, "; ") }

// single groups several address operands into one object on targets
// whose NAT rules take one operand (StoneOS).
func (tr *translator) single(refs []firemon.AddressRef, base string) []firemon.AddressRef {
	if len(refs) <= 1 || !tr.caps.NumericRuleIDs {
		return refs
	}
	g := firemon.AddressGroup{Name: tr.names.fresh(nsAddress, base)}
	var entries []firemon.AddressEntry
	for _, r := range refs {
		if r.IsInline() {
			entries = append(entries, r.Entry)
		} else {
			g.Members = append(g.Members, r.Name)
		}
	}
	if len(entries) > 0 && len(g.Members) == 0 {
		a := firemon.Address{Name: g.Name, Entries: entries}
		tr.out.Addresses = append(tr.out.Addresses, a)
		tr.changes.addresses = append(tr.changes.addresses, design.AddAddress{Address: a})
		return []firemon.AddressRef{firemon.NamedAddress(a.Name)}
	}
	g.Entries = entries
	tr.out.AddressGroups = append(tr.out.AddressGroups, g)
	tr.changes.groups = append(tr.changes.groups, design.AddAddressGroup{Group: g})
	return []firemon.AddressRef{firemon.NamedAddress(g.Name)}
}

// singleService groups several services into one on StoneOS NAT rules.
func (tr *translator) singleService(names []string, base string) []string {
	if len(names) <= 1 || !tr.caps.NumericRuleIDs {
		return names
	}
	g := firemon.ServiceGroup{Name: tr.names.fresh(nsService, base), Members: names}
	tr.out.ServiceGroups = append(tr.out.ServiceGroups, g)
	tr.changes.svcGroups = append(tr.changes.svcGroups, design.AddServiceGroup{Group: g})
	return []string{g.Name}
}
