package plan

import (
	fm "github.com/gatework/firemon"
	"reflect"
	"slices"
	"strings"
)

// nativeNATKey distinguishes native declaration namespaces, not arbitrary graph
// IDs. Source projections have no second native declaration and are validated
// against their VIP parent before this key is used.
func nativeNATKey(vendor string, o fm.Object, order fm.NATOrder, projection bool) string {
	namespace := ""
	switch vendor {
	case "fortinet":
		if projection {
			namespace = "vip-source"
		} else if order.Section == "vip" && order.Stage == 0 {
			namespace = "vip"
		} else if order.Section == "policy" && order.Stage == 1 {
			namespace = "policy"
		}
	case "srx":
		direction, set, ok := strings.Cut(order.Section, ":")
		if ok && set != "" && (direction == "static" && order.Stage == 0 || direction == "destination" && order.Stage == 1 || direction == "source" && order.Stage == 2) {
			namespace = order.Section
		}
	case "hillstone":
		if order.Section == "bnat" && order.Stage == 0 || order.Section == "dnat" && order.Stage == 1 || order.Section == "snat" && order.Stage == 2 {
			namespace = order.Section
		}
	}
	return namespace + "\x00" + nativeNameKey(o)
}
func validVIPProjections(vendor string, d fm.Data) error {
	if vendor != "fortinet" {
		return nil
	}
	addresses := map[fm.ID]fm.AddressRecord{}
	fixed := map[fm.ID]fm.StaticNATRecord{}
	for _, a := range d.Addresses {
		addresses[a.ID] = a
	}
	for _, r := range d.StaticNATs {
		fixed[r.ID] = r
	}
	for _, r := range d.StaticNATs {
		if r.SourceVIP == (fm.AddressRef{}) {
			continue
		}
		a, ok := addresses[r.SourceVIP.ID]
		parent, found := fixed[a.VIP.ID]
		if !ok || !found || r.SourceVIP.Kind != fm.AddressObject || a.VIP.Kind != fm.StaticNATObject || parent.SourceVIP != (fm.AddressRef{}) || a.Name != r.Name || parent.Name != r.Name || a.Scope != r.Scope || parent.Scope != r.Scope || parent.Order.Section != "vip" || parent.Order.Stage != 0 || len(parent.Destination) != 1 || len(r.Source) != 1 || r.Source[0] != (fm.Mapping{Original: parent.Destination[0].Translated, Translated: parent.Destination[0].Original, Mode: parent.Destination[0].Mode}) || r.Order.Stage != 2 || r.Disabled != parent.Disabled || len(r.Destination) != 0 || len(r.SourcePorts) != 0 || len(r.DestinationPorts) != 0 || r.Bidirectional {
			return ErrInvalid
		}
		want := fm.Match{AnySource: true, AnyDestination: true, AnyService: true, AnyFromZone: true, AnyToZone: true}
		switch r.Order.Section {
		case "vip-source-interface":
			if !parent.Match.AnyFromZone {
				want.AnyToZone = false
				want.ToZones = slices.Clone(parent.Match.FromZones)
			}
			if r.Interface != parent.Interface {
				return ErrInvalid
			}
		case "vip-source-forced":
			if r.Interface != "" {
				return ErrInvalid
			}
		default:
			return ErrInvalid
		}
		if !reflect.DeepEqual(want, r.Match) {
			return ErrInvalid
		}
	}
	return nil
}

// Inline values may only accompany a newly declared native owner. Their exact
// syntax/identity is additionally checked by the native emitter and readback.
func validateNativeInlineOwnership(a NativeAdditions) error {
	addresses, services := map[fm.ID]bool{}, map[fm.ID]bool{}
	match := func(m fm.Match) {
		for _, refs := range [][]fm.AddressRef{m.Sources, m.Destinations} {
			for _, r := range refs {
				if r.Kind == fm.AddressObject {
					addresses[r.ID] = true
				}
			}
		}
		for _, r := range m.Services {
			if r.Kind == fm.ServiceObject {
				services[r.ID] = true
			}
		}
	}
	for _, r := range a.Rules {
		match(r.Match)
	}
	for _, r := range a.StaticNATs {
		match(r.Match)
	}
	for _, r := range a.DynamicNATs {
		match(r.Match)
	}
	for _, r := range a.Addresses {
		if r.Inline && !addresses[r.ID] {
			return ErrInvalid
		}
	}
	for _, r := range a.Services {
		if r.Inline && !services[r.ID] {
			return ErrInvalid
		}
	}
	return nil
}
