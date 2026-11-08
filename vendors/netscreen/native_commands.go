package netscreen

import (
	"context"
	"fmt"
	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/vendors/internal/render"
	"net/netip"
	"reflect"
	"slices"
	"strings"
)

func nativeCommands(ctx context.Context, before, after *fm.Firewall, c plan.NativeChanges, out *render.NativeBuilder) error {
	if err := render.AppendNAT(before, after); err != nil {
		return err
	}
	// DIP IDs are device-wide even across virtual systems. The current parser
	// establishes only a complete root capture; selected-vsys evidence is refused.
	if before.Metadata().Context != "" && before.Metadata().Context != "root" {
		return ErrRender
	}
	poolNames := map[string]bool{}
	for _, p := range after.NATPools() {
		v := p.Record()
		if !render.Number(v.Name) || poolNames[v.Name] {
			return ErrRender
		}
		poolNames[v.Name] = true
	}
	for _, p := range c.Additions.NATPools {
		i := after.Interface(p.Interface)
		if !render.PlainObject(p.Object) || p.Scope != "" || !render.Number(p.Name) || i == nil || i.Disabled() || i.HasUnsupported() || i.Zone() == nil || p.ID != nativeID("dip", string(p.Interface), p.Name) || len(p.Ranges) != 1 || !p.Ranges[0].First.Is4() {
			return ErrRender
		}
		name, e := quoted(i.Name())
		if e != nil {
			return e
		}
		line := "set interface " + name + " dip " + p.Name + " " + p.Ranges[0].First.String() + " " + p.Ranges[0].Last.String()
		if p.Ports == (flow.Interval{}) {
			line += " fix-port"
		} else if p.Ports != (flow.Interval{Low: 1024, High: 65535}) {
			return ErrRender
		}
		out.AppendCommands(line)
	}
	mapped := func(owner render.Owner, o fm.Object, m fm.Match, mapping []fm.Mapping, iface fm.ID, kind string) (string, string, error) {
		if !render.PlainObject(o) || o.Scope != "" || !render.PlainMatch(m) || len(mapping) != 1 || mapping[0].Original.First.String() != o.Name || m.AnyFromZone || m.AnyToZone || len(m.FromZones) != 1 || len(m.ToZones) != 1 || !m.AnySource || len(m.Sources) != 0 || m.AnyDestination || len(m.Destinations) != 1 {
			return "", "", ErrRender
		}
		// VIP has no separate Interface record field; its ingress zone must identify
		// one interface, exactly as the capture parser requires.
		i := uniqueInterface(after, m.FromZones[0])
		if i == nil || iface != "" && i.ID() != iface {
			return "", "", ErrRender
		}
		target, _ := flow.NewAddressSet(mapping[0].Translated)
		egress := routeInterface(ctx, after, i.Scope(), target)
		if egress == nil || egress.Zone() == nil || egress.Zone().ID() != m.ToZones[0] {
			return "", "", ErrRender
		}
		ref := m.Destinations[0]
		a := after.Address(ref.ID)
		if ref.Kind != fm.AddressObject || a == nil {
			return "", "", ErrRender
		}
		ar := a.Record()
		name := kind + "(" + mapping[0].Original.First.String()
		if kind == "MIP" {
			p, ok := rangePrefix(mapping[0].Original)
			if !ok {
				return "", "", ErrRender
			}
			if p.Bits() != 32 {
				name += fmt.Sprintf("/%d", p.Bits())
			}
		}
		name += ")"
		if ar.ID != fm.ID(name) || ar.Name != name || ar.Scope != "" || ar.Inline || len(ar.Unsupported) != 0 || ar.FQDN != "" || ar.VIP != (fm.NATRef{}) || len(ar.Ranges) != 1 || ar.Ranges[0] != mapping[0].Original {
			return "", "", ErrRender
		}
		if err := out.ClaimAddress(owner, ref); err != nil {
			return "", "", err
		}
		in, e := quoted(i.Name())
		if e != nil {
			return "", "", e
		}
		vr, e := quoted(i.Scope())
		return in, vr, e
	}
	for _, r := range c.Additions.StaticNATs {
		if r.Order.Stage != 0 || r.Order.Section != "mip" || r.Disabled || !r.Bidirectional || r.SourceVIP != (fm.AddressRef{}) || len(r.Source) != 0 || len(r.SourcePorts) != 0 || len(r.DestinationPorts) != 0 || len(r.Destination) != 1 || r.Destination[0].Mode != fm.Offset || !r.Match.AnyService || len(r.Match.Services) != 0 {
			return ErrRender
		}
		in, vr, e := mapped(render.NATOwner(fm.NATRef{Kind: fm.StaticNATObject, ID: r.ID}), r.Object, r.Match, r.Destination, r.Interface, "MIP")
		if e != nil {
			return e
		}
		m := r.Destination[0]
		p, ok := rangePrefix(m.Original)
		q, ok2 := rangePrefix(m.Translated)
		if !ok || !ok2 || p.Bits() != q.Bits() || r.ID != nativeID("mip", string(r.Interface), m.Original.First.String()) {
			return ErrRender
		}
		out.AppendCommands(fmt.Sprintf("set interface %s mip %s host %s netmask %s vrouter %s", in, p.Addr(), q.Addr(), mask(p.Bits()), vr))
	}
	for _, r := range c.Additions.DynamicNATs {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !render.PlainObject(r.Object) || r.Scope != "" || r.Disabled || r.InterfaceAddress.IsValid() || r.DestinationPool != "" || len(r.SourcePorts) != 0 {
			return ErrRender
		}
		if r.Order.Section == "vip" {
			if r.Order.Stage != 0 || r.Rule != "" || r.SourceMode != fm.NoTranslation || r.SourcePool != "" || r.DestinationMode != fm.StaticIP || r.Interface != "" || len(r.Destination) != 1 || r.Destination[0].Mode != fm.Constant || len(r.DestinationPorts) != 1 || r.Match.AnyService || len(r.Match.Services) != 1 {
				return ErrRender
			}
			in, _, e := mapped(render.NATOwner(fm.NATRef{Kind: fm.DynamicNATObject, ID: r.ID}), r.Object, r.Match, r.Destination, "", "VIP")
			if e != nil {
				return e
			}
			mapping := r.Destination[0]
			ports := r.DestinationPorts[0]
			if mapping.Original.First != mapping.Original.Last || mapping.Translated.First != mapping.Translated.Last || ports.Mode != fm.Constant || ports.Original.Low != ports.Original.High || ports.Translated.Low != ports.Translated.High {
				return ErrRender
			}
			i := uniqueInterface(after, r.Match.FromZones[0])
			if r.ID != nativeID("vip", string(i.ID()), r.Name, fmt.Sprint(ports.Original.Low)) {
				return ErrRender
			}
			svc := after.Service(r.Match.Services[0].ID)
			if svc == nil || r.Match.Services[0].Kind != fm.ServiceObject {
				return ErrRender
			}
			s := svc.Record()
			if s.ID != nativeID("vip-service", string(r.ID)) || s.Scope != "nat:"+string(r.ID) || !render.PlainObject(s.Object) || len(s.Terms) != 1 {
				return ErrRender
			}
			original := after.Service(fm.ID(s.Name))
			if original == nil || len(original.Record().Terms) != 1 {
				return ErrRender
			}
			term := original.Record().Terms[0]
			if term.DestinationPort != ports.Translated || term.Protocol.Low != term.Protocol.High || term.Protocol.Low != 6 && term.Protocol.Low != 17 || term.SourcePort != (flow.Interval{High: 65535}) {
				return ErrRender
			}
			term.DestinationPort = ports.Original
			if term != s.Terms[0] {
				return ErrRender
			}
			if err := out.ClaimService(render.NATOwner(fm.NATRef{Kind: fm.DynamicNATObject, ID: r.ID}), r.Match.Services[0]); err != nil {
				return err
			}
			service, e := quoted(s.Name)
			if e != nil {
				return e
			}
			out.AppendCommands(fmt.Sprintf("set interface %s vip %s %d %s %s", in, mapping.Original.First, ports.Original.Low, service, mapping.Translated.First))
			continue
		}
		owner := after.Rule(r.Rule)
		if r.Rule == "" || owner == nil || before.Rule(r.Rule) != nil || owner.Action() != fm.Permit || r.ID != nativeID("policy", string(r.Rule)) || r.Name != string(r.Rule) || r.Order.Stage != 1 || r.Order.Section != "policy" || !reflect.DeepEqual(r.Match, owner.Record().Match) {
			return ErrRender
		}
		line := "nat"
		switch r.SourceMode {
		case fm.NoTranslation:
			if r.SourcePool != "" || r.Interface != "" {
				return ErrRender
			}
		case fm.InterfaceIP:
			if r.SourcePool != "" || len(r.Match.ToZones) != 1 {
				return ErrRender
			}
			i := uniqueInterface(after, r.Match.ToZones[0])
			if i == nil || i.ID() != r.Interface || len(i.Record().Addresses) != 1 {
				return ErrRender
			}
			line += " src"
		case fm.DynamicIP, fm.DynamicIPPort:
			if r.Interface != "" || len(r.Match.ToZones) != 1 {
				return ErrRender
			}
			p := after.NATPool(r.SourcePool)
			if p == nil || p.Interface() == nil || uniqueInterface(after, r.Match.ToZones[0]) != p.Interface() {
				return ErrRender
			}
			mode := fm.DynamicIP
			if p.Record().Ports != (flow.Interval{}) {
				mode = fm.DynamicIPPort
			}
			if mode != r.SourceMode || !render.Number(p.Name()) {
				return ErrRender
			}
			line += " src dip-id " + p.Name()
		default:
			return ErrRender
		}
		if r.DestinationMode == fm.StaticIP {
			ranges, e := render.Addresses(ctx, after, r.Match.Destinations, r.Match.AnyDestination)
			if e != nil || len(ranges) != 1 || len(r.Destination) != 1 || r.Destination[0].Original != ranges[0] || r.Destination[0].Mode != fm.Constant || r.Destination[0].Translated.First != r.Destination[0].Translated.Last {
				return ErrRender
			}
			line += " dst ip " + r.Destination[0].Translated.First.String()
			if len(r.DestinationPorts) > 0 {
				if len(r.DestinationPorts) != 1 || r.DestinationPorts[0].Mode != fm.Constant || r.DestinationPorts[0].Original != (flow.Interval{High: 65535}) || r.DestinationPorts[0].Translated.Low != r.DestinationPorts[0].Translated.High {
					return ErrRender
				}
				terms, e := render.Services(ctx, after, r.Match)
				if e != nil || len(terms) == 0 || slices.ContainsFunc(terms, func(t fm.ServiceTerm) bool {
					return t.Protocol.Low != t.Protocol.High || t.Protocol.Low != 6 && t.Protocol.Low != 17
				}) {
					return ErrRender
				}
				line += fmt.Sprintf(" port %d", r.DestinationPorts[0].Translated.Low)
			}
		} else if r.DestinationMode != fm.NoTranslation || len(r.Destination) != 0 || len(r.DestinationPorts) != 0 {
			return ErrRender
		}
		if line == "nat" {
			return ErrRender
		}
		if err := out.AttachPolicy(fm.NATRef{Kind: fm.DynamicNATObject, ID: r.ID}, r.Rule, []string{line}); err != nil {
			return err
		}
	}
	// A complete root capture cannot hide an unmodelled vsys DIP namespace.
	if len(c.Additions.NATPools) > 0 && strings.Contains(before.Raw(), "set vsys") {
		return ErrRender
	}
	return nil
}

func mask(bits int) string {
	var v [4]byte
	for i := range bits {
		v[i/8] |= 1 << uint(7-i%8)
	}
	return netip.AddrFrom4(v).String()
}
