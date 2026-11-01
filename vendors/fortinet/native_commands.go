package fortinet

import (
	"context"
	"fmt"
	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/vendors/internal/render"
	"reflect"
	"slices"
)

func nativeCommands(ctx context.Context, before, after *fm.Firewall, c plan.NativeChanges) (render.Native, error) {
	out := render.NewNative(c)
	if err := render.AppendNAT(before, after); err != nil {
		return out, err
	}
	if before.Metadata().Context == "" {
		return out, ErrRender
	}
	block := func(section, name string, fields []string) {
		out.Commands = append(out.Commands, "config "+section, "edit "+name)
		out.Commands = append(out.Commands, fields...)
		out.Commands = append(out.Commands, "next", "end")
	}
	for _, p := range c.Additions.NATPools {
		name, e := quoted(p.Name)
		if e != nil || !render.PlainObject(p.Object) || p.Scope != before.Metadata().Context || p.ID != fm.ID(p.Name) || len(p.Ranges) != 1 || p.Ports != (flow.Interval{High: 65535}) {
			return out, ErrRender
		}
		r := p.Ranges[0]
		if !r.Valid() || !r.First.Is4() {
			return out, ErrRender
		}
		fields := []string{"set type overload", "set startip " + r.First.String(), "set endip " + r.Last.String()}
		if p.Interface != "" {
			i := after.Interface(p.Interface)
			if i == nil || i.Disabled() || i.HasUnsupported() {
				return out, ErrRender
			}
			v, e := quoted(i.Name())
			if e != nil {
				return out, e
			}
			fields = append(fields, "set associated-interface "+v)
		}
		block("firewall ippool", name, fields)
	}
	consumed := map[fm.ID]bool{}
	vip := func(o fm.Object, m fm.Match, order fm.NATOrder, iface fm.ID, mapping []fm.Mapping, ports []fm.PortMapping, kind fm.Kind) error {
		if !render.PlainObject(o) || o.Scope != before.Metadata().Context || o.ID != fm.ID("vip:"+o.Name) || order.Stage != 0 || order.Section != "vip" || len(mapping) != 1 || mapping[0].Mode != fm.Offset || !equalSize(mapping[0].Original, mapping[0].Translated) {
			return ErrRender
		}
		want := fm.Match{AnySource: true, AnyDestination: true, AnyService: true, AnyFromZone: true, AnyToZone: true}
		external := "any"
		if iface != "" {
			i := after.Interface(iface)
			if i == nil || i.Zone() == nil || i.Disabled() || i.HasUnsupported() {
				return ErrRender
			}
			external = i.Name()
			want.AnyFromZone = false
			want.FromZones = []fm.ID{i.Zone().ID()}
			count := 0
			for _, other := range after.Interfaces() {
				if other.Zone() == i.Zone() {
					count++
				}
			}
			if count != 1 {
				return ErrRender
			}
		}
		name, e := quoted(o.Name)
		if e != nil {
			return e
		}
		external, e = quoted(external)
		if e != nil {
			return e
		}
		public, e := render.Range(mapping[0].Original)
		if e != nil {
			return e
		}
		real, e := render.Range(mapping[0].Translated)
		if e != nil {
			return e
		}
		fields := []string{"set extintf " + external, "set extip " + public, "set mappedip " + real}
		a := after.Address(o.ID)
		if a == nil {
			return ErrRender
		}
		ar := a.Record()
		if ar.ID != o.ID || ar.Name != o.Name || ar.Scope != o.Scope || ar.Inline || ar.FQDN != "" || len(ar.Unsupported) > 0 || ar.VIP != (fm.NATRef{Kind: kind, ID: o.ID}) || len(ar.Ranges) != 1 || ar.Ranges[0] != mapping[0].Original {
			return ErrRender
		}
		out.Addresses[ar.ID] = true
		active := false
		for _, r := range c.Additions.Rules {
			if slices.Contains(r.Match.Destinations, fm.AddressRef{Kind: fm.AddressObject, ID: ar.ID}) {
				active = true
			}
		}
		if !active {
			return ErrRender
		}
		if kind == fm.DynamicNATObject {
			if len(ports) != 1 || ports[0].Mode != fm.Offset || ports[0].Original.High-ports[0].Original.Low != ports[0].Translated.High-ports[0].Translated.Low || len(m.Services) != 1 {
				return ErrRender
			}
			s := after.Service(m.Services[0].ID)
			if s == nil {
				return ErrRender
			}
			sr := s.Record()
			if sr.ID != fm.ID(string(o.ID)+":service") || sr.Name != o.Name || sr.Scope != o.Scope || !render.PlainObject(sr.Object) || len(sr.Terms) != 1 {
				return ErrRender
			}
			term := sr.Terms[0]
			proto := map[uint16]string{6: "tcp", 17: "udp", 132: "sctp"}[term.Protocol.Low]
			expected := serviceTerm(term.Protocol.Low)
			expected.DestinationPort = ports[0].Original
			if proto == "" || term != expected {
				return ErrRender
			}
			want.AnyService = false
			want.Services = []fm.ServiceRef{{Kind: fm.ServiceObject, ID: sr.ID}}
			out.Services[sr.ID] = true
			port := func(p flow.Interval) string {
				if p.Low == p.High {
					return fmt.Sprint(p.Low)
				}
				return portText(p)
			}
			fields = append(fields, "set portforward enable", "set protocol "+proto, "set extport "+port(ports[0].Original), "set mappedport "+port(ports[0].Translated))
		} else {
			reverse := after.StaticNAT(fm.ID("vip-source:" + o.Name))
			if reverse == nil || before.StaticNAT(reverse.ID()) != nil {
				return ErrRender
			}
			r := reverse.Record()
			expected := fm.StaticNATRecord{Object: fm.Object{ID: reverse.ID(), Name: o.Name, Scope: o.Scope}, SourceVIP: fm.AddressRef{Kind: fm.AddressObject, ID: ar.ID}, Match: fm.Match{AnySource: true, AnyDestination: true, AnyService: true, AnyFromZone: true, AnyToZone: true}, Order: fm.NATOrder{Stage: 2, Section: "vip-source-interface", Position: r.Order.Position}, Source: []fm.Mapping{{Original: mapping[0].Translated, Translated: mapping[0].Original, Mode: fm.Offset}}}
			if iface != "" {
				expected.Interface = iface
				expected.Match.AnyToZone = false
				expected.Match.ToZones = slices.Clone(want.FromZones)
			}
			r.Spans = nil
			if !reflect.DeepEqual(r, expected) {
				return ErrRender
			}
			consumed[r.ID] = true
		}
		if !reflect.DeepEqual(m, want) {
			return ErrRender
		}
		block("firewall vip", name, fields)
		return nil
	}
	for _, r := range c.Additions.StaticNATs {
		if r.SourceVIP != (fm.AddressRef{}) {
			continue
		}
		if r.Disabled || r.Bidirectional || len(r.Source) != 0 || len(r.SourcePorts) != 0 || len(r.DestinationPorts) != 0 {
			return out, ErrRender
		}
		if err := vip(r.Object, r.Match, r.Order, r.Interface, r.Destination, nil, fm.StaticNATObject); err != nil {
			return out, err
		}
		consumed[r.ID] = true
	}
	for _, r := range c.Additions.StaticNATs {
		if !consumed[r.ID] {
			return out, ErrRender
		}
	}
	for _, r := range c.Additions.DynamicNATs {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		if r.Rule == "" {
			if r.Disabled || r.SourceMode != fm.NoTranslation || r.DestinationMode != fm.StaticIP || r.SourcePool != "" || r.DestinationPool != "" || r.InterfaceAddress.IsValid() || len(r.SourcePorts) != 0 {
				return out, ErrRender
			}
			if err := vip(r.Object, r.Match, r.Order, r.Interface, r.Destination, r.DestinationPorts, fm.DynamicNATObject); err != nil {
				return out, err
			}
			continue
		}
		owner := after.Rule(r.Rule)
		if owner == nil || before.Rule(r.Rule) != nil || owner.Action() != fm.Permit {
			return out, ErrRender
		}
		rule := owner.Record()
		if !render.PlainObject(r.Object) || r.ID != fm.ID("policy:"+string(r.Rule)) || r.Name != rule.Name || r.Scope != rule.Scope || r.Order.Stage != 1 || r.Order.Section != "policy" || r.Disabled || !reflect.DeepEqual(r.Match, rule.Match) || r.DestinationMode != fm.NoTranslation || r.DestinationPool != "" || len(r.Destination) != 0 || len(r.SourcePorts) != 0 || len(r.DestinationPorts) != 0 || r.InterfaceAddress.IsValid() {
			return out, ErrRender
		}
		fields := []string{"set nat enable"}
		if r.SourceMode == fm.InterfaceIP {
			if r.SourcePool != "" {
				return out, ErrRender
			}
			i := after.Interface(r.Interface)
			if i == nil || i.Disabled() || i.HasUnsupported() || len(i.Record().Addresses) != 1 || i.Zone() == nil || !slices.Contains(rule.Match.ToZones, i.Zone().ID()) {
				return out, ErrRender
			}
			count := 0
			for _, other := range after.Interfaces() {
				if !other.Disabled() && other.Zone() != nil && slices.Contains(rule.Match.ToZones, other.Zone().ID()) {
					count++
				}
			}
			if count != 1 {
				return out, ErrRender
			}
		} else {
			if r.SourceMode != fm.DynamicIPPort || r.Interface != "" {
				return out, ErrRender
			}
			p := after.NATPool(r.SourcePool)
			if p == nil {
				return out, ErrRender
			}
			name, e := quoted(p.Name())
			if e != nil {
				return out, e
			}
			fields = append(fields, "set ippool enable", "set poolname "+name)
		}
		if out.Policy[r.Rule] != nil {
			return out, ErrRender
		}
		out.Policy[r.Rule] = fields
	}
	return out, nil
}
