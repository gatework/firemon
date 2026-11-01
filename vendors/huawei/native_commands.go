package huawei

import (
	"context"
	"fmt"
	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/vendors/internal/render"
	"strings"
)

func nativeCommands(ctx context.Context, before, after *fm.Firewall, c plan.NativeChanges) (render.Native, error) {
	out := render.NewNative(c)
	if !strings.HasPrefix(before.Metadata().Software, "V500R005") {
		return out, ErrRender
	}
	if err := render.AppendNAT(before, after); err != nil {
		return out, err
	}
	// Literal values are syntax-owned. Require the exact identity constructed by
	// the native parser; never skip an arbitrary inline object supplied by a caller.
	for _, a := range c.Additions.Addresses {
		if !a.Inline {
			continue
		}
		if a.Scope != "literal" || len(a.Ranges) != 1 || a.FQDN != "" || a.VIP != (fm.NATRef{}) || len(a.Unsupported) != 0 || a.ID != fm.ID("$address:"+a.Ranges[0].First.String()+"-"+a.Ranges[0].Last.String()) || a.Name != string(a.ID) {
			return out, ErrRender
		}
		out.Addresses[a.ID] = true
	}
	for _, s := range c.Additions.Services {
		if !s.Inline {
			continue
		}
		var key strings.Builder
		key.WriteString("$service:")
		for _, t := range s.Terms {
			fmt.Fprintf(&key, "%d/%d-%d:%d-%d;", t.Protocol.Low, t.SourcePort.Low, t.SourcePort.High, t.DestinationPort.Low, t.DestinationPort.High)
			if _, err := nativeService(t); err != nil {
				return out, err
			}
		}
		if s.Scope != "literal" || len(s.Terms) == 0 || len(s.Unsupported) != 0 || s.ID != fm.ID(key.String()) || s.Name != key.String() {
			return out, ErrRender
		}
		out.Services[s.ID] = true
	}
	modes := map[fm.ID]fm.TranslationMode{}
	for _, r := range c.Additions.DynamicNATs {
		if r.SourcePool != "" {
			if mode, ok := modes[r.SourcePool]; ok && mode != r.SourceMode {
				return out, ErrRender
			}
			modes[r.SourcePool] = r.SourceMode
		}
		if r.DestinationPool != "" {
			modes[r.DestinationPool] = fm.StaticIP
		}
	}
	for _, p := range c.Additions.NATPools {
		direction, name, ok := strings.Cut(string(p.ID), ":")
		if !ok || name != p.Name || !render.PlainObject(p.Object) || p.Scope != "" || p.Interface != "" || p.Ports != (flow.Interval{High: 65535}) || len(p.Ranges) == 0 {
			return out, ErrRender
		}
		quotedName, e := quoted(name)
		if e != nil {
			return out, e
		}
		header := "nat address-group "
		if direction == "destination" {
			header = "destination-nat address-group "
			if modes[p.ID] != fm.StaticIP || len(p.Ranges) != 1 || p.Ranges[0].First != p.Ranges[0].Last {
				return out, ErrRender
			}
		} else if direction != "source" {
			return out, ErrRender
		}
		out.Commands = append(out.Commands, header+quotedName)
		if direction == "source" {
			mode := "pat"
			if modes[p.ID] == fm.DynamicIP {
				mode = "no-pat global"
			} else if modes[p.ID] != fm.DynamicIPPort {
				return out, ErrRender
			}
			out.Commands = append(out.Commands, "mode "+mode)
		}
		for i, r := range p.Ranges {
			if !r.Valid() || !r.First.Is4() {
				return out, ErrRender
			}
			out.Commands = append(out.Commands, fmt.Sprintf("section %d %s %s", i, r.First, r.Last))
		}
		out.Commands = append(out.Commands, "quit")
	}
	server := func(o fm.Object, m fm.Match, maps []fm.Mapping, bidirectional bool, ports []fm.PortMapping, iface fm.ID) (string, error) {
		if !render.PlainObject(o) || o.Scope != "" || o.ID != fm.ID("server:"+o.Name) || len(maps) != 1 || maps[0].Mode != fm.Offset || iface != "" || !render.PlainMatch(m) || !m.AnySource || !m.AnyDestination || !m.AnyToZone || len(m.Sources) != 0 || len(m.Destinations) != 0 || len(m.ToZones) != 0 {
			return "", ErrRender
		}
		name, e := quoted(o.Name)
		if e != nil {
			return "", e
		}
		line := "nat server " + name
		if !m.AnyFromZone {
			if len(m.FromZones) != 1 || after.Zone(m.FromZones[0]) == nil {
				return "", ErrRender
			}
			zone, e := quoted(string(m.FromZones[0]))
			if e != nil {
				return "", e
			}
			line += " zone " + zone
		} else if len(m.FromZones) != 0 {
			return "", ErrRender
		}
		original, target := maps[0].Original, maps[0].Translated
		if !original.Valid() || !target.Valid() || !original.First.Is4() || !target.First.Is4() || addressCount(original) != addressCount(target) {
			return "", ErrRender
		}
		endpoint := func(r flow.AddressRange) string {
			v := r.First.String()
			if r.First != r.Last {
				v += " " + r.Last.String()
			}
			return v
		}
		public, real := endpoint(original), endpoint(target)
		if !m.AnyService {
			terms, e := render.Services(ctx, after, m)
			if e != nil || len(terms) != 1 || bidirectional {
				return "", ErrRender
			}
			term := terms[0]
			proto := map[uint16]string{6: "tcp", 17: "udp", 132: "sctp"}[term.Protocol.Low]
			if proto == "" || term.Protocol.Low != term.Protocol.High || term.SourcePort != (flow.Interval{High: 65535}) || term.ICMPType != (flow.Interval{High: 255}) || term.ICMPCode != (flow.Interval{High: 255}) || original.First != original.Last || target.First != target.Last {
				return "", ErrRender
			}
			line += " protocol " + proto
			if len(ports) != 1 || ports[0].Mode != fm.Offset || ports[0].Original != term.DestinationPort || ports[0].Original.Low != ports[0].Original.High || ports[0].Translated.Low != ports[0].Translated.High {
				return "", ErrRender
			}
			public += fmt.Sprintf(" %d", ports[0].Original.Low)
			real += fmt.Sprintf(" %d", ports[0].Translated.Low)
		} else if len(m.Services) != 0 || len(ports) != 0 {
			return "", ErrRender
		}
		line += " global " + public + " inside " + real
		if !bidirectional {
			line += " no-reverse"
		}
		return line, nil
	}
	for _, r := range c.Additions.StaticNATs {
		if r.Order.Stage != 0 || r.Order.Section != "nat-server" || r.Disabled || r.Bidirectional || r.SourceVIP != (fm.AddressRef{}) || len(r.Source) != 0 || len(r.SourcePorts) != 0 || len(r.DestinationPorts) != 0 {
			return out, ErrRender
		}
		line, e := server(r.Object, r.Match, r.Destination, r.Bidirectional, nil, r.Interface)
		if e != nil {
			return out, e
		}
		out.Commands = append(out.Commands, line)
	}
	for _, r := range c.Additions.DynamicNATs {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		if !render.PlainObject(r.Object) || r.Scope != "" || r.Disabled || r.Rule != "" || r.InterfaceAddress.IsValid() || len(r.SourcePorts) != 0 {
			return out, ErrRender
		}
		if r.Order.Section == "nat-server" {
			if r.Order.Stage != 0 || r.SourceMode != fm.NoTranslation || r.DestinationMode != fm.StaticIP || r.SourcePool != "" || r.DestinationPool != "" {
				return out, ErrRender
			}
			line, e := server(r.Object, r.Match, r.Destination, false, r.DestinationPorts, r.Interface)
			if e != nil {
				return out, e
			}
			out.Commands = append(out.Commands, line)
			continue
		}
		if r.Order.Section != "nat-policy" || r.ID != fm.ID("policy:"+r.Name) || !render.PlainMatch(r.Match) {
			return out, ErrRender
		}
		name, e := quoted(r.Name)
		if e != nil {
			return out, e
		}
		out.Commands = append(out.Commands, "nat-policy", "rule name "+name)
		for _, side := range []struct {
			word  string
			any   bool
			zones []fm.ID
		}{{"source-zone", r.Match.AnyFromZone, r.Match.FromZones}, {"destination-zone", r.Match.AnyToZone, r.Match.ToZones}} {
			if side.any {
				if len(side.zones) != 0 {
					return out, ErrRender
				}
				continue
			}
			if len(side.zones) == 0 {
				return out, ErrRender
			}
			for _, id := range side.zones {
				if after.Zone(id) == nil {
					return out, ErrRender
				}
				v, e := quoted(string(id))
				if e != nil {
					return out, e
				}
				out.Commands = append(out.Commands, side.word+" "+v)
			}
		}
		for _, side := range []struct {
			word string
			any  bool
			refs []fm.AddressRef
		}{{"source-address", r.Match.AnySource, r.Match.Sources}, {"destination-address", r.Match.AnyDestination, r.Match.Destinations}} {
			if side.any {
				if len(side.refs) != 0 {
					return out, ErrRender
				}
				continue
			}
			if len(side.refs) == 0 {
				return out, ErrRender
			}
			for _, ref := range side.refs {
				v, e := addressText(after, ref)
				if e != nil {
					return out, e
				}
				out.Commands = append(out.Commands, side.word+" "+v)
			}
		}
		if !r.Match.AnyService {
			if len(r.Match.Services) == 0 {
				return out, ErrRender
			}
			for _, ref := range r.Match.Services {
				values, e := serviceText(after, ref)
				if e != nil {
					return out, e
				}
				for _, v := range values {
					out.Commands = append(out.Commands, "service "+v)
				}
			}
		} else if len(r.Match.Services) != 0 {
			return out, ErrRender
		}
		if r.Interface != "" {
			i := after.Interface(r.Interface)
			if i == nil || i.Disabled() || i.HasUnsupported() {
				return out, ErrRender
			}
			name, e := render.Token(i.Name())
			if e != nil {
				return out, e
			}
			out.Commands = append(out.Commands, "egress-interface "+name)
		}
		if r.DestinationMode != fm.NoTranslation {
			if r.Order.Stage != 1 || r.SourceMode != fm.NoTranslation || r.SourcePool != "" || r.DestinationMode != fm.StaticIP || r.DestinationPool == "" {
				return out, ErrRender
			}
			pool := after.NATPool(r.DestinationPool)
			if pool == nil {
				return out, ErrRender
			}
			p := pool.Record()
			all, _ := addressRange([]string{"0.0.0.0", "mask", "0"})
			if len(p.Ranges) != 1 || p.Ranges[0].First != p.Ranges[0].Last || len(r.Destination) != 1 || r.Destination[0] != (fm.Mapping{Original: all, Translated: p.Ranges[0], Mode: fm.Constant}) {
				return out, ErrRender
			}
			name, e := quoted(p.Name)
			if e != nil {
				return out, e
			}
			line := "action destination-nat address-group " + name
			if len(r.DestinationPorts) > 0 {
				if len(r.DestinationPorts) != 1 || r.DestinationPorts[0].Mode != fm.Constant || r.DestinationPorts[0].Original != (flow.Interval{High: 65535}) || r.DestinationPorts[0].Translated.Low != r.DestinationPorts[0].Translated.High {
					return out, ErrRender
				}
				line += fmt.Sprintf(" %d", r.DestinationPorts[0].Translated.Low)
			}
			out.Commands = append(out.Commands, line)
		} else {
			if r.Order.Stage != 2 || r.DestinationPool != "" || len(r.Destination) != 0 || len(r.DestinationPorts) != 0 {
				return out, ErrRender
			}
			if r.SourceMode == fm.InterfaceIP {
				if r.SourcePool != "" || r.Interface == "" {
					return out, ErrRender
				}
				out.Commands = append(out.Commands, "action source-nat easy-ip")
			} else {
				if r.SourceMode != fm.DynamicIPPort && r.SourceMode != fm.DynamicIP {
					return out, ErrRender
				}
				p := after.NATPool(r.SourcePool)
				if p == nil || !strings.HasPrefix(string(p.ID()), "source:") {
					return out, ErrRender
				}
				name, e := quoted(p.Name())
				if e != nil {
					return out, e
				}
				out.Commands = append(out.Commands, "action source-nat address-group "+name)
			}
		}
		out.Commands = append(out.Commands, "quit", "quit")
	}
	// Reject an inline impostor even if its traffic happens to match the parent.
	for _, a := range c.Additions.Addresses {
		if a.Inline && !out.Addresses[a.ID] {
			return out, ErrRender
		}
	}
	return out, nil
}
