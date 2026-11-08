package paloalto

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/vendors/internal/render"
)

func nativeCommands(ctx context.Context, before, after *fm.Firewall, c plan.NativeChanges, out *render.NativeBuilder) error {
	if len(c.Additions.StaticNATs)+len(c.Additions.DynamicNATs)+len(c.Additions.NATPools) == 0 {
		return nil
	}
	if !strings.HasPrefix(strings.TrimPrefix(before.Metadata().Software, "PAN-OS "), "10.2.") {
		return ErrRender
	}
	if err := render.AppendNAT(before, after); err != nil {
		return err
	}
	used := make(map[fm.ID]bool)
	addressName := func(owner render.Owner, ref fm.AddressRef) (string, error) {
		var o fm.Object
		switch ref.Kind {
		case fm.AddressObject:
			a := after.Address(ref.ID)
			if a == nil {
				return "", ErrRender
			}
			r := a.Record()
			o = r.Object
			if value, ok := strings.CutPrefix(string(r.ID), "$literal:"); ok {
				v, e := address(value)
				if e != nil || r.Name != value || r.Scope != "" || r.Inline || r.FQDN != "" || r.VIP != (fm.NATRef{}) || len(r.Unsupported) > 0 || len(r.Ranges) != 1 || r.Ranges[0] != v {
					return "", ErrRender
				}
				if e = out.ClaimAddress(owner, ref); e != nil {
					return "", e
				}
				return quoted(value)
			}
		case fm.AddressGroupObject:
			g := after.AddressGroup(ref.ID)
			if g == nil {
				return "", ErrRender
			}
			o = g.Record().Object
		default:
			return "", ErrRender
		}
		if o.Scope != "" || o.ID != fm.ID(o.Name) || !render.PlainObject(o) {
			return "", ErrRender
		}
		return quoted(o.Name)
	}
	match := func(owner render.Owner, o fm.Object, m fm.Match, order fm.NATOrder) (string, error) {
		if !render.PlainObject(o) || o.Scope != "" || o.ID != fm.ID(o.Name) || !render.PlainMatch(m) || order.Stage != 1 || order.Section != "" {
			return "", ErrRender
		}
		name, e := quoted(o.Name)
		if e != nil {
			return "", e
		}
		prefix := "set rulebase nat rules " + name
		for _, side := range []struct {
			field string
			any   bool
			zones []fm.ID
		}{{"from", m.AnyFromZone, m.FromZones}, {"to", m.AnyToZone, m.ToZones}} {
			if side.any {
				if len(side.zones) > 0 {
					return "", ErrRender
				}
				out.AppendCommands(prefix + " " + side.field + " any")
				continue
			}
			if len(side.zones) == 0 {
				return "", ErrRender
			}
			for _, id := range side.zones {
				z := after.Zone(id)
				if z == nil || z.HasUnsupported() {
					return "", ErrRender
				}
				name, e := quoted(z.Name())
				if e != nil {
					return "", e
				}
				out.AppendCommands(prefix + " " + side.field + " " + name)
			}
		}
		for _, side := range []struct {
			field string
			any   bool
			refs  []fm.AddressRef
		}{{"source", m.AnySource, m.Sources}, {"destination", m.AnyDestination, m.Destinations}} {
			if side.any {
				if len(side.refs) > 0 {
					return "", ErrRender
				}
				out.AppendCommands(prefix + " " + side.field + " any")
				continue
			}
			if len(side.refs) == 0 {
				return "", ErrRender
			}
			for _, ref := range side.refs {
				name, e := addressName(owner, ref)
				if e != nil {
					return "", e
				}
				out.AppendCommands(prefix + " " + side.field + " " + name)
			}
		}
		service := "any"
		if m.AnyService {
			if len(m.Services) > 0 {
				return "", ErrRender
			}
		} else {
			if len(m.Services) != 1 || m.Services[0].Kind != fm.ServiceObject {
				return "", ErrRender
			}
			s := after.Service(m.Services[0].ID)
			if s == nil || s.HasUnsupported() || s.Scope() != "" {
				return "", ErrRender
			}
			var e error
			service, e = quoted(s.Name())
			if e != nil {
				return "", e
			}
		}
		out.AppendCommands(prefix + " service " + service)
		return prefix, nil
	}
	destination := func(prefix string, m fm.Match, maps []fm.Mapping, ports []fm.PortMapping) error {
		if len(maps) == 0 {
			if len(ports) > 0 {
				return ErrRender
			}
			return nil
		}
		original, e := render.Addresses(ctx, after, m.Destinations, m.AnyDestination)
		if e != nil || len(original) != len(maps) {
			return ErrRender
		}
		target := maps[0].Translated
		if !target.Valid() || !target.First.Is4() || target.First != target.Last {
			return ErrRender
		}
		for i, v := range maps {
			if v.Mode != fm.Constant || v.Original != original[i] || v.Translated != target {
				return ErrRender
			}
		}
		out.AppendCommands(prefix + " destination-translation translated-address " + target.First.String())
		if len(ports) > 0 {
			terms, e := render.Services(ctx, after, m)
			if e != nil || len(terms) != len(ports) {
				return ErrRender
			}
			target := ports[0].Translated
			if target.Low != target.High {
				return ErrRender
			}
			for i, p := range ports {
				if p.Mode != fm.Constant || p.Original != terms[i].DestinationPort || p.Translated != target {
					return ErrRender
				}
			}
			out.AppendCommands(fmt.Sprintf("%s destination-translation translated-port %d", prefix, target.Low))
		}
		return nil
	}
	for _, entry := range after.NATSequence() {
		if err := ctx.Err(); err != nil {
			return err
		}
		owner := render.NATOwner(fm.NATRef{Kind: entry.Kind, ID: entry.ID})
		if entry.Kind == fm.StaticNATObject {
			if before.StaticNAT(entry.ID) != nil {
				continue
			}
			r := after.StaticNAT(entry.ID).Record()
			if r.Disabled || r.SourceVIP != (fm.AddressRef{}) || r.Interface != "" || len(r.SourcePorts) > 0 || len(r.Source) != 1 || r.Source[0].Mode != fm.Offset {
				return ErrRender
			}
			prefix, e := match(owner, r.Object, r.Match, r.Order)
			if e != nil {
				return e
			}
			original, e := render.Addresses(ctx, after, r.Match.Sources, r.Match.AnySource)
			if e != nil || len(original) != 1 || original[0] != r.Source[0].Original {
				return ErrRender
			}
			target, e := render.Prefix(r.Source[0].Translated)
			if e != nil {
				return e
			}
			out.AppendCommands(prefix + " source-translation static-ip translated-address " + target)
			bidirectional := "no"
			if r.Bidirectional {
				bidirectional = "yes"
			}
			out.AppendCommands(prefix + " source-translation static-ip bi-directional " + bidirectional)
			if e = destination(prefix, r.Match, r.Destination, r.DestinationPorts); e != nil {
				return e
			}
		} else {
			if before.DynamicNAT(entry.ID) != nil {
				continue
			}
			r := after.DynamicNAT(entry.ID).Record()
			if r.Disabled || r.Rule != "" || r.DestinationPool != "" || len(r.SourcePorts) > 0 {
				return ErrRender
			}
			prefix, e := match(owner, r.Object, r.Match, r.Order)
			if e != nil {
				return e
			}
			switch r.SourceMode {
			case fm.NoTranslation:
				if r.SourcePool != "" || r.Interface != "" || r.InterfaceAddress.IsValid() {
					return ErrRender
				}
			case fm.DynamicIP, fm.DynamicIPPort:
				if r.Interface != "" || r.InterfaceAddress.IsValid() {
					return ErrRender
				}
				pool := after.NATPool(r.SourcePool)
				if pool == nil {
					return ErrRender
				}
				p := pool.Record()
				if !render.PlainObject(p.Object) || p.ID != fm.ID("$nat:"+r.Name) || p.Name != "" || p.Scope != "" || p.Interface != "" || p.Ports != (flow.Interval{}) || len(p.Ranges) == 0 {
					return ErrRender
				}
				var targets []string
				for _, v := range p.Ranges {
					target, e := render.Range(v)
					if e != nil {
						return e
					}
					targets = append(targets, target)
				}
				mode := "dynamic-ip"
				if r.SourceMode == fm.DynamicIPPort {
					mode = "dynamic-ip-and-port"
				}
				out.AppendCommands(prefix + " source-translation " + mode + " translated-address [ " + strings.Join(targets, " ") + " ]")
				used[p.ID] = true
			case fm.InterfaceIP:
				if r.SourcePool != "" {
					return ErrRender
				}
				i := after.Interface(r.Interface)
				if i == nil || i.Disabled() || i.HasUnsupported() {
					return ErrRender
				}
				addresses := i.Record().Addresses
				if r.InterfaceAddress.IsValid() {
					if !slices.ContainsFunc(addresses, func(p netip.Prefix) bool { return p.Addr() == r.InterfaceAddress }) {
						return ErrRender
					}
				} else if len(addresses) != 1 {
					return ErrRender
				}
				name, e := quoted(i.Name())
				if e != nil {
					return e
				}
				out.AppendCommands(prefix + " source-translation dynamic-ip-and-port interface-address interface " + name)
				if r.InterfaceAddress.IsValid() {
					out.AppendCommands(prefix + " source-translation dynamic-ip-and-port interface-address ip " + r.InterfaceAddress.String())
				}
			default:
				return ErrRender
			}
			if r.DestinationMode == fm.NoTranslation {
				if len(r.Destination)+len(r.DestinationPorts) > 0 {
					return ErrRender
				}
			} else if r.DestinationMode == fm.StaticIP {
				if len(r.Destination) == 0 {
					return ErrRender
				}
			} else {
				return ErrRender
			}
			if e = destination(prefix, r.Match, r.Destination, r.DestinationPorts); e != nil {
				return e
			}
		}
	}
	for _, p := range c.Additions.NATPools {
		if !used[p.ID] {
			return ErrRender
		}
	}
	return nil
}
