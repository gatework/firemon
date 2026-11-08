package srx

import (
	"context"
	"fmt"
	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/vendors/internal/render"
	"reflect"
	"strings"
)

func nativeCommands(ctx context.Context, before, after *fm.Firewall, c plan.NativeChanges, out *render.NativeBuilder) error {
	if err := render.AppendNAT(before, after); err != nil {
		return err
	}
	usedPools := map[fm.ID]string{}
	for _, r := range c.Additions.DynamicNATs {
		if r.SourcePool != "" {
			usedPools[r.SourcePool] = "source"
		}
		if r.DestinationPool != "" {
			usedPools[r.DestinationPool] = "destination"
		}
	}
	for _, p := range c.Additions.NATPools {
		direction := usedPools[p.ID]
		name, e := token(p.Name)
		if e != nil || direction == "" || !render.PlainObject(p.Object) || p.Scope != "" || p.ID != nativeID("nat-pool", direction, p.Name) || p.Interface != "" || len(p.Ranges) != 1 {
			return ErrRender
		}
		value, e := render.Prefix(p.Ranges[0])
		if e != nil {
			if direction == "destination" {
				return ErrRender
			}
			value = p.Ranges[0].First.String() + " to " + p.Ranges[0].Last.String()
		}
		prefix := "set security nat " + direction + " pool " + name
		out.AppendCommands(prefix + " address " + value)
		if direction == "source" {
			if p.Ports == (flow.Interval{}) {
				out.AppendCommands(prefix + " port no-translation")
			} else {
				if p.Ports.Low < 1024 {
					return ErrRender
				}
				if p.Ports != (flow.Interval{Low: 1024, High: 65535}) {
					out.AppendCommands(fmt.Sprintf("%s port range %d to %d", prefix, p.Ports.Low, p.Ports.High))
				}
			}
		} else if p.Ranges[0].First != p.Ranges[0].Last {
			return ErrRender
		} else if p.Ports != (flow.Interval{}) {
			if p.Ports.Low != p.Ports.High {
				return ErrRender
			}
			out.AppendCommands(fmt.Sprintf("%s address port %d", prefix, p.Ports.Low))
		}
	}
	emitMatch := func(owner render.Owner, o fm.Object, m fm.Match, order fm.NATOrder) (string, string, error) {
		direction, set, ok := strings.Cut(order.Section, ":")
		if !ok || o.Scope != "" || !render.PlainObject(o) || !render.PlainMatch(m) || m.AnyFromZone || len(m.FromZones) != 1 || after.Zone(m.FromZones[0]) == nil {
			return "", "", ErrRender
		}
		if _, err := token(set); err != nil {
			return "", "", err
		}
		if _, err := token(o.Name); err != nil {
			return "", "", err
		}
		if o.ID != nativeID("nat", direction, set, o.Name) {
			return "", "", ErrRender
		}
		if order.Stage != map[string]int{"static": 0, "destination": 1, "source": 2}[direction] || direction != "static" && direction != "destination" && direction != "source" {
			return "", "", ErrRender
		}
		prefix := "set security nat " + direction + " rule-set " + set
		from, err := token(string(m.FromZones[0]))
		if err != nil {
			return "", "", err
		}
		out.AppendCommands(prefix + " from zone " + from)
		if direction == "source" {
			if m.AnyToZone || len(m.ToZones) != 1 || after.Zone(m.ToZones[0]) == nil {
				return "", "", ErrRender
			}
			to, e := token(string(m.ToZones[0]))
			if e != nil {
				return "", "", e
			}
			out.AppendCommands(prefix + " to zone " + to)
		} else if !m.AnyToZone || len(m.ToZones) != 0 {
			return "", "", ErrRender
		}
		// Reopening a rule-set may not change surviving rules' shared context.
		for _, entry := range after.NATSequence() {
			var other fm.Match
			if entry.Kind == fm.StaticNATObject {
				other = after.StaticNAT(entry.ID).Record().Match
			} else {
				other = after.DynamicNAT(entry.ID).Record().Match
			}
			if entry.ID == o.ID {
				continue
			}
			if entry.Order.Section == order.Section && (!reflect.DeepEqual(other.FromZones, m.FromZones) || !reflect.DeepEqual(other.ToZones, m.ToZones)) {
				return "", "", ErrRender
			}
			if entry.Order.Stage == order.Stage && entry.Order.Section != order.Section && reflect.DeepEqual(other.FromZones, m.FromZones) && reflect.DeepEqual(other.ToZones, m.ToZones) {
				return "", "", ErrRender
			}
		}
		prefix += " rule " + o.Name
		for axis, side := range []struct {
			any  bool
			refs []fm.AddressRef
			word string
		}{{m.AnySource, m.Sources, "source-address"}, {m.AnyDestination, m.Destinations, "destination-address"}} {
			if side.any {
				if len(side.refs) != 0 {
					return "", "", ErrRender
				}
				continue
			}
			if len(side.refs) == 0 {
				return "", "", ErrRender
			}
			for _, ref := range side.refs {
				a := after.Address(ref.ID)
				if ref.Kind != fm.AddressObject || a == nil {
					return "", "", ErrRender
				}
				v := a.Record()
				if len(v.Ranges) != 1 || !render.PlainObject(v.Object) || v.Name != "" || v.Scope != "nat:"+string(o.ID) || v.FQDN != "" || v.VIP != (fm.NATRef{}) {
					return "", "", ErrRender
				}
				r := v.Ranges[0]
				if v.ID != nativeID("nat-address", string(o.ID), string(rune('s'+axis)), r.First.String(), r.Last.String()) {
					return "", "", ErrRender
				}
				value, e := render.Prefix(r)
				if e != nil {
					return "", "", e
				}
				if err := out.ClaimAddress(owner, ref); err != nil {
					return "", "", err
				}
				out.AppendCommands(prefix + " match " + side.word + " " + value)
			}
		}
		if !m.AnyService {
			terms, e := render.Services(ctx, after, m)
			if e != nil || len(terms) != 1 || len(m.Services) != 1 {
				return "", "", ErrRender
			}
			s := after.Service(m.Services[0].ID)
			if s == nil || s.ID() != nativeID("nat-service", string(o.ID)) || s.Name() != "" || s.Scope() != "nat:"+string(o.ID) {
				return "", "", ErrRender
			}
			term := terms[0]
			if term.Protocol.Low != term.Protocol.High || term.ICMPType != (flow.Interval{High: 255}) || term.ICMPCode != (flow.Interval{High: 255}) {
				return "", "", ErrRender
			}
			if err := out.ClaimService(owner, m.Services[0]); err != nil {
				return "", "", err
			}
			out.AppendCommands(fmt.Sprintf("%s match protocol %d", prefix, term.Protocol.Low))
			for _, side := range []struct {
				word string
				p    flow.Interval
			}{{"source-port", term.SourcePort}, {"destination-port", term.DestinationPort}} {
				if side.p != (flow.Interval{High: 65535}) {
					if term.Protocol.Low != 6 && term.Protocol.Low != 17 {
						return "", "", ErrRender
					}
					out.AppendCommands(prefix + " match " + side.word + " " + portText(side.p))
				}
			}
		} else if len(m.Services) != 0 {
			return "", "", ErrRender
		}
		return prefix, direction, nil
	}
	for _, entry := range after.NATSequence() {
		if err := ctx.Err(); err != nil {
			return err
		}
		if entry.Kind == fm.StaticNATObject {
			if before.StaticNAT(entry.ID) != nil {
				continue
			}
			r := after.StaticNAT(entry.ID).Record()
			prefix, direction, e := emitMatch(render.NATOwner(fm.NATRef{Kind: fm.StaticNATObject, ID: r.ID}), r.Object, r.Match, r.Order)
			if e != nil {
				return e
			}
			if direction != "static" || r.Disabled || !r.Bidirectional || r.Interface != "" || r.SourceVIP != (fm.AddressRef{}) || len(r.Source) != 0 || len(r.SourcePorts) != 0 || len(r.DestinationPorts) != 0 || len(r.Destination) != 1 || r.Destination[0].Mode != fm.Offset || !equalPrefixSize(r.Destination[0].Original, r.Destination[0].Translated) {
				return ErrRender
			}
			ranges, e := render.Addresses(ctx, after, r.Match.Destinations, r.Match.AnyDestination)
			if e != nil || len(ranges) != 1 || ranges[0] != r.Destination[0].Original {
				return ErrRender
			}
			v, e := render.Prefix(r.Destination[0].Translated)
			if e != nil {
				return e
			}
			out.AppendCommands(prefix + " then static-nat prefix " + v)
		} else {
			if before.DynamicNAT(entry.ID) != nil {
				continue
			}
			r := after.DynamicNAT(entry.ID).Record()
			prefix, direction, e := emitMatch(render.NATOwner(fm.NATRef{Kind: fm.DynamicNATObject, ID: r.ID}), r.Object, r.Match, r.Order)
			if e != nil {
				return e
			}
			if r.Disabled || r.Rule != "" || r.Interface != "" || r.InterfaceAddress.IsValid() || len(r.SourcePorts) != 0 {
				return ErrRender
			}
			poolID := r.SourcePool
			if direction == "destination" {
				poolID = r.DestinationPool
			}
			pool := after.NATPool(poolID)
			if pool == nil {
				return ErrRender
			}
			p := pool.Record()
			if p.ID != nativeID("nat-pool", direction, p.Name) || p.Scope != "" || len(p.Unsupported) != 0 {
				return ErrRender
			}
			if direction == "source" {
				mode := fm.DynamicIPPort
				if p.Ports == (flow.Interval{}) {
					mode = fm.DynamicIP
				}
				if r.SourceMode != mode || r.DestinationMode != fm.NoTranslation || r.DestinationPool != "" || len(r.Destination) != 0 || len(r.DestinationPorts) != 0 {
					return ErrRender
				}
			} else if direction == "destination" {
				if r.SourceMode != fm.NoTranslation || r.SourcePool != "" || r.DestinationMode != fm.StaticIP || len(p.Ranges) != 1 || p.Ranges[0].First != p.Ranges[0].Last {
					return ErrRender
				}
				ranges, e := render.Addresses(ctx, after, r.Match.Destinations, r.Match.AnyDestination)
				if e != nil || len(ranges) != 1 || len(r.Destination) != 1 || r.Destination[0] != (fm.Mapping{Original: ranges[0], Translated: p.Ranges[0], Mode: fm.Constant}) {
					return ErrRender
				}
				want := []fm.PortMapping(nil)
				if p.Ports != (flow.Interval{}) {
					want = []fm.PortMapping{{Original: flow.Interval{High: 65535}, Translated: p.Ports, Mode: fm.Constant}}
				}
				if !reflect.DeepEqual(want, r.DestinationPorts) {
					return ErrRender
				}
			} else {
				return ErrRender
			}
			name, e := token(p.Name)
			if e != nil {
				return e
			}
			out.AppendCommands(prefix + " then " + direction + "-nat pool " + name)
		}
	}
	return nil
}
