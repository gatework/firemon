package asa

import (
	"context"
	"fmt"
	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/vendors/internal/render"
	"reflect"
	"slices"
	"strconv"
	"strings"
)

func nativeCommands(ctx context.Context, before, after *fm.Firewall, c plan.NativeChanges) (render.Native, error) {
	out := render.NewNative(c)
	v := strings.TrimPrefix(strings.TrimSpace(before.Metadata().Software), "ASA Version ")
	major, minor, ok := strings.Cut(v, ".")
	end := 0
	for end < len(minor) && minor[end] >= '0' && minor[end] <= '9' {
		end++
	}
	mi, e := strconv.Atoi(minor[:end])
	if !ok || e != nil || major != "9" && (major != "8" || mi < 3) {
		return out, ErrRender
	}
	usedPools := map[fm.ID]bool{}
	owner := func(o fm.Object, m fm.Match) (string, string, error) {
		if !render.PlainObject(o) || o.Scope != "" || o.ID != fm.ID("auto:"+o.Name) || !render.PlainMatch(m) || len(m.Sources) != 1 || m.AnySource || !m.AnyDestination || len(m.Destinations) != 0 {
			return "", "", ErrRender
		}
		a := after.Address(m.Sources[0].ID)
		if m.Sources[0].Kind != fm.AddressObject || a == nil || a.Name() != o.Name || before.Address(a.ID()) != nil {
			return "", "", ErrRender
		}
		name, err := commandName(o.Name)
		if err != nil {
			return "", "", err
		}
		zones := []string{}
		for _, side := range []struct {
			any bool
			ids []fm.ID
		}{{m.AnyFromZone, m.FromZones}, {m.AnyToZone, m.ToZones}} {
			if side.any && len(side.ids) == 0 {
				zones = append(zones, "any")
				continue
			}
			if side.any || len(side.ids) != 1 || after.Zone(side.ids[0]) == nil {
				return "", "", ErrRender
			}
			z, err := commandName(string(side.ids[0]))
			if err != nil {
				return "", "", err
			}
			zones = append(zones, z)
		}
		return name, "nat (" + strings.Join(zones, ",") + ") ", nil
	}
	target := func(r flow.AddressRange) (string, error) {
		if !r.Valid() || !r.First.Is4() {
			return "", ErrRender
		}
		if r.First == r.Last {
			return r.First.String(), nil
		}
		for _, a := range after.Addresses() {
			v := a.Record()
			if !v.Inline && v.Scope == "" && len(v.Ranges) == 1 && v.Ranges[0] == r && v.FQDN == "" && len(v.Unsupported) == 0 {
				return commandName(v.Name)
			}
		}
		return "", ErrRender
	}
	for _, r := range c.Additions.StaticNATs {
		name, prefix, err := owner(r.Object, r.Match)
		if err != nil {
			return out, err
		}
		if r.Order.Stage != 2 || r.Order.Section != "" || r.Disabled || !r.Bidirectional || r.SourceVIP != (fm.AddressRef{}) || r.Interface != "" || len(r.Source) != 1 || r.Source[0].Mode != fm.Offset || len(r.Destination) != 0 || len(r.DestinationPorts) != 0 {
			return out, ErrRender
		}
		real := after.Address(r.Match.Sources[0].ID).Record()
		if len(real.Ranges) != 1 || real.Ranges[0] != r.Source[0].Original {
			return out, ErrRender
		}
		mapped, err := target(r.Source[0].Translated)
		if err != nil {
			return out, err
		}
		line := prefix + "static " + mapped
		if len(r.SourcePorts) > 0 {
			if len(r.SourcePorts) != 1 || len(r.Match.Services) != 1 || r.Match.AnyService {
				return out, ErrRender
			}
			ref := r.Match.Services[0]
			svc := after.Service(ref.ID)
			if ref.Kind != fm.ServiceObject || svc == nil {
				return out, ErrRender
			}
			s := svc.Record()
			p := r.SourcePorts[0]
			if s.ID != fm.ID("$nat-service:"+string(r.ID)) || s.Name != "" || s.Scope != "" || !render.PlainObject(s.Object) || len(s.Terms) != 1 || p.Mode != fm.Offset || p.Original.Low != p.Original.High || p.Translated.Low != p.Translated.High {
				return out, ErrRender
			}
			proto := map[uint16]string{6: "tcp", 17: "udp"}[s.Terms[0].Protocol.Low]
			want := term(s.Terms[0].Protocol.Low, p.Original, flow.Interval{High: 65535})
			if proto == "" || !reflect.DeepEqual(s.Terms[0], want) {
				return out, ErrRender
			}
			out.Services[s.ID] = true
			line += fmt.Sprintf(" service %s %d %d", proto, p.Original.Low, p.Translated.Low)
		} else if !r.Match.AnyService || len(r.Match.Services) != 0 {
			return out, ErrRender
		}
		out.Commands = append(out.Commands, "object network "+name, line, "exit")
	}
	for _, r := range c.Additions.DynamicNATs {
		name, prefix, err := owner(r.Object, r.Match)
		if err != nil {
			return out, err
		}
		if r.Order.Stage != 2 || r.Order.Section != "" || r.Disabled || r.Rule != "" || !r.Match.AnyService || len(r.Match.Services) != 0 || r.DestinationMode != fm.NoTranslation || r.DestinationPool != "" || len(r.Destination) != 0 || len(r.SourcePorts) != 0 || len(r.DestinationPorts) != 0 || r.InterfaceAddress.IsValid() {
			return out, ErrRender
		}
		mapped := "interface"
		if r.SourceMode == fm.InterfaceIP {
			if r.SourcePool != "" || r.Match.AnyToZone || len(r.Match.ToZones) != 1 {
				return out, ErrRender
			}
			i := after.Interface(r.Interface)
			if i == nil || i.Zone() == nil || i.Zone().ID() != r.Match.ToZones[0] || i.Disabled() || i.HasUnsupported() {
				return out, ErrRender
			}
		} else {
			if r.SourceMode != fm.DynamicIPPort || r.Interface != "" {
				return out, ErrRender
			}
			pool := after.NATPool(r.SourcePool)
			if pool == nil {
				return out, ErrRender
			}
			p := pool.Record()
			if !render.PlainObject(p.Object) || p.ID != fm.ID("$pool:"+string(r.ID)) || p.Name != "" || p.Scope != "" || p.Interface != "" || p.Ports != (flow.Interval{}) || len(p.Ranges) != 1 || p.Ranges[0].First != p.Ranges[0].Last {
				return out, ErrRender
			}
			mapped, err = target(p.Ranges[0])
			if err != nil {
				return out, err
			}
			usedPools[p.ID] = true
		}
		out.Commands = append(out.Commands, "object network "+name, prefix+"dynamic "+mapped, "exit")
	}
	for _, p := range c.Additions.NATPools {
		if !usedPools[p.ID] {
			return out, ErrRender
		}
	}
	// Auto NAT uses derived source cardinality/address/name order, not command
	// append order. Check the candidate's actual order, including surviving rules.
	entries := []fm.NATEntry{}
	for _, e := range after.NATSequence() {
		if e.Order.Stage == 2 {
			entries = append(entries, e)
		}
	}
	sorted := slices.Clone(entries)
	slices.SortStableFunc(sorted, func(a, b fm.NATEntry) int {
		if a.Kind != b.Kind {
			return int(a.Kind) - int(b.Kind)
		}
		get := func(e fm.NATEntry) (flow.AddressRange, string) {
			if e.Kind == fm.StaticNATObject {
				r := after.StaticNAT(e.ID).Record()
				return r.Source[0].Original, r.Name
			}
			r := after.DynamicNAT(e.ID).Record()
			return after.Address(r.Match.Sources[0].ID).Record().Ranges[0], r.Name
		}
		x, xn := get(a)
		y, yn := get(b)
		if n := rangeCount(x).Cmp(rangeCount(y)); n != 0 {
			return n
		}
		if n := x.First.Compare(y.First); n != 0 {
			return n
		}
		return strings.Compare(xn, yn)
	})
	if !reflect.DeepEqual(entries, sorted) {
		return out, ErrRender
	}
	return out, ctx.Err()
}
