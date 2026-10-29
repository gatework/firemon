package fortinet

import (
	"context"
	"math/big"
	"slices"
	"strings"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/flow"
)

func addressRange(value string) (flow.Range, bool) {
	a, b, has := strings.Cut(value, "-")
	if !has {
		b = a
	}
	return ipv4Range(a, b)
}
func equalSize(a, b flow.Range) bool {
	size := func(r flow.Range) *big.Int {
		lo, hi := r.First.As16(), r.Last.As16()
		return new(big.Int).Sub(new(big.Int).SetBytes(hi[:]), new(big.Int).SetBytes(lo[:]))
	}
	return a.Valid() && b.Valid() && size(a).Cmp(size(b)) == 0
}
func (p *parser) natObjects(ctx context.Context, s *config.Session) error {
	tx := s.Cursor().Begin()
	defer tx.Rollback()
	var d fm.Data
	err := p.each(ctx, tx, "firewall ippool", func(b *config.Block) {
		name := b.Header.Words[1]
		r := fm.NATPoolRecord{Object: object(name, name, p.vdom), Ports: flow.Interval{High: 65535}}
		f := readFields(tx, b, &r.Object)
		mode := f.choice("type", "overload", "overload", "one-to-one", "fixed-port-range", "port-block-allocation")
		p.poolModes[r.ID] = fm.UnknownTranslation
		if mode == "overload" {
			p.poolModes[r.ID] = fm.DynamicIPPort
		} else {
			f.invalid("pool allocation mode")
		}
		if target, ok := ipv4Range(f.one("startip", ""), f.one("endip", "")); ok {
			r.Ranges = []flow.Range{target}
		} else {
			f.invalid("pool range")
		}
		r.Interface = fm.ID(f.one("associated-interface", ""))
		f.choice("arp-reply", "enable", "enable", "disable")
		f.ignore("comments")
		f.finish()
		d.NATPools = append(d.NATPools, r)
	})
	if err != nil {
		return err
	}
	err = p.each(ctx, tx, "firewall vip", func(b *config.Block) {
		name := b.Header.Words[1]
		id := "vip:" + name
		o := object(id, name, p.vdom)
		f := readFields(tx, b, &o)
		if f.choice("type", "static-nat", "static-nat") != "static-nat" {
			f.invalid("VIP type")
		}
		public, ok1 := addressRange(f.one("extip", ""))
		private, ok2 := addressRange(f.one("mappedip", ""))
		if !ok1 || !ok2 {
			f.invalid("VIP address range")
		}
		if ok1 && public.First.IsUnspecified() {
			f.invalid("interface-dependent VIP address")
		}
		match := fm.Match{AnySource: true, AnyDestination: true, AnyService: true, AnyFromZone: true, AnyToZone: true}
		external := f.one("extintf", "")
		ifaceID := fm.ID("")
		if external != "any" {
			ifaceID = fm.ID(external)
			if iface, ok := p.interfaces[ifaceID]; ok {
				match.AnyFromZone = false
				match.FromZones = []fm.ID{iface.Zone}
				count := 0
				for _, i := range p.data.Interfaces {
					if i.Zone == iface.Zone {
						count++
					}
				}
				if count != 1 {
					f.invalid("VIP interface is ambiguous within its zone")
				}
			} else {
				f.invalid("VIP external interface")
			}
		}
		forward := f.choice("portforward", "disable", "enable", "disable") == "enable"
		disabled := f.choice("status", "enable", "enable", "disable") == "disable"
		// Source forcing is retained as a distinct native source-stage mapping.
		forced := f.choice("nat-source-vip", "disable", "enable", "disable") == "enable"
		f.choice("arp-reply", "enable", "enable", "disable")
		var mappings []fm.Mapping
		if ok1 && ok2 {
			mode := fm.Offset
			if !equalSize(public, private) {
				mode = fm.UnknownMapping
				f.invalid("unequal VIP address ranges")
			}
			mappings = []fm.Mapping{{Original: public, Translated: private, Mode: mode}}
		}
		var portMappings []fm.PortMapping
		if forward {
			proto := uint16(0)
			switch f.choice("protocol", "tcp", "tcp", "udp", "sctp") {
			case "tcp":
				proto = 6
			case "udp":
				proto = 17
			case "sctp":
				proto = 132
			}
			original, a := ports(f.one("extport", ""))
			mappedText := f.one("mappedport", "")
			translated, b := ports(mappedText)
			if f.choice("portmapping-type", "1-to-1", "1-to-1") != "1-to-1" {
				f.invalid("port mapping type")
			}
			if b && !strings.Contains(mappedText, "-") {
				end := uint32(translated.Low) + uint32(original.High-original.Low)
				if end > 65535 {
					b = false
				} else {
					translated.High = uint16(end)
				}
			}
			if !a || !b || original.High-original.Low != translated.High-translated.Low {
				f.invalid("VIP port mapping")
			} else {
				portMappings = []fm.PortMapping{{Original: original, Translated: translated, Mode: fm.Offset}}
				service := fm.ServiceRecord{Object: object(id+":service", name, p.vdom), Terms: []fm.ServiceTerm{serviceTerm(proto)}}
				service.Terms[0].DestinationPort = original
				d.Services = append(d.Services, service)
				match.AnyService = false
				match.Services = []fm.ServiceRef{{Kind: fm.ServiceObject, ID: service.ID}}
			}
		}
		f.ignore("comment", "uuid", "color")
		f.finish()
		kind := fm.StaticNATObject
		if forward {
			kind = fm.DynamicNATObject
		}
		a := fm.AddressRecord{Object: object(id, name, p.vdom), VIP: fm.NATRef{Kind: kind, ID: o.ID}}
		if ok1 {
			a.Ranges = []flow.Range{public}
		}
		a.Unsupported = slices.Clone(o.Unsupported)
		d.Addresses = append(d.Addresses, a)
		p.addresses[name] = fm.AddressRef{Kind: fm.AddressObject, ID: a.ID}
		order := fm.NATOrder{Stage: 0, Position: len(d.StaticNATs) + len(d.DynamicNATs), Section: "vip"}
		if forward {
			d.DynamicNATs = append(d.DynamicNATs, fm.DynamicNATRecord{Object: o, Match: match, Order: order, SourceMode: fm.NoTranslation, DestinationMode: fm.StaticIP, Destination: mappings, DestinationPorts: portMappings, Interface: ifaceID, Disabled: disabled})
		} else {
			d.StaticNATs = append(d.StaticNATs, fm.StaticNATRecord{Object: o, Match: match, Order: order, Destination: mappings, Interface: ifaceID, Disabled: disabled})
		}
		if !forward || forced {
			reverse := fm.StaticNATRecord{Object: object("vip-source:"+name, name, p.vdom), SourceVIP: fm.AddressRef{Kind: fm.AddressObject, ID: a.ID}, Match: fm.Match{AnySource: true, AnyDestination: true, AnyService: true, AnyFromZone: true, AnyToZone: true}, Order: fm.NATOrder{Stage: 2, Position: order.Position, Section: "vip-source-interface"}, Disabled: disabled}
			reverse.Spans = slices.Clone(o.Spans)
			reverse.Unsupported = slices.Clone(o.Unsupported)
			if forward {
				reverse.Unsupported = append(reverse.Unsupported, "port-forward source forcing is not established")
			}
			for _, m := range mappings {
				reverse.Source = append(reverse.Source, fm.Mapping{Original: m.Translated, Translated: m.Original, Mode: m.Mode})
			}
			if forced {
				reverse.Order.Section = "vip-source-forced"
			} else if !match.AnyFromZone {
				reverse.Match.AnyToZone = false
				reverse.Match.ToZones = slices.Clone(match.FromZones)
				reverse.Interface = ifaceID
			}
			d.StaticNATs = append(d.StaticNATs, reverse)
		}
	})
	if err != nil {
		return err
	}
	var groupNames [][]string
	err = p.each(ctx, tx, "firewall vipgrp", func(b *config.Block) {
		name := b.Header.Words[1]
		r := fm.AddressGroupRecord{Object: object("vip-group:"+name, name, p.vdom)}
		f := readFields(tx, b, &r.Object)
		names := f.list("member")
		if iface := f.one("interface", ""); iface != "" && iface != "any" {
			f.invalid("interface-qualified VIP group")
		}
		f.ignore("comments", "uuid", "color")
		f.finish()
		p.addresses[name] = fm.AddressRef{Kind: fm.AddressGroupObject, ID: r.ID}
		groupNames = append(groupNames, names)
		d.AddressGroups = append(d.AddressGroups, r)
	})
	if err != nil {
		return err
	}
	vips := make(map[fm.ID]bool, len(d.Addresses))
	for _, a := range d.Addresses {
		if a.VIP != (fm.NATRef{}) {
			vips[a.ID] = true
		}
	}
	for i, names := range groupNames {
		for _, name := range names {
			ref := p.addressRef(name)
			if ref.Kind != fm.AddressObject || !vips[ref.ID] {
				d.AddressGroups[i].Unsupported = append(d.AddressGroups[i].Unsupported, "VIP group member is not a VIP")
			}
			d.AddressGroups[i].Members = append(d.AddressGroups[i].Members, ref)
		}
	}
	return p.commit(s, tx, d)
}

func (p *parser) policyNAT(f *fields, r fm.RuleRecord) *fm.DynamicNATRecord {
	enabled := f.choice("nat", "disable", "enable", "disable") == "enable"
	poolEnabled := f.choice("ippool", "disable", "enable", "disable") == "enable"
	pools := f.list("poolname")
	fixed := f.choice("fixedport", "disable", "enable", "disable") == "enable"
	if !enabled {
		return nil
	}
	n := &fm.DynamicNATRecord{Object: object("policy:"+string(r.ID), r.Name, p.vdom), Rule: r.ID, Match: r.Match, Order: fm.NATOrder{Stage: 1, Position: r.Position, Section: "policy"}, SourceMode: fm.InterfaceIP, DestinationMode: fm.NoTranslation, Disabled: r.Disabled}
	n.Spans = slices.Clone(r.Spans)
	if poolEnabled {
		if len(pools) != 1 {
			n.Unsupported = append(n.Unsupported, "policy requires exactly one IP pool")
		} else {
			n.SourcePool = fm.ID(pools[0])
			n.SourceMode = p.poolModes[n.SourcePool]
			if fixed && n.SourceMode == fm.DynamicIPPort {
				n.SourceMode = fm.DynamicIP
			}
		}
	} else {
		var candidates []fm.InterfaceRecord
		for _, iface := range p.data.Interfaces {
			if !iface.Disabled && slices.Contains(r.Match.ToZones, iface.Zone) {
				candidates = append(candidates, iface)
			}
		}
		if len(candidates) != 1 || len(candidates[0].Addresses) != 1 {
			n.Unsupported = append(n.Unsupported, "interface NAT requires a unique addressed egress")
		} else {
			n.Interface = candidates[0].ID
		}
		if fixed {
			n.Unsupported = append(n.Unsupported, "fixed port interface allocation")
		}
	}
	return n
}
