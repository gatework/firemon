package fortinet

import (
	"context"
	"net/netip"
	"strconv"
	"strings"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/flow"
)

func ipv4Range(first, last string) (flow.Range, bool) {
	a, e1 := netip.ParseAddr(first)
	b, e2 := netip.ParseAddr(last)
	r := flow.Range{First: a, Last: b}
	return r, e1 == nil && e2 == nil && a.Is4() && b.Is4() && r.Valid()
}
func ports(value string) (flow.Interval, bool) {
	a, b, has := strings.Cut(value, "-")
	if !has {
		b = a
	}
	lo, e1 := strconv.ParseUint(a, 10, 16)
	hi, e2 := strconv.ParseUint(b, 10, 16)
	return flow.Interval{Low: uint16(lo), High: uint16(hi)}, e1 == nil && e2 == nil && lo <= hi
}
func serviceTerm(protocol uint16) fm.ServiceTerm {
	return fm.ServiceTerm{Protocol: flow.Interval{Low: protocol, High: protocol}, SourcePort: flow.Interval{High: 65535}, DestinationPort: flow.Interval{High: 65535}, ICMPType: flow.Interval{High: 255}, ICMPCode: flow.Interval{High: 255}}
}
func (p *parser) addressRef(name string) fm.AddressRef {
	if ref, ok := p.addresses[name]; ok {
		return ref
	}
	if name == "all" {
		return fm.AddressRef{Kind: fm.AddressObject, ID: "$all-ipv4"}
	}
	return fm.AddressRef{Kind: fm.AddressObject, ID: fm.ID(name)}
}
func (p *parser) serviceRef(name string) fm.ServiceRef {
	if ref, ok := p.services[name]; ok {
		return ref
	}
	if name == "ALL" {
		return fm.ServiceRef{Kind: fm.ServiceObject, ID: "$ALL"}
	}
	return fm.ServiceRef{Kind: fm.ServiceObject, ID: fm.ID(name)}
}
func (p *parser) objects(ctx context.Context, s *config.Session) error {
	tx := s.Cursor.Begin()
	defer tx.Rollback()
	any4, _ := flow.PrefixRange(netip.MustParsePrefix("0.0.0.0/0"))
	anyService := serviceTerm(0)
	anyService.Protocol.High = 255
	d := fm.Data{Addresses: []fm.AddressRecord{{Object: object("$all-ipv4", "all", "builtin"), Ranges: []flow.Range{any4}}}, Services: []fm.ServiceRecord{{Object: object("$ALL", "ALL", "builtin"), Terms: []fm.ServiceTerm{anyService}}}}
	err := p.each(ctx, tx, "firewall address", func(b *config.Block) {
		name := b.Header.Words[1]
		r := fm.AddressRecord{Object: object(name, name, "")}
		f := readFields(tx, b, &r.Object)
		switch f.one("type", "subnet") {
		case "subnet":
			values := f.list("subnet")
			if len(values) == 0 {
				values = []string{"0.0.0.0", "0.0.0.0"}
			}
			if v, ok := prefix(values); ok && v == v.Masked() {
				rr, _ := flow.PrefixRange(v)
				r.Ranges = []flow.Range{rr}
			} else {
				f.invalid("subnet")
			}
		case "iprange":
			if v, ok := ipv4Range(f.one("start-ip", ""), f.one("end-ip", "")); ok {
				r.Ranges = []flow.Range{v}
			} else {
				f.invalid("iprange")
			}
		case "fqdn":
			r.FQDN = f.one("fqdn", "")
			f.invalid("runtime FQDN resolution")
		default:
			f.invalid("address type")
		}
		if assoc := f.one("associated-interface", ""); assoc != "" && assoc != "any" {
			if _, ok := p.interfaces[fm.ID(assoc)]; !ok {
				if _, ok := p.zones[fm.ID(assoc)]; !ok {
					f.invalid("associated-interface")
				}
			}
		}
		f.ignore("comment", "uuid", "color")
		f.finish()
		p.addresses[name] = fm.AddressRef{Kind: fm.AddressObject, ID: r.ID}
		d.Addresses = append(d.Addresses, r)
	})
	if err != nil {
		return err
	}
	var groupNames [][]string
	// Register VIP identities before groups, while leaving their fields pending
	// until the NAT stage can resolve interfaces and services.
	for _, section := range p.sections["firewall vip"] {
		for _, b := range section.Children {
			if b.Kind == "edit" {
				name := b.Header.Words[1]
				p.addresses[name] = fm.AddressRef{Kind: fm.AddressObject, ID: fm.ID("vip:" + name)}
			}
		}
	}
	err = p.each(ctx, tx, "firewall addrgrp", func(b *config.Block) {
		name := b.Header.Words[1]
		r := fm.AddressGroupRecord{Object: object(name, name, "")}
		f := readFields(tx, b, &r.Object)
		names := f.list("member")
		f.ignore("comment", "uuid", "color")
		f.finish()
		if _, exists := p.addresses[name]; exists {
			r.Unsupported = append(r.Unsupported, "address/group name collision")
		}
		p.addresses[name] = fm.AddressRef{Kind: fm.AddressGroupObject, ID: r.ID}
		groupNames = append(groupNames, names)
		d.AddressGroups = append(d.AddressGroups, r)
	})
	if err != nil {
		return err
	}
	for i, names := range groupNames {
		for _, name := range names {
			d.AddressGroups[i].Members = append(d.AddressGroups[i].Members, p.addressRef(name))
		}
	}
	err = p.each(ctx, tx, "firewall service custom", func(b *config.Block) {
		name := b.Header.Words[1]
		r := fm.ServiceRecord{Object: object(name, name, "")}
		f := readFields(tx, b, &r.Object)
		if f.choice("proxy", "disable", "disable", "enable") == "enable" {
			f.invalid("proxy service")
		}
		switch f.one("protocol", "TCP/UDP/SCTP") {
		case "TCP/UDP/SCTP":
			for _, pair := range []struct {
				key   string
				proto uint16
			}{{"tcp-portrange", 6}, {"udp-portrange", 17}, {"sctp-portrange", 132}} {
				for _, value := range f.list(pair.key) {
					dest, source, has := strings.Cut(value, ":")
					term := serviceTerm(pair.proto)
					if pair.proto == 6 || pair.proto == 17 {
						term.SourcePort = p.sourcePorts
					}
					var ok bool
					if term.DestinationPort, ok = ports(dest); !ok {
						f.invalid(pair.key)
						continue
					}
					if has {
						if term.SourcePort, ok = ports(source); !ok {
							f.invalid(pair.key)
							continue
						}
					}
					r.Terms = append(r.Terms, term)
				}
			}
		case "ICMP", "ICMP6":
			proto := uint16(1)
			if f.one("protocol", "") == "ICMP6" {
				proto = 58
			}
			term := serviceTerm(proto)
			for _, pair := range []struct {
				key string
				dst *flow.Interval
			}{{"icmptype", &term.ICMPType}, {"icmpcode", &term.ICMPCode}} {
				if value := f.one(pair.key, ""); value != "" {
					n, e := strconv.ParseUint(value, 10, 8)
					if e != nil {
						f.invalid(pair.key)
					} else {
						*pair.dst = flow.Interval{Low: uint16(n), High: uint16(n)}
					}
				}
			}
			r.Terms = append(r.Terms, term)
		case "IP":
			n, e := strconv.ParseUint(f.one("protocol-number", "0"), 10, 8)
			if e != nil || n > 254 {
				f.invalid("protocol-number")
			} else {
				term := serviceTerm(uint16(n))
				if n == 0 {
					term.Protocol.High = 255
				}
				r.Terms = append(r.Terms, term)
			}
		default:
			f.invalid("service protocol")
		}
		f.ignore("comment", "uuid", "color", "category")
		f.finish()
		p.services[name] = fm.ServiceRef{Kind: fm.ServiceObject, ID: r.ID}
		d.Services = append(d.Services, r)
	})
	if err != nil {
		return err
	}
	var serviceNames [][]string
	err = p.each(ctx, tx, "firewall service group", func(b *config.Block) {
		name := b.Header.Words[1]
		r := fm.ServiceGroupRecord{Object: object(name, name, "")}
		f := readFields(tx, b, &r.Object)
		names := f.list("member")
		f.ignore("comment", "uuid", "color")
		f.finish()
		if _, exists := p.services[name]; exists {
			r.Unsupported = append(r.Unsupported, "service/group name collision")
		}
		p.services[name] = fm.ServiceRef{Kind: fm.ServiceGroupObject, ID: r.ID}
		serviceNames = append(serviceNames, names)
		d.ServiceGroups = append(d.ServiceGroups, r)
	})
	if err != nil {
		return err
	}
	for i, names := range serviceNames {
		for _, name := range names {
			d.ServiceGroups[i].Members = append(d.ServiceGroups[i].Members, p.serviceRef(name))
		}
	}
	return p.commit(s, tx, d)
}
