package netscreen

import (
	"context"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/policy"
)

func natFields(w []string) (policyNAT, bool) {
	n := policyNAT{}
	if len(w) == 0 || w[0] != "nat" {
		return n, false
	}
	w = w[1:]
	if len(w) > 0 && w[0] == "src" {
		n.source = true
		w = w[1:]
		if len(w) > 0 && w[0] == "dip-id" {
			if len(w) < 2 {
				return n, false
			}
			if _, e := strconv.ParseUint(w[1], 10, 32); e != nil {
				return n, false
			}
			n.pool = w[1]
			w = w[2:]
		}
	}
	if len(w) > 0 && w[0] == "dst" {
		if len(w) < 3 || w[1] != "ip" {
			return n, false
		}
		a, e := netip.ParseAddr(w[2])
		if e != nil || !a.Is4() {
			return n, false
		}
		n.destination = a.String()
		w = w[3:]
		if len(w) > 0 && w[0] == "port" {
			if len(w) < 2 {
				return n, false
			}
			v, e := strconv.ParseUint(w[1], 10, 16)
			if e != nil || v == 0 {
				return n, false
			}
			n.port = w[1]
			w = w[2:]
		}
	}
	return n, len(w) == 0 && (n.source || n.destination != "")
}

func uniqueInterface(fw *fm.Firewall, zone fm.ID) *fm.Interface {
	var out *fm.Interface
	for _, i := range fw.Interfaces() {
		r := i.Record()
		if r.Zone != zone || r.Disabled {
			continue
		}
		if out != nil || len(r.Unsupported) > 0 {
			return nil
		}
		out = i
	}
	return out
}
func routeInterface(ctx context.Context, fw *fm.Firewall, vrf string, addresses flow.Set) *fm.Interface {
	paths, err := policy.Routes(ctx, fw, vrf, addresses, 4096)
	if err != nil || len(paths) == 0 {
		return nil
	}
	var out *fm.Interface
	for _, p := range paths {
		if !p.Known || out != nil && out != p.Interface {
			return nil
		}
		out = p.Interface
	}
	return out
}
func (p *parser) nativeAddress(d *fm.Data, name string, r flow.Range, span fm.Span) fm.AddressRef {
	id := fm.ID(name)
	ref := fm.AddressRef{Kind: fm.AddressObject, ID: id}
	if old, ok := p.addresses[id]; ok {
		matches := false
		for _, a := range append(slices.Clone(p.data.Addresses), d.Addresses...) {
			if a.ID == id && old.Kind == fm.AddressObject && len(a.Ranges) == 1 && a.Ranges[0] == r && len(a.Unsupported) == 0 {
				matches = true
			}
		}
		if !matches {
			d.Diagnostics = append(d.Diagnostics, invalid("", "mapped address conflicts with an existing native object"))
		}
		return old
	}
	d.Addresses = append(d.Addresses, fm.AddressRecord{Object: fm.Object{ID: id, Name: name, Spans: []fm.Span{span}}, Ranges: []flow.Range{r}})
	p.addresses[id] = ref
	return ref
}

func (p *parser) interfaceNAT(ctx context.Context, s *config.Session) error {
	tx := s.Cursor.Begin()
	defer tx.Rollback()
	d := fm.Data{}
	fw, err := fm.Seal(p.data)
	if err != nil {
		return err
	}
	seen := make(map[fm.ID]bool)
	for _, row := range p.rows {
		if err := ctx.Err(); err != nil {
			return err
		}
		w := row.Words
		if row.scope != "root" || len(w) < 6 || !begins(w, "set", "interface") {
			continue
		}
		iface := fw.Interface(fm.ID(w[2]))
		if iface == nil || iface.Zone() == nil {
			continue
		}
		ir := iface.Record()
		if ir.Disabled || len(ir.Unsupported) > 0 {
			continue
		}
		rest := w[4:]
		base := fm.Match{AnySource: true, AnyService: true, FromZones: []fm.ID{ir.Zone}}
		switch w[3] {
		case "dip":
			if len(rest) != 3 && !(len(rest) == 4 && rest[3] == "fix-port") {
				continue
			}
			if _, e := strconv.ParseUint(rest[0], 10, 32); e != nil {
				continue
			}
			first, e1 := netip.ParseAddr(rest[1])
			last, e2 := netip.ParseAddr(rest[2])
			if e1 != nil || e2 != nil || !first.Is4() || !last.Is4() || first.Compare(last) > 0 {
				continue
			}
			id := nativeID("dip", w[2], rest[0])
			if seen[id] {
				d.Diagnostics = append(d.Diagnostics, invalid("", "duplicate DIP identifier"))
				continue
			}
			seen[id] = true
			pool := fm.NATPoolRecord{Object: object(id, rest[0], ""), Interface: ir.ID, Ranges: []flow.Range{{First: first, Last: last}}}
			if len(rest) == 3 {
				pool.Ports = flow.Interval{Low: 1024, High: 65535}
			}
			touch(&pool.Object, row)
			d.NATPools = append(d.NATPools, pool)
			tx.Parse(row.Lines()...)
		case "mip":
			id := nativeID("mip", w[2], rest[0])
			if seen[id] {
				d.Diagnostics = append(d.Diagnostics, invalid("", "duplicate MIP"))
				continue
			}
			seen[id] = true
			if len(rest) < 3 || rest[1] != "host" {
				continue
			}
			fields := make(map[string]string)
			valid := true
			for words := rest[3:]; len(words) > 0; words = words[2:] {
				if len(words) < 2 {
					valid = false
					break
				}
				key := words[0]
				if key == "vr" {
					key = "vrouter"
				}
				if key != "netmask" && key != "vrouter" || fields[key] != "" {
					valid = false
					break
				}
				fields[key] = words[1]
			}
			if !valid {
				continue
			}
			mask := fields["netmask"]
			if mask == "" {
				mask = "255.255.255.255"
			}
			mapped, _, ok1 := prefix([]string{rest[0], mask})
			real, _, ok2 := prefix([]string{rest[2], mask})
			if !ok1 || !ok2 || mapped != mapped.Masked() || real != real.Masked() {
				continue
			}
			original, _ := flow.PrefixRange(mapped)
			target, _ := flow.PrefixRange(real)
			set, _ := flow.NewSet(target)
			vr := fields["vrouter"]
			if vr == "" {
				vr = "trust-vr"
			}
			targetInterface := routeInterface(ctx, fw, vr, set)
			n := fm.StaticNATRecord{Object: object(id, rest[0], ""), Match: base, Order: fm.NATOrder{Stage: 0, Position: len(d.StaticNATs) + len(d.DynamicNATs), Section: "mip"}, Bidirectional: true, Interface: ir.ID, Destination: []fm.Mapping{{Original: original, Translated: target, Mode: fm.Offset}}}
			if targetInterface == nil {
				n.Unsupported = append(n.Unsupported, "MIP target has no unique routed zone")
			} else {
				n.Match.ToZones = []fm.ID{targetInterface.Record().Zone}
			}
			if uniqueInterface(fw, ir.Zone) != iface {
				n.Unsupported = append(n.Unsupported, "MIP ingress interface is ambiguous within its zone")
			}
			name := "MIP(" + mapped.Addr().String()
			if mapped.Bits() != 32 {
				name += "/" + strconv.Itoa(mapped.Bits())
			}
			name += ")"
			n.Match.Destinations = []fm.AddressRef{p.nativeAddress(&d, name, original, row.Span)}
			touch(&n.Object, row)
			d.StaticNATs = append(d.StaticNATs, n)
			tx.Parse(row.Lines()...)
		case "vip":
			if len(rest) > 1 && rest[1] == "+" {
				rest = append(slices.Clone(rest[:1]), rest[2:]...)
			}
			if len(rest) != 4 && !(len(rest) == 5 && rest[4] == "manual") {
				continue
			}
			mapped, e1 := netip.ParseAddr(rest[0])
			real, e2 := netip.ParseAddr(rest[3])
			port, e3 := strconv.ParseUint(rest[1], 10, 16)
			if e1 != nil || e2 != nil || e3 != nil || port == 0 || !mapped.Is4() || !real.Is4() {
				continue
			}
			id := nativeID("vip", w[2], rest[0], rest[1])
			if seen[id] {
				d.Diagnostics = append(d.Diagnostics, invalid("", "duplicate VIP"))
				continue
			}
			seen[id] = true
			original, target := flow.Range{First: mapped, Last: mapped}, flow.Range{First: real, Last: real}
			set, _ := flow.NewSet(target)
			targetInterface := routeInterface(ctx, fw, ir.Scope, set)
			n := fm.DynamicNATRecord{Object: object(id, rest[0], ""), Match: base, Order: fm.NATOrder{Stage: 0, Position: len(d.StaticNATs) + len(d.DynamicNATs), Section: "vip"}, SourceMode: fm.NoTranslation, DestinationMode: fm.StaticIP, Destination: []fm.Mapping{{Original: original, Translated: target, Mode: fm.Constant}}}
			n.Match.Destinations = []fm.AddressRef{p.nativeAddress(&d, "VIP("+mapped.String()+")", original, row.Span)}
			if targetInterface == nil {
				n.Unsupported = append(n.Unsupported, "VIP target has no unique routed zone")
			} else {
				n.Match.ToZones = []fm.ID{targetInterface.Record().Zone}
			}
			if uniqueInterface(fw, ir.Zone) != iface {
				n.Unsupported = append(n.Unsupported, "VIP ingress interface is ambiguous within its zone")
			}
			terms, known, err := (policy.Engine{}).ResolveServices(ctx, fw, []fm.ServiceRef{p.serviceRef(rest[2])}, false)
			if err != nil {
				return err
			}
			if !known || len(terms) != 1 || terms[0].Protocol.Low != terms[0].Protocol.High || terms[0].Protocol.Low != 6 && terms[0].Protocol.Low != 17 || terms[0].DestinationPort.Low != terms[0].DestinationPort.High || terms[0].SourcePort != (flow.Interval{High: 65535}) {
				n.Unsupported = append(n.Unsupported, "VIP requires a single TCP/UDP service port")
			} else {
				term := terms[0]
				inside := term.DestinationPort
				outside := flow.Interval{Low: uint16(port), High: uint16(port)}
				term.DestinationPort = outside
				serviceID := nativeID("vip-service", string(id))
				d.Services = append(d.Services, fm.ServiceRecord{Object: object(serviceID, rest[2], "nat:"+string(id)), Terms: []fm.ServiceTerm{term}})
				n.Match.AnyService = false
				n.Match.Services = []fm.ServiceRef{{Kind: fm.ServiceObject, ID: serviceID}}
				n.DestinationPorts = []fm.PortMapping{{Original: outside, Translated: inside, Mode: fm.Constant}}
			}
			touch(&n.Object, row)
			d.DynamicNATs = append(d.DynamicNATs, n)
			tx.Parse(row.Lines()...)
		}
	}
	return p.commit(s, tx, d)
}

func (p *parser) embeddedNAT(ctx context.Context, s *config.Session) error {
	tx := s.Cursor.Begin()
	defer tx.Rollback()
	d := fm.Data{}
	fw, err := fm.Seal(p.data)
	if err != nil {
		return err
	}
	for _, name := range p.rules.names {
		if err := ctx.Err(); err != nil {
			return err
		}
		r := p.rules.entries[name]
		fields, ok := p.policyNAT[r.ID]
		if !ok {
			continue
		}
		id := nativeID("policy", name)
		n := fm.DynamicNATRecord{Object: object(id, name, r.Scope), Rule: r.ID, Match: r.Match, Order: fm.NATOrder{Stage: 1, Position: len(d.DynamicNATs), Section: "policy"}, SourceMode: fm.NoTranslation, DestinationMode: fm.NoTranslation, Disabled: r.Disabled}
		n.Spans = slices.Clone(r.Spans)
		n.Unsupported = slices.Clone(r.Unsupported)
		if fields.destination != "" {
			target := netip.MustParseAddr(fields.destination)
			destinations, known, err := (policy.Engine{}).ResolveAddresses(ctx, fw, r.Match.Destinations, r.Match.AnyDestination)
			if err != nil {
				return err
			}
			if !known || destinations.Empty() || slices.ContainsFunc(r.Match.Destinations, func(ref fm.AddressRef) bool { return ref.ID == "$any-ipv4" }) {
				n.Unsupported = append(n.Unsupported, "policy destination NAT requires explicit resolved addresses")
			} else {
				for _, v := range destinations.Ranges() {
					n.Destination = append(n.Destination, fm.Mapping{Original: v, Translated: flow.Range{First: target, Last: target}, Mode: fm.Constant})
				}
			}
			n.DestinationMode = fm.StaticIP
			if fields.port != "" {
				terms, known, err := (policy.Engine{}).ResolveServices(ctx, fw, r.Match.Services, r.Match.AnyService)
				if err != nil {
					return err
				}
				if !known || len(terms) == 0 || slices.ContainsFunc(terms, func(term fm.ServiceTerm) bool {
					return term.Protocol.Low != term.Protocol.High || term.Protocol.Low != 6 && term.Protocol.Low != 17
				}) {
					n.Unsupported = append(n.Unsupported, "destination port translation requires resolved transport services")
				} else {
					port, _ := strconv.ParseUint(fields.port, 10, 16)
					n.DestinationPorts = []fm.PortMapping{{Original: flow.Interval{High: 65535}, Translated: flow.Interval{Low: uint16(port), High: uint16(port)}, Mode: fm.Constant}}
				}
			}
		}
		if fields.source {
			if fields.pool != "" {
				var pool *fm.NATPool
				for _, v := range fw.NATPools() {
					iface := v.Interface()
					if v.Record().Name != fields.pool || iface == nil || !slices.Contains(r.Match.ToZones, iface.Record().Zone) {
						continue
					}
					if pool != nil {
						pool = nil
						break
					}
					pool = v
				}
				if pool == nil {
					n.Unsupported = append(n.Unsupported, "DIP is missing or ambiguous in the destination zone")
					n.SourceMode = fm.UnknownTranslation
				} else {
					n.SourcePool = pool.Record().ID
					if uniqueInterface(fw, r.Match.ToZones[0]) != pool.Interface() {
						n.Unsupported = append(n.Unsupported, "DIP egress interface is ambiguous within its zone")
					}
					n.SourceMode = fm.DynamicIP
					if pool.Record().Ports != (flow.Interval{}) {
						n.SourceMode = fm.DynamicIPPort
					}
				}
			} else {
				iface := uniqueInterface(fw, r.Match.ToZones[0])
				n.SourceMode = fm.InterfaceIP
				if iface == nil || len(iface.Record().Addresses) != 1 {
					n.Unsupported = append(n.Unsupported, "interface NAT requires a unique addressed egress")
				} else {
					n.Interface = iface.Record().ID
				}
			}
		}
		d.DynamicNATs = append(d.DynamicNATs, n)
	}
	return p.commit(s, tx, d)
}

func mappedName(value string) string {
	if strings.HasPrefix(strings.ToLower(value), "mip(") || strings.HasPrefix(strings.ToLower(value), "vip(") {
		return strings.ToUpper(value[:3]) + value[3:]
	}
	return value
}
