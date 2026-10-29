package srx

import (
	"context"
	"net/netip"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/flow"
)

// Native rule-set context is selected before its ordered rules. It is not a
// generic NAT rule: drafts are sealed into separate StaticNAT/DynamicNAT tables.
type natContext struct {
	from, to    string
	disabled    bool
	rules       catalog[natDraft]
	unsupported []string
}
type natDraft struct {
	object                          fm.Object
	source, destination             []flow.AddressRange
	sourcePorts, destinationPorts   []flow.Interval
	protocol                        uint16
	hasProtocol, hasMatch, disabled bool
	target, action                  string
	mappedPort                      *flow.Interval
}
type poolDraft struct {
	record         fm.NATPoolRecord
	noPAT, portSet bool
}

func nativePorts(w []string) (flow.Interval, bool) {
	if len(w) == 1 {
		return ports(w[0])
	}
	if len(w) == 3 && w[1] == "to" {
		return ports(w[0] + "-" + w[2])
	}
	return flow.Interval{}, false
}

func (p *parser) nat(ctx context.Context, s *config.Session) error {
	tx := s.Cursor().Begin()
	defer tx.Rollback()
	var contexts catalog[natContext]
	var pools catalog[poolDraft]
	directions := make(map[string]string)
	d := fm.Data{}
	for _, row := range p.rows {
		if err := ctx.Err(); err != nil {
			return err
		}
		w := row.Words
		if len(w) < 6 || (w[0] != "set" && w[0] != "deactivate") || !begins(w[1:], "security", "nat") {
			continue
		}
		direction := w[3]
		if direction != "static" && direction != "source" && direction != "destination" {
			continue
		}
		if w[4] == "pool" && direction != "static" && w[0] == "set" {
			id := nativeID("nat-pool", direction, w[5])
			pool := pools.get(string(id))
			r := &pool.record
			r.ID, r.Name = id, w[5]
			valid := false
			rest := w[6:]
			switch {
			case len(rest) >= 2 && rest[0] == "address" && rest[1] != "port":
				var value flow.AddressRange
				var err error
				if len(rest) == 2 {
					value, err = addressRange(rest[1])
					valid = err == nil
				}
				if len(rest) == 4 && rest[2] == "to" {
					a, e1 := netip.ParseAddr(rest[1])
					b, e2 := netip.ParseAddr(rest[3])
					value = flow.AddressRange{First: a, Last: b}
					valid = e1 == nil && e2 == nil && value.Valid()
				}
				if valid {
					r.Ranges = unique(r.Ranges, value)
				}
			case direction == "destination" && len(rest) == 3 && begins(rest, "address", "port"):
				v, ok := nativePorts(rest[2:])
				valid = ok && v.Low == v.High
				if valid {
					if pool.portSet && r.Ports != v {
						r.Unsupported = append(r.Unsupported, "conflicting pool ports")
					}
					r.Ports = v
					pool.portSet = true
				}
			case direction == "source" && begins(rest, "port"):
				if len(rest) == 2 && rest[1] == "no-translation" {
					valid = true
					if pool.portSet {
						r.Unsupported = append(r.Unsupported, "conflicting pool port modes")
					}
					pool.noPAT = true
				}
				if len(rest) > 2 && rest[1] == "range" {
					v, ok := nativePorts(rest[2:])
					valid = ok && v.Low >= 1024
					if valid {
						if pool.noPAT || pool.portSet && r.Ports != v {
							r.Unsupported = append(r.Unsupported, "conflicting pool ports")
						}
						r.Ports = v
						pool.portSet = true
					}
				}
			}
			if valid {
				touch(&r.Object, row)
				tx.Parse(row.Lines()...)
			} else {
				r.Unsupported = append(r.Unsupported, "unsupported NAT pool leaf")
			}
			continue
		}
		if w[4] != "rule-set" {
			continue
		}
		key := string(nativeID(direction, w[5]))
		group := contexts.get(key)
		directions[key] = direction
		rest := w[6:]
		valid := false
		switch {
		case w[0] == "deactivate" && len(rest) == 0:
			group.disabled = true
			valid = true
		case w[0] == "set" && len(rest) == 3 && rest[1] == "zone" && (rest[0] == "from" || rest[0] == "to" && direction == "source"):
			target := &group.from
			if rest[0] == "to" {
				target = &group.to
			}
			if *target != "" && *target != rest[2] {
				group.unsupported = append(group.unsupported, "conflicting NAT rule-set zones")
			}
			*target = rest[2]
			valid = true
		case len(rest) >= 2 && rest[0] == "rule":
			name := rest[1]
			r := group.rules.get(name)
			r.object.ID, r.object.Name = nativeID("nat", direction, w[5], name), name
			leaf := rest[2:]
			if w[0] == "deactivate" {
				if len(leaf) == 0 {
					r.disabled = true
					valid = true
				}
			} else {
				valid = parseNATLeaf(r, leaf, direction)
			}
			if valid {
				touch(&r.object, row)
			} else {
				r.object.Unsupported = append(r.object.Unsupported, "unsupported NAT rule condition")
			}
		default:
			group.unsupported = append(group.unsupported, "unsupported NAT rule-set context")
		}
		if valid {
			tx.Parse(row.Lines()...)
		}
	}
	for _, name := range pools.names {
		pool := pools.entries[name]
		if len(name) >= len("nat-pool:source/") && name[:len("nat-pool:source/")] == "nat-pool:source/" && !pool.noPAT && !pool.portSet {
			pool.record.Ports = flow.Interval{Low: 1024, High: 65535}
		}
		if len(pool.record.Ranges) == 0 {
			pool.record.Unsupported = append(pool.record.Unsupported, "empty NAT pool")
		}
		d.NATPools = append(d.NATPools, pool.record)
	}
	seen := make(map[string]bool)
	position := 0
	for _, key := range contexts.names {
		group := contexts.entries[key]
		direction := directions[key]
		if group.from == "" || direction == "source" && group.to == "" {
			group.unsupported = append(group.unsupported, "missing NAT rule-set zone")
		}
		// Two zone-only rule sets of the same type cannot have identical context.
		identity := direction + "\x00" + group.from + "\x00" + group.to
		if seen[identity] {
			d.Diagnostics = append(d.Diagnostics, diagnostic("ambiguous-nat-context", "multiple NAT rule sets share the same context"))
		}
		seen[identity] = true
		for _, name := range group.rules.names {
			r := group.rules.entries[name]
			r.object.Unsupported = append(r.object.Unsupported, group.unsupported...)
			if !r.hasMatch {
				r.object.Unsupported = append(r.object.Unsupported, "missing NAT match")
			}
			match := natMatch(r, group, &d)
			order := fm.NATOrder{Section: key, Position: position}
			position++
			switch direction {
			case "static":
				order.Stage = 0
				fixed := fm.StaticNATRecord{Object: r.object, Match: match, Order: order, Bidirectional: true, Disabled: r.disabled || group.disabled}
				target, err := addressRange(r.target)
				if err == nil && len(r.destination) == 1 && equalPrefixSize(r.destination[0], target) && r.action == "prefix" {
					fixed.Destination = []fm.Mapping{{Original: r.destination[0], Translated: target, Mode: fm.Offset}}
				} else {
					fixed.Unsupported = append(fixed.Unsupported, "static NAT requires equal-sized explicit prefixes")
				}
				if r.mappedPort != nil || len(r.destinationPorts) > 0 {
					if r.mappedPort == nil || len(r.destinationPorts) != 1 || r.destinationPorts[0].High-r.destinationPorts[0].Low != r.mappedPort.High-r.mappedPort.Low || len(r.destination) != 1 || r.destination[0].First != r.destination[0].Last || target.First != target.Last {
						fixed.Unsupported = append(fixed.Unsupported, "incomplete static port mapping")
					} else {
						fixed.DestinationPorts = []fm.PortMapping{{Original: r.destinationPorts[0], Translated: *r.mappedPort, Mode: fm.Offset}}
					}
				}
				d.StaticNATs = append(d.StaticNATs, fixed)
			default:
				order.Stage = 1
				if direction == "source" {
					order.Stage = 2
				}
				dynamic := fm.DynamicNATRecord{Object: r.object, Match: match, Order: order, SourceMode: fm.NoTranslation, DestinationMode: fm.NoTranslation, Disabled: r.disabled || group.disabled}
				if r.action == "pool" {
					poolID := nativeID("nat-pool", direction, r.target)
					pool := pools.entries[string(poolID)]
					if direction == "source" {
						dynamic.SourcePool = poolID
						dynamic.SourceMode = fm.DynamicIPPort
					} else {
						dynamic.DestinationPool = poolID
						dynamic.DestinationMode = fm.StaticIP
					}
					if pool != nil {
						dynamic.Unsupported = append(dynamic.Unsupported, pool.record.Unsupported...)
						if direction == "source" {
							if pool.noPAT {
								dynamic.SourceMode = fm.DynamicIP
							}
						} else if len(pool.record.Ranges) == 1 && pool.record.Ranges[0].First == pool.record.Ranges[0].Last {
							originals := r.destination
							if len(originals) == 0 {
								v, _ := addressRange("0.0.0.0/0")
								originals = []flow.AddressRange{v}
							}
							for _, original := range originals {
								if original.First.BitLen() != pool.record.Ranges[0].First.BitLen() {
									dynamic.Unsupported = append(dynamic.Unsupported, "cross-family destination NAT")
									continue
								}
								dynamic.Destination = append(dynamic.Destination, fm.Mapping{Original: original, Translated: pool.record.Ranges[0], Mode: fm.Constant})
							}
							if pool.portSet {
								dynamic.DestinationPorts = []fm.PortMapping{{Original: flow.Interval{High: 65535}, Translated: pool.record.Ports, Mode: fm.Constant}}
							}
						} else {
							dynamic.Unsupported = append(dynamic.Unsupported, "destination pool allocation is not an established fixed mapping")
						}
					}
				} else if r.action != "off" {
					dynamic.Unsupported = append(dynamic.Unsupported, "unsupported NAT allocation action")
					dynamic.SourceMode = fm.UnknownTranslation
				}
				d.DynamicNATs = append(d.DynamicNATs, dynamic)
			}
		}
	}
	tx.Emit(d)
	if err := s.Commit(tx); err != nil {
		return err
	}
	p.data = s.Data()
	return nil
}

func equalPrefixSize(a, b flow.AddressRange) bool {
	// Input comes from native prefixes, not arbitrary pools with equal counts.
	pa, oka := rangePrefix(a)
	pb, okb := rangePrefix(b)
	return oka && okb && pa.Addr().BitLen() == pb.Addr().BitLen() && pa.Bits() == pb.Bits()
}
func rangePrefix(r flow.AddressRange) (netip.Prefix, bool) {
	for bits := r.First.BitLen(); bits >= 0; bits-- {
		p := netip.PrefixFrom(r.First, bits).Masked()
		v, err := flow.PrefixRange(p)
		if err == nil && v == r {
			return p, true
		}
	}
	return netip.Prefix{}, false
}
func parseNATLeaf(r *natDraft, leaf []string, direction string) bool {
	if len(leaf) >= 3 && leaf[0] == "match" {
		switch leaf[1] {
		case "source-address", "destination-address":
			values, ok := list(leaf[2:])
			if !ok {
				return false
			}
			var ranges []flow.AddressRange
			for _, v := range values {
				a, err := addressRange(v)
				if err != nil {
					return false
				}
				ranges = unique(ranges, a)
			}
			for _, v := range ranges {
				if leaf[1] == "source-address" {
					r.source = unique(r.source, v)
				} else {
					r.destination = unique(r.destination, v)
				}
			}
		case "source-port", "destination-port":
			if leaf[1] == "source-port" && direction == "destination" {
				return false
			}
			v, ok := nativePorts(leaf[2:])
			if !ok {
				return false
			}
			if leaf[1] == "source-port" {
				r.sourcePorts = unique(r.sourcePorts, v)
			} else {
				r.destinationPorts = unique(r.destinationPorts, v)
			}
		case "protocol":
			if len(leaf) != 3 {
				return false
			}
			v, ok := protocol(leaf[2])
			if !ok {
				return false
			}
			if r.hasProtocol && r.protocol != v {
				r.object.Unsupported = append(r.object.Unsupported, "conflicting NAT protocols")
			}
			r.protocol, r.hasProtocol = v, true
		default:
			return false
		}
		r.hasMatch = true
		return true
	}
	if len(leaf) < 3 || leaf[0] != "then" || leaf[1] != direction+"-nat" {
		return false
	}
	if direction == "static" && len(leaf) >= 5 && begins(leaf[2:], "prefix", "mapped-port") {
		v, ok := nativePorts(leaf[4:])
		if !ok {
			return false
		}
		if r.mappedPort != nil && *r.mappedPort != v {
			r.object.Unsupported = append(r.object.Unsupported, "conflicting mapped ports")
		}
		r.mappedPort = &v
		return true
	}
	action, target := "", ""
	if len(leaf) == 4 && (leaf[2] == "pool" && direction != "static" || leaf[2] == "prefix" && direction == "static") {
		action, target = leaf[2], leaf[3]
	}
	if len(leaf) == 3 && direction != "static" && leaf[2] == "off" {
		action = "off"
	}
	if action == "" {
		return false
	}
	if r.action != "" && (r.action != action || r.target != target) {
		r.object.Unsupported = append(r.object.Unsupported, "conflicting NAT actions")
	}
	r.action, r.target = action, target
	return true
}

func natMatch(r *natDraft, group *natContext, d *fm.Data) fm.Match {
	m := fm.Match{AnySource: len(r.source) == 0, AnyDestination: len(r.destination) == 0, AnyToZone: group.to == "", FromZones: []fm.ID{fm.ID(group.from)}}
	if group.to != "" {
		m.ToZones = []fm.ID{fm.ID(group.to)}
	}
	for axis, values := range [][]flow.AddressRange{r.source, r.destination} {
		for _, v := range values {
			id := nativeID("nat-address", string(r.object.ID), string(rune('s'+axis)), v.First.String(), v.Last.String())
			d.Addresses = append(d.Addresses, fm.AddressRecord{Object: fm.Object{ID: id, Scope: "nat:" + string(r.object.ID)}, Ranges: []flow.AddressRange{v}})
			ref := fm.AddressRef{Kind: fm.AddressObject, ID: id}
			if axis == 0 {
				m.Sources = append(m.Sources, ref)
			} else {
				m.Destinations = append(m.Destinations, ref)
			}
		}
	}
	constrained := r.hasProtocol || len(r.sourcePorts) > 0 || len(r.destinationPorts) > 0
	m.AnyService = !constrained
	if constrained {
		protocols := []flow.Interval{{High: 255}}
		hasPorts := len(r.sourcePorts) > 0 || len(r.destinationPorts) > 0
		if r.hasProtocol {
			protocols = []flow.Interval{{Low: r.protocol, High: r.protocol}}
		} else if hasPorts {
			protocols = []flow.Interval{{Low: 6, High: 6}, {Low: 17, High: 17}}
		}
		if hasPorts && r.hasProtocol && r.protocol != 6 && r.protocol != 17 {
			r.object.Unsupported = append(r.object.Unsupported, "NAT ports require TCP or UDP")
		}
		src, dst := r.sourcePorts, r.destinationPorts
		if len(src) == 0 {
			src = []flow.Interval{{High: 65535}}
		}
		if len(dst) == 0 {
			dst = []flow.Interval{{High: 65535}}
		}
		service := fm.ServiceRecord{Object: fm.Object{ID: nativeID("nat-service", string(r.object.ID)), Scope: "nat:" + string(r.object.ID)}}
		if len(src) > 4096 || len(dst) > 4096 || len(src)*len(dst) > 4096/len(protocols) {
			service.Unsupported = []string{"NAT service combination limit"}
		} else {
			for _, proto := range protocols {
				for _, sp := range src {
					for _, dp := range dst {
						service.Terms = append(service.Terms, fm.ServiceTerm{Protocol: proto, SourcePort: sp, DestinationPort: dp, ICMPType: flow.Interval{High: 255}, ICMPCode: flow.Interval{High: 255}})
					}
				}
			}
		}
		d.Services = append(d.Services, service)
		m.Services = []fm.ServiceRef{{Kind: fm.ServiceObject, ID: service.ID}}
	}
	return m
}
