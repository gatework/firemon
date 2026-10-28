package fortinet

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/plan"
)

var ErrRender = errors.New("unsupported FortiOS command representation")

// Renderer emits commands within Metadata.Context. A deployment session must
// establish that VDOM before executing them; Fortinet online sessions are not
// enabled by the optional connector adapter yet.
type Renderer struct{}

func quoted(value string) (string, error) {
	if value == "" || len(value) > 79 || !utf8.ValidString(value) {
		return "", ErrRender
	}
	for _, r := range value {
		if unicode.IsControl(r) || r == '"' || r == '\\' {
			return "", ErrRender
		}
	}
	return "\"" + value + "\"", nil
}
func label(o fm.Object) string {
	if o.Name != "" {
		return o.Name
	}
	return string(o.ID)
}
func portText(p flow.Interval) string { return fmt.Sprintf("%d-%d", p.Low, p.High) }
func prefixRange(r flow.Range) (netip.Prefix, bool) {
	if !r.First.Is4() || !r.Last.Is4() {
		return netip.Prefix{}, false
	}
	for bits := 32; bits >= 0; bits-- {
		p := netip.PrefixFrom(r.First, bits)
		rr, _ := flow.PrefixRange(p)
		if p == p.Masked() && rr == r {
			return p, true
		}
	}
	return netip.Prefix{}, false
}
func mask(bits int) string {
	var v [4]byte
	for i := 0; i < bits; i++ {
		v[i/8] |= 1 << uint(7-i%8)
	}
	return netip.AddrFrom4(v).String()
}
func nativePolicyID(id fm.ID) bool {
	n, e := strconv.ParseUint(string(id), 10, 32)
	return e == nil && n > 0 && n < 1<<32-1 && strconv.FormatUint(n, 10) == string(id)
}
func addressName(fw *fm.Firewall, ref fm.AddressRef) (string, error) {
	if ref.Kind == fm.AddressObject && ref.ID == "$all-ipv4" {
		if fw.Address("all") != nil || fw.AddressGroup("all") != nil {
			return "", ErrRender
		}
		return "\"all\"", nil
	}
	var o fm.Object
	if ref.Kind == fm.AddressObject {
		if a := fw.Address(ref.ID); a != nil {
			o = a.Record().Object
		}
	}
	if ref.Kind == fm.AddressGroupObject {
		if a := fw.AddressGroup(ref.ID); a != nil {
			o = a.Record().Object
		}
	}
	if o.ID == "" || o.Scope != "" || o.ID != fm.ID(label(o)) {
		return "", ErrRender
	}
	return quoted(label(o))
}
func serviceName(fw *fm.Firewall, ref fm.ServiceRef) (string, error) {
	if ref.Kind == fm.ServiceObject && ref.ID == "$ALL" {
		if fw.Service("ALL") != nil || fw.ServiceGroup("ALL") != nil {
			return "", ErrRender
		}
		return "\"ALL\"", nil
	}
	var o fm.Object
	if ref.Kind == fm.ServiceObject {
		if s := fw.Service(ref.ID); s != nil {
			o = s.Record().Object
		}
	}
	if ref.Kind == fm.ServiceGroupObject {
		if s := fw.ServiceGroup(ref.ID); s != nil {
			o = s.Record().Object
		}
	}
	if o.ID == "" || o.Scope != "" || o.ID != fm.ID(label(o)) {
		return "", ErrRender
	}
	return quoted(label(o))
}
func natOwner(fw *fm.Firewall, id fm.ID) bool {
	return slices.ContainsFunc(fw.DynamicNATs(), func(n *fm.DynamicNAT) bool { return n.Record().Rule == id })
}

func (Renderer) Render(ctx context.Context, before, after *fm.Firewall, changes []plan.Change) ([]string, error) {
	if before == nil || after == nil || !before.Complete() || !after.Complete() || before.Metadata().Vendor != "fortinet" || after.Metadata().Vendor != "fortinet" || before.Metadata().Context == "" || before.Metadata().Context != after.Metadata().Context {
		return nil, ErrRender
	}
	var commands []string
	block := func(section, name string, fields []string) {
		commands = append(commands, "config "+section, "edit "+name)
		commands = append(commands, fields...)
		commands = append(commands, "next", "end")
	}
	for _, address := range after.Addresses() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		r := address.Record()
		if before.Address(r.ID) != nil {
			continue
		}
		name, err := quoted(r.Name)
		if err != nil || r.Scope != "" || r.ID != fm.ID(r.Name) || len(r.Unsupported) > 0 || r.FQDN != "" || len(r.Ranges) != 1 || !r.Ranges[0].First.Is4() {
			return nil, ErrRender
		}
		fields := []string{"set type iprange", "set start-ip " + r.Ranges[0].First.String(), "set end-ip " + r.Ranges[0].Last.String()}
		if p, ok := prefixRange(r.Ranges[0]); ok {
			fields = []string{"set subnet " + p.Addr().String() + " " + mask(p.Bits())}
		}
		block("firewall address", name, fields)
	}
	for _, service := range after.Services() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		r := service.Record()
		if before.Service(r.ID) != nil {
			continue
		}
		name, err := quoted(r.Name)
		if err != nil || r.Scope != "" || r.ID != fm.ID(r.Name) || len(r.Unsupported) > 0 || len(r.Terms) == 0 {
			return nil, ErrRender
		}
		fields, err := renderService(r.Terms)
		if err != nil {
			return nil, err
		}
		block("firewall service custom", name, fields)
	}
	used := make(map[fm.ID]bool)
	first := fm.ID("")
	position := int(^uint(0) >> 1)
	for _, rule := range before.Rules() {
		r := rule.Record()
		used[r.ID] = true
		if !r.Builtin && r.Position < position && after.Rule(r.ID) != nil {
			first, position = r.ID, r.Position
		}
	}
	allocated := make(map[fm.ID]fm.ID)
	next := uint64(1)
	ordered := slices.Clone(changes)
	var created []plan.Change
	for _, c := range ordered {
		if c.Kind == plan.CreateRule && (after.Rule(c.Rule) == nil || before.Rule(c.Rule) != nil) {
			return nil, ErrRender
		}
		if c.Kind == plan.CreateRule {
			created = append(created, c)
		}
	}
	slices.SortStableFunc(created, func(a, b plan.Change) int {
		return after.Rule(a.Rule).Record().Position - after.Rule(b.Rule).Record().Position
	})
	index := 0
	for i, c := range ordered {
		if c.Kind == plan.CreateRule {
			ordered[i] = created[index]
			index++
		}
	}
	for _, c := range ordered {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if natOwner(before, c.Rule) || natOwner(after, c.Rule) {
			return nil, ErrRender
		}
		if c.Kind == plan.RemoveRule {
			old := before.Rule(c.Rule)
			if old == nil || old.Record().Builtin || !nativePolicyID(c.Rule) || after.Rule(c.Rule) != nil {
				return nil, ErrRender
			}
			commands = append(commands, "config firewall policy", "delete "+string(c.Rule), "end")
			continue
		}
		rule := after.Rule(c.Rule)
		if rule == nil {
			return nil, ErrRender
		}
		r := rule.Record()
		m := r.Match
		if r.Scope != before.Metadata().Context || r.RuleSet != "security" || r.Builtin || r.Disabled || len(r.Unsupported) > 0 || len(m.Unsupported) > 0 || len(m.Users) > 0 || len(m.Applications) > 0 || m.Schedule != "" || m.ZoneRelation != fm.AnyZoneRelation || m.AnySource || m.AnyDestination {
			return nil, ErrRender
		}
		var source, destination, service []string
		for _, pair := range []struct {
			refs []fm.AddressRef
			out  *[]string
		}{{m.Sources, &source}, {m.Destinations, &destination}} {
			for _, ref := range pair.refs {
				name, err := addressName(after, ref)
				if err != nil {
					return nil, err
				}
				*pair.out = append(*pair.out, name)
			}
		}
		for _, ref := range m.Services {
			name, err := serviceName(after, ref)
			if err != nil {
				return nil, err
			}
			service = append(service, name)
		}
		if m.AnyService {
			service = []string{"\"ALL\""}
		}
		if len(source) == 0 || len(destination) == 0 || len(service) == 0 {
			return nil, ErrRender
		}
		fields := []string{"set srcaddr " + strings.Join(source, " "), "set dstaddr " + strings.Join(destination, " "), "set service " + strings.Join(service, " ")}
		id := c.Rule
		switch c.Kind {
		case plan.CreateRule:
			if before.Rule(c.Rule) != nil {
				return nil, ErrRender
			}
			for next < 1<<32-1 && used[fm.ID(strconv.FormatUint(next, 10))] {
				next++
			}
			if next >= 1<<32-1 {
				return nil, ErrRender
			}
			id = fm.ID(strconv.FormatUint(next, 10))
			used[id] = true
			allocated[c.Rule] = id
			next++
			for _, pair := range []struct {
				key   string
				zones []fm.ID
				any   bool
			}{{"srcintf", m.FromZones, m.AnyFromZone}, {"dstintf", m.ToZones, m.AnyToZone}} {
				var names []string
				if pair.any {
					names = []string{"\"any\""}
				} else {
					for _, zone := range pair.zones {
						if after.Zone(zone) == nil {
							return nil, ErrRender
						}
						name, err := quoted(string(zone))
						if err != nil {
							return nil, err
						}
						names = append(names, name)
					}
				}
				if len(names) == 0 {
					return nil, ErrRender
				}
				fields = append(fields, "set "+pair.key+" "+strings.Join(names, " "))
			}
			if r.Action != fm.Permit || r.Description != "" || r.Log != fm.Irrelevant || r.LogStart != fm.Irrelevant || r.LogEnd != fm.Irrelevant {
				return nil, ErrRender
			}
			name, err := quoted(r.Name)
			if err != nil {
				return nil, err
			}
			fields = append(fields, "set name "+name, "set action accept", "set schedule \"always\"", "set logtraffic disable")
		case plan.AppendMembers:
			if before.Rule(c.Rule) == nil || !nativePolicyID(c.Rule) {
				return nil, ErrRender
			}
		default:
			return nil, ErrRender
		}
		block("firewall policy", string(id), fields)
	}
	if first != "" {
		var moves []string
		for _, c := range ordered {
			if id := allocated[c.Rule]; id != "" {
				moves = append(moves, "move "+string(id)+" before "+string(first))
			}
		}
		if len(moves) > 0 {
			commands = append(commands, "config firewall policy")
			commands = append(commands, moves...)
			commands = append(commands, "end")
		}
	}
	if len(commands) == 0 {
		return nil, ErrRender
	}
	return commands, nil
}

func renderService(terms []fm.ServiceTerm) ([]string, error) {
	paired := make(map[uint16][]string)
	for _, term := range terms {
		if term.Protocol.Low != term.Protocol.High {
			return nil, ErrRender
		}
		proto := term.Protocol.Low
		if proto == 6 || proto == 17 || proto == 132 {
			if term.ICMPType != (flow.Interval{High: 255}) || term.ICMPCode != (flow.Interval{High: 255}) {
				return nil, ErrRender
			}
			paired[proto] = append(paired[proto], portText(term.DestinationPort)+":"+portText(term.SourcePort))
			continue
		}
		if len(terms) != 1 || term.SourcePort != (flow.Interval{High: 65535}) || term.DestinationPort != (flow.Interval{High: 65535}) {
			return nil, ErrRender
		}
		if proto == 1 || proto == 58 {
			protocol := "ICMP"
			if proto == 58 {
				protocol = "ICMP6"
			}
			out := []string{"set protocol " + protocol}
			for _, pair := range []struct {
				key   string
				value flow.Interval
			}{{"icmptype", term.ICMPType}, {"icmpcode", term.ICMPCode}} {
				if pair.value == (flow.Interval{High: 255}) {
					continue
				}
				if pair.value.Low != pair.value.High {
					return nil, ErrRender
				}
				out = append(out, fmt.Sprintf("set %s %d", pair.key, pair.value.Low))
			}
			return out, nil
		}
		if proto == 0 || proto > 254 || term.ICMPType != (flow.Interval{High: 255}) || term.ICMPCode != (flow.Interval{High: 255}) {
			return nil, ErrRender
		}
		return []string{"set protocol IP", fmt.Sprintf("set protocol-number %d", proto)}, nil
	}
	var out []string
	for _, pair := range []struct {
		key   string
		proto uint16
	}{{"tcp-portrange", 6}, {"udp-portrange", 17}, {"sctp-portrange", 132}} {
		if values := paired[pair.proto]; len(values) > 0 {
			out = append(out, "set "+pair.key+" "+strings.Join(values, " "))
		}
	}
	return out, nil
}
