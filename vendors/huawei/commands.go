package huawei

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"unicode"
	"unicode/utf8"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/plan"
)

var ErrRender = errors.New("unsupported Huawei command representation")

// Renderer emits USG system-view commands. Native policy moves preserve the
// planner's first-match order; device save/commit belongs to the deploy adapter.
type Renderer struct{}

func quoted(v string) (string, error) {
	if v == "" || len(v) > 63 || !utf8.ValidString(v) {
		return "", ErrRender
	}
	for _, r := range v {
		if unicode.IsControl(r) || r == '"' || r == '\\' {
			return "", ErrRender
		}
	}
	return "\"" + v + "\"", nil
}
func nativeRange(r flow.Range) (string, error) {
	if !r.Valid() || !r.First.Is4() {
		return "", ErrRender
	}
	for bits := 32; bits >= 0; bits-- {
		p := netip.PrefixFrom(r.First, bits)
		rr, _ := flow.PrefixRange(p)
		if p == p.Masked() && rr == r {
			return fmt.Sprintf("%s mask %d", r.First, bits), nil
		}
	}
	return fmt.Sprintf("range %s %s", r.First, r.Last), nil
}
func nativeService(t fm.ServiceTerm) (string, error) {
	if t.Protocol.Low != t.Protocol.High || t.Protocol.Low == 0 || t.ICMPType != (flow.Interval{High: 255}) || t.ICMPCode != (flow.Interval{High: 255}) {
		return "", ErrRender
	}
	proto := strconv.Itoa(int(t.Protocol.Low))
	switch t.Protocol.Low {
	case 6:
		proto = "tcp"
	case 17:
		proto = "udp"
	case 132:
		proto = "sctp"
	}
	line := "protocol " + proto
	if t.Protocol.Low == 6 || t.Protocol.Low == 17 || t.Protocol.Low == 132 {
		line += " source-port " + portText(t.SourcePort) + " destination-port " + portText(t.DestinationPort)
	} else if t.SourcePort != (flow.Interval{High: 65535}) || t.DestinationPort != (flow.Interval{High: 65535}) {
		return "", ErrRender
	}
	return line, nil
}
func addressText(fw *fm.Firewall, ref fm.AddressRef) (string, error) {
	var o fm.Object
	if ref.Kind == fm.AddressObject && fw.Address(ref.ID) != nil {
		r := fw.Address(ref.ID).Record()
		o = r.Object
		if o.Scope == "literal" && len(r.Ranges) == 1 && len(o.Unsupported) == 0 {
			return nativeRange(r.Ranges[0])
		}
	}
	if ref.Kind == fm.AddressGroupObject && fw.AddressGroup(ref.ID) != nil {
		o = fw.AddressGroup(ref.ID).Record().Object
	}
	if o.ID == "" || o.Scope != "" || o.ID != fm.ID(o.Name) {
		return "", ErrRender
	}
	name, err := quoted(o.Name)
	return "address-set " + name, err
}
func serviceText(fw *fm.Firewall, ref fm.ServiceRef) ([]string, error) {
	var o fm.Object
	if ref.Kind == fm.ServiceObject && fw.Service(ref.ID) != nil {
		r := fw.Service(ref.ID).Record()
		o = r.Object
		if o.Scope == "literal" && len(o.Unsupported) == 0 && len(r.Terms) > 0 {
			var lines []string
			for _, t := range r.Terms {
				v, err := nativeService(t)
				if err != nil {
					return nil, err
				}
				lines = append(lines, v)
			}
			return lines, nil
		}
	}
	if ref.Kind == fm.ServiceGroupObject && fw.ServiceGroup(ref.ID) != nil {
		o = fw.ServiceGroup(ref.ID).Record().Object
	}
	if o.ID == "" || o.Scope != "" || o.ID != fm.ID(o.Name) {
		return nil, ErrRender
	}
	name, err := quoted(o.Name)
	return []string{name}, err
}
func (Renderer) Render(ctx context.Context, before, after *fm.Firewall, changes []plan.Change) ([]string, error) {
	if before == nil || after == nil || !before.Complete() || !after.Complete() || before.Metadata().Vendor != "huawei" || after.Metadata().Vendor != "huawei" {
		return nil, ErrRender
	}
	commands := []string{"system-view"}
	for _, a := range after.Addresses() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		r := a.Record()
		if before.Address(r.ID) != nil {
			continue
		}
		name, err := quoted(r.Name)
		if err != nil || r.Scope != "" || r.ID != fm.ID(r.Name) || r.FQDN != "" || len(r.Unsupported) > 0 || len(r.Ranges) == 0 {
			return nil, ErrRender
		}
		commands = append(commands, "ip address-set "+name+" type object")
		for i, rr := range r.Ranges {
			text, err := nativeRange(rr)
			if err != nil {
				return nil, err
			}
			commands = append(commands, fmt.Sprintf("address %d %s", i, text))
		}
		commands = append(commands, "quit")
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
		commands = append(commands, "ip service-set "+name+" type object")
		for i, t := range r.Terms {
			text, err := nativeService(t)
			if err != nil {
				return nil, err
			}
			commands = append(commands, fmt.Sprintf("service %d %s", i, text))
		}
		commands = append(commands, "quit")
	}
	ordered := slices.Clone(changes)
	for _, c := range ordered {
		if c.Kind != plan.RemoveRule && after.Rule(c.Rule) == nil {
			return nil, ErrRender
		}
	}
	var creates []plan.Change
	for _, c := range ordered {
		if c.Kind == plan.CreateRule {
			creates = append(creates, c)
		}
	}
	slices.SortStableFunc(creates, func(a, b plan.Change) int {
		return after.Rule(a.Rule).Record().Position - after.Rule(b.Rule).Record().Position
	})
	next := 0
	for i, c := range ordered {
		if c.Kind == plan.CreateRule {
			ordered[i] = creates[next]
			next++
		}
	}
	first := fm.ID("")
	position := int(^uint(0) >> 1)
	for _, r := range before.Rules() {
		v := r.Record()
		if !v.Builtin && v.Position < position && after.Rule(v.ID) != nil {
			first, position = v.ID, v.Position
		}
	}
	var created []string
	for _, c := range ordered {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if c.Kind == plan.RemoveRule {
			r := before.Rule(c.Rule)
			if r == nil || r.Builtin() || r.Scope() != "" || after.Rule(c.Rule) != nil {
				return nil, ErrRender
			}
			name, err := quoted(r.Name())
			if err != nil {
				return nil, err
			}
			commands = append(commands, "security-policy", "undo rule name "+name, "quit")
			continue
		}
		r := after.Rule(c.Rule).Record()
		m := r.Match
		name, err := quoted(r.Name)
		if err != nil || r.Scope != "" || r.ID != fm.ID(r.Name) || r.RuleSet != "security" || r.Disabled || r.Builtin || len(r.Unsupported) > 0 || len(m.Unsupported) > 0 || m.Schedule != "" || len(m.Applications) > 0 || len(m.Users) > 0 || m.ZoneRelation != fm.AnyZoneRelation {
			return nil, ErrRender
		}
		commands = append(commands, "security-policy", "rule name "+name)
		sources, destinations, services := c.Sources, c.Destinations, c.Services
		switch c.Kind {
		case plan.CreateRule:
			if before.Rule(c.Rule) != nil || r.Description != "" {
				return nil, ErrRender
			}
			created = append(created, name)
			sources, destinations, services = m.Sources, m.Destinations, m.Services
			for _, pair := range []struct {
				key   string
				zones []fm.ID
				any   bool
			}{{"source-zone", m.FromZones, m.AnyFromZone}, {"destination-zone", m.ToZones, m.AnyToZone}} {
				if pair.any {
					commands = append(commands, pair.key+" any")
					continue
				}
				if len(pair.zones) == 0 {
					return nil, ErrRender
				}
				for _, id := range pair.zones {
					if after.Zone(id) == nil {
						return nil, ErrRender
					}
					v, err := quoted(string(id))
					if err != nil {
						return nil, err
					}
					commands = append(commands, pair.key+" "+v)
				}
			}
			for _, pair := range []struct {
				key string
				any bool
			}{{"source-address", m.AnySource}, {"destination-address", m.AnyDestination}, {"service", m.AnyService}} {
				if pair.any {
					commands = append(commands, pair.key+" any")
				}
			}
			if (!m.AnySource && len(sources) == 0) || (!m.AnyDestination && len(destinations) == 0) || (!m.AnyService && len(services) == 0) {
				return nil, ErrRender
			}
		case plan.AppendMembers:
			if before.Rule(c.Rule) == nil {
				return nil, ErrRender
			}
		default:
			return nil, ErrRender
		}
		for _, pair := range []struct {
			key  string
			refs []fm.AddressRef
		}{{"source-address", sources}, {"destination-address", destinations}} {
			for _, ref := range pair.refs {
				v, err := addressText(after, ref)
				if err != nil {
					return nil, err
				}
				commands = append(commands, pair.key+" "+v)
			}
		}
		for _, ref := range services {
			values, err := serviceText(after, ref)
			if err != nil {
				return nil, err
			}
			for _, v := range values {
				commands = append(commands, "service "+v)
			}
		}
		if c.Kind == plan.CreateRule {
			action := map[fm.Action]string{fm.Permit: "permit", fm.Deny: "deny"}[r.Action]
			if action == "" || r.LogStart != fm.Irrelevant || r.Log != r.LogEnd || (r.Log != fm.Known && r.Log != fm.Irrelevant) {
				return nil, ErrRender
			}
			commands = append(commands, "action "+action)
			if r.Log == fm.Known {
				commands = append(commands, "policy logging")
			}
		}
		commands = append(commands, "quit", "quit")
	}
	if first != "" && len(created) > 0 {
		target, err := quoted(before.Rule(first).Name())
		if err != nil {
			return nil, err
		}
		commands = append(commands, "security-policy")
		for _, name := range created {
			commands = append(commands, "rule move "+name+" before "+target)
		}
		commands = append(commands, "quit")
	}
	if len(commands) == 1 || len(changes) == 0 {
		return nil, ErrRender
	}
	return append(commands, "return"), nil
}
