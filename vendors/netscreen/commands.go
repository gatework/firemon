package netscreen

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/plan"
)

var ErrRender = errors.New("unsupported ScreenOS command representation")

type Renderer struct{}

func quoted(value string) (string, error) {
	if value == "" || len(value) > 63 || !utf8.ValidString(value) {
		return "", ErrRender
	}
	for _, r := range value {
		if r < 32 || r == 127 || r == '"' || r == '\\' {
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
func addressName(fw *fm.Firewall, zone fm.ID, ref fm.AddressRef) (string, error) {
	if ref.ID == "$any-ipv4" && ref.Kind == fm.AddressObject {
		return "\"Any\"", nil
	}
	var o fm.Object
	switch ref.Kind {
	case fm.AddressObject:
		if a := fw.Address(ref.ID); a != nil {
			o = a.Record().Object
		}
	case fm.AddressGroupObject:
		if g := fw.AddressGroup(ref.ID); g != nil {
			o = g.Record().Object
		}
	}
	if o.ID == "" {
		return "", ErrRender
	}
	for _, scope := range []string{addressScope(string(zone)), ""} {
		id := addressID(scope, label(o))
		if a := fw.Address(id); a != nil {
			if ref.Kind != fm.AddressObject || ref.ID != id {
				return "", ErrRender
			}
			return quoted(label(o))
		}
		if g := fw.AddressGroup(id); g != nil {
			if ref.Kind != fm.AddressGroupObject || ref.ID != id {
				return "", ErrRender
			}
			return quoted(label(o))
		}
	}
	return "", ErrRender
}
func serviceName(fw *fm.Firewall, ref fm.ServiceRef) (string, error) {
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
func portText(v flow.Interval) string { return fmt.Sprintf("%d-%d", v.Low, v.High) }
func rangePrefix(v flow.Range) (netip.Prefix, bool) {
	if !v.First.Is4() || !v.Last.Is4() {
		return netip.Prefix{}, false
	}
	for bits := 32; bits >= 0; bits-- {
		p := netip.PrefixFrom(v.First, bits)
		if p != p.Masked() {
			continue
		}
		r, e := flow.PrefixRange(p)
		if e == nil && r == v {
			return p, true
		}
	}
	return netip.Prefix{}, false
}
func ownsNAT(fw *fm.Firewall, id fm.ID) bool {
	return slices.ContainsFunc(fw.DynamicNATs(), func(n *fm.DynamicNAT) bool { return n.Record().Rule == id })
}

// Render produces configuration commands only. Persisting configuration belongs
// to the deployment session's independently verified save operation.
func (Renderer) Render(ctx context.Context, before, after *fm.Firewall, changes []plan.Change) ([]string, error) {
	if before == nil || after == nil || before.Metadata().Vendor != "netscreen" || after.Metadata().Vendor != "netscreen" || !before.Complete() || !after.Complete() {
		return nil, ErrRender
	}
	var commands []string
	for _, address := range after.Addresses() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		a := address.Record()
		if before.Address(a.ID) != nil {
			continue
		}
		zone := "Global"
		if a.Scope != "" {
			if !strings.HasPrefix(a.Scope, "zone:") {
				return nil, ErrRender
			}
			zone = strings.TrimPrefix(a.Scope, "zone:")
		}
		if a.ID != addressID(addressScope(zone), a.Name) || len(a.Ranges) != 1 || len(a.Unsupported) > 0 || a.FQDN != "" {
			return nil, ErrRender
		}
		p, ok := rangePrefix(a.Ranges[0])
		if !ok {
			return nil, ErrRender
		}
		name, e1 := quoted(a.Name)
		z, e2 := quoted(zone)
		if e1 != nil || e2 != nil {
			return nil, ErrRender
		}
		commands = append(commands, "set address "+z+" "+name+" "+p.String())
	}
	for _, service := range after.Services() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		s := service.Record()
		if before.Service(s.ID) != nil {
			continue
		}
		name, err := quoted(s.Name)
		if err != nil || s.Scope != "" || s.ID != fm.ID(s.Name) || len(s.Terms) == 0 || len(s.Unsupported) > 0 {
			return nil, ErrRender
		}
		for i, term := range s.Terms {
			if term.Protocol.Low != term.Protocol.High || term.Protocol.High > 255 || term.ICMPType != (flow.Interval{High: 255}) || term.ICMPCode != (flow.Interval{High: 255}) {
				return nil, ErrRender
			}
			verb := "protocol"
			if i > 0 {
				verb = "+"
			}
			commands = append(commands, fmt.Sprintf("set service %s %s %d src-port %s dst-port %s", name, verb, term.Protocol.Low, portText(term.SourcePort), portText(term.DestinationPort)))
		}
	}
	used := make(map[fm.ID]bool)
	for _, r := range before.Rules() {
		used[r.Record().ID] = true
	}
	allocated := make(map[fm.ID]fm.ID)
	next := 1
	for _, c := range changes {
		if c.Kind != plan.CreateRule {
			continue
		}
		if after.Rule(c.Rule) == nil || before.Rule(c.Rule) != nil {
			return nil, ErrRender
		}
		for next < 320000 && used[fm.ID(strconv.Itoa(next))] {
			next++
		}
		if next >= 320000 {
			return nil, ErrRender
		}
		id := fm.ID(strconv.Itoa(next))
		allocated[c.Rule] = id
		used[id] = true
		next++
	}
	// Every new policy uses native top placement; emit creations in reverse final
	// order so a multi-rule request retains its proven relative order.
	ordered := slices.Clone(changes)
	var created []plan.Change
	for _, c := range changes {
		if c.Kind == plan.CreateRule {
			created = append(created, c)
		}
	}
	slices.SortStableFunc(created, func(a, b plan.Change) int {
		return after.Rule(b.Rule).Record().Position - after.Rule(a.Rule).Record().Position
	})
	index := 0
	for i := range ordered {
		if ordered[i].Kind == plan.CreateRule {
			ordered[i] = created[index]
			index++
		}
	}
	for _, c := range ordered {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if ownsNAT(before, c.Rule) || ownsNAT(after, c.Rule) {
			return nil, ErrRender
		}
		if c.Kind == plan.RemoveRule {
			id, ok := policyID(string(c.Rule))
			r := before.Rule(id)
			if !ok || r == nil || r.Record().Builtin || after.Rule(id) != nil {
				return nil, ErrRender
			}
			commands = append(commands, "unset policy id "+string(id))
			continue
		}
		rule := after.Rule(c.Rule)
		if rule == nil {
			return nil, ErrRender
		}
		r := rule.Record()
		m := r.Match
		if r.Scope != "" || r.RuleSet != "security" || r.Builtin || r.Disabled || len(r.Unsupported) > 0 || len(m.Unsupported) > 0 || len(m.Applications) > 0 || len(m.Users) > 0 || m.Schedule != "" || m.ZoneRelation != fm.AnyZoneRelation || m.AnyFromZone || m.AnyToZone || len(m.FromZones) != 1 || len(m.ToZones) != 1 || r.Description != "" {
			return nil, ErrRender
		}
		id := c.Rule
		if c.Kind == plan.CreateRule {
			id = allocated[c.Rule]
		}
		if _, ok := policyID(string(id)); !ok {
			return nil, ErrRender
		}
		var sources, destinations, services []string
		src, dst, srv := c.Sources, c.Destinations, c.Services
		if c.Kind == plan.CreateRule {
			src, dst, srv = m.Sources, m.Destinations, m.Services
		}
		for _, side := range []struct {
			refs []fm.AddressRef
			zone fm.ID
			out  *[]string
		}{{src, m.FromZones[0], &sources}, {dst, m.ToZones[0], &destinations}} {
			for _, ref := range side.refs {
				name, err := addressName(after, side.zone, ref)
				if err != nil {
					return nil, err
				}
				*side.out = append(*side.out, name)
			}
		}
		for _, ref := range srv {
			name, err := serviceName(after, ref)
			if err != nil {
				return nil, err
			}
			services = append(services, name)
		}
		if c.Kind == plan.CreateRule {
			// ScreenOS Any is IPv4-only. A generic dual-family wildcard cannot be rendered.
			if m.AnySource || m.AnyDestination {
				return nil, ErrRender
			}
			if m.AnyService {
				services = []string{"\"ANY\""}
			}
			if len(sources) == 0 || len(destinations) == 0 || len(services) == 0 {
				return nil, ErrRender
			}
			from, e1 := quoted(string(m.FromZones[0]))
			to, e2 := quoted(string(m.ToZones[0]))
			action := map[fm.Action]string{fm.Permit: "permit", fm.Deny: "deny", fm.Reject: "reject"}[r.Action]
			if e1 != nil || e2 != nil || action == "" {
				return nil, ErrRender
			}
			line := fmt.Sprintf("set policy id %s top from %s to %s %s %s %s %s", id, from, to, sources[0], destinations[0], services[0], action)
			if r.LogEnd == fm.Known {
				line += " log"
			} else if r.LogEnd != fm.Irrelevant {
				return nil, ErrRender
			}
			if r.LogStart != fm.Known && r.LogStart != fm.Irrelevant || (r.Log == fm.Known) != (r.LogStart == fm.Known || r.LogEnd == fm.Known) || r.Log != fm.Known && r.Log != fm.Irrelevant {
				return nil, ErrRender
			}
			commands = append(commands, line)
			sources, destinations, services = sources[1:], destinations[1:], services[1:]
			if r.LogStart == fm.Known {
				commands = append(commands, "set log session-init")
			}
		} else if c.Kind == plan.AppendMembers {
			if before.Rule(c.Rule) == nil {
				return nil, ErrRender
			}
			commands = append(commands, "set policy id "+string(id))
		} else {
			return nil, ErrRender
		}
		for _, side := range []struct {
			field  string
			values []string
		}{{"src-address", sources}, {"dst-address", destinations}, {"service", services}} {
			for _, name := range side.values {
				commands = append(commands, "set "+side.field+" "+name)
			}
		}
		commands = append(commands, "exit")
	}
	if len(commands) == 0 {
		return nil, ErrRender
	}
	return commands, nil
}
