package asa

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/vendors/internal/render"
)

var ErrRender = fmt.Errorf("%w: unsupported ASA command representation", plan.ErrRender)

type Renderer struct{}

func commandName(s string) (string, error) {
	if s == "" || len(s) > 64 {
		return "", ErrRender
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.') {
			return "", ErrRender
		}
	}
	return s, nil
}
func nativeName(o fm.Object) string {
	if o.Name != "" {
		return o.Name
	}
	return string(o.ID)
}
func ports(r flow.Interval) string {
	if r.Low == r.High {
		return "eq " + strconv.Itoa(int(r.Low))
	}
	return fmt.Sprintf("range %d %d", r.Low, r.High)
}

func (Renderer) Render(ctx context.Context, before, after *fm.Firewall, changes []plan.Change) ([]string, error) {
	changes, err := render.Prepare(ctx, "asa", before, after, changes)
	if err != nil {
		return nil, err
	}
	if len(changes) == 0 {
		return nil, nil
	}
	commands := []string{"configure terminal"}
	for _, address := range after.Addresses() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		r := address.Record()
		if before.Address(r.ID) != nil {
			continue
		}
		if len(r.Ranges) != 1 || r.FQDN != "" || r.Scope != "" || len(r.Unsupported) > 0 {
			return nil, ErrRender
		}
		name, err := commandName(nativeName(r.Object))
		if err != nil {
			return nil, err
		}
		v := r.Ranges[0]
		value := "range " + v.First.String() + " " + v.Last.String()
		if v.First == v.Last {
			value = "host " + v.First.String()
		}
		commands = append(commands, "object network "+name, value, "exit")
	}
	for _, service := range after.Services() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		r := service.Record()
		if before.Service(r.ID) != nil {
			continue
		}
		if len(r.Terms) != 1 || r.Scope != "" || len(r.Unsupported) > 0 {
			return nil, ErrRender
		}
		name, err := commandName(nativeName(r.Object))
		if err != nil {
			return nil, err
		}
		t := r.Terms[0]
		proto := map[uint16]string{6: "tcp", 17: "udp"}[t.Protocol.Low]
		if t.Protocol.Low != t.Protocol.High || proto == "" || t.ICMPType != (flow.Interval{High: 255}) || t.ICMPCode != (flow.Interval{High: 255}) {
			return nil, ErrRender
		}
		commands = append(commands, "object service "+name, "service "+proto+" source "+ports(t.SourcePort)+" destination "+ports(t.DestinationPort), "exit")
	}
	ordered := after.Rules()
	slices.SortStableFunc(ordered, func(a, b *fm.Rule) int {
		x, y := a.Record(), b.Record()
		if x.Position < y.Position {
			return -1
		}
		if x.Position > y.Position {
			return 1
		}
		return strings.Compare(string(x.ID), string(y.ID))
	})
	positions := make(map[fm.ID]int)
	ranks := make(map[string]int)
	for _, r := range ordered {
		record := r.Record()
		ranks[record.RuleSet]++
		positions[record.ID] = ranks[record.RuleSet]
	}
	for _, change := range changes {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		// ACL entries have no mutable member list. Creating an exact new entry
		// avoids modifying a shared object-group outside the approved request.
		if change.Kind != plan.CreateRule {
			return nil, ErrRender
		}
		rule := after.Rule(change.Rule)
		if rule == nil {
			return nil, ErrRender
		}
		r := rule.Record()
		m := r.Match
		if r.Scope != "" || r.Action != fm.Permit || r.Disabled || r.Builtin || len(r.Unsupported) > 0 || r.Log != fm.Irrelevant || r.LogStart != fm.Irrelevant || r.LogEnd != fm.Irrelevant || m.Schedule != "" || m.ZoneRelation != fm.AnyZoneRelation || len(m.Unsupported) > 0 || len(m.Applications) > 0 || len(m.Users) > 0 {
			return nil, ErrRender
		}
		if !nativeBinding(before, r) {
			return nil, ErrRender
		}
		acl, err := commandName(r.RuleSet)
		if err != nil {
			return nil, err
		}
		if m.AnySource || m.AnyDestination || m.AnyService || len(m.Sources) != 1 || len(m.Destinations) != 1 || len(m.Services) != 1 {
			return nil, ErrRender
		}
		address := func(ref fm.AddressRef) (string, error) {
			keyword := "object"
			var object fm.Object
			switch ref.Kind {
			case fm.AddressObject:
				a := after.Address(ref.ID)
				if a == nil {
					return "", ErrRender
				}
				object = a.Record().Object
			case fm.AddressGroupObject:
				g := after.AddressGroup(ref.ID)
				if g == nil {
					return "", ErrRender
				}
				object = g.Record().Object
				keyword = "object-group"
			default:
				return "", ErrRender
			}
			name, err := commandName(nativeName(object))
			return keyword + " " + name, err
		}
		src, err := address(m.Sources[0])
		if err != nil {
			return nil, err
		}
		dst, err := address(m.Destinations[0])
		if err != nil {
			return nil, err
		}
		var svc string
		ref := m.Services[0]
		if ref.Kind == fm.ServiceObject {
			s := after.Service(ref.ID)
			if s == nil {
				return nil, ErrRender
			}
			name, err := commandName(nativeName(s.Record().Object))
			if err != nil {
				return nil, err
			}
			svc = "object " + name
		} else if ref.Kind == fm.ServiceGroupObject {
			s := after.ServiceGroup(ref.ID)
			if s == nil {
				return nil, ErrRender
			}
			name, err := commandName(nativeName(s.Record().Object))
			if err != nil {
				return nil, err
			}
			svc = "object-group " + name
		} else {
			return nil, ErrRender
		}
		commands = append(commands, fmt.Sprintf("access-list %s line %d extended permit %s %s %s", acl, positions[r.ID], svc, src, dst))
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return append(commands, "end"), nil
}

func nativeBinding(fw *fm.Firewall, r fm.RuleRecord) bool {
	var from, to []fm.ID
	for _, b := range fw.RuleBindings() {
		x := b.Record()
		if x.Scope != r.Scope || x.RuleSet != r.RuleSet {
			continue
		}
		if x.Direction == "in" {
			from = append(from, x.Zone)
		} else if x.Direction == "out" {
			to = append(to, x.Zone)
		} else {
			return false
		}
	}
	m := r.Match
	if len(from) == 1 && len(to) == 0 {
		return !m.AnyFromZone && slices.Equal(from, m.FromZones) && m.AnyToZone && len(m.ToZones) == 0
	}
	if len(to) == 1 && len(from) == 0 {
		return m.AnyFromZone && len(m.FromZones) == 0 && !m.AnyToZone && slices.Equal(to, m.ToZones)
	}
	return false
}
