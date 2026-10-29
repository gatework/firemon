package srx

import (
	"context"
	"fmt"
	"slices"
	"strconv"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/vendors/internal/render"
)

var ErrRender = fmt.Errorf("%w: unsupported Junos command representation", plan.ErrRender)

type Renderer struct{}

func token(s string) (string, error) {
	if len(s) == 0 || len(s) > 63 {
		return "", ErrRender
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.') {
			return "", ErrRender
		}
	}
	if s == "." || s == ".." {
		return "", ErrRender
	}
	return s, nil
}
func nativeName(o fm.Object) string {
	if o.Name != "" {
		return o.Name
	}
	return string(o.ID)
}
func portText(p flow.Interval) string {
	if p.Low == p.High {
		return strconv.Itoa(int(p.Low))
	}
	return fmt.Sprintf("%d-%d", p.Low, p.High)
}

func policyPath(r fm.RuleRecord) (string, error) {
	if r.Scope != "" || r.RuleSet != "security" || r.Builtin || r.Match.AnyFromZone || r.Match.AnyToZone || len(r.Match.FromZones) != 1 || len(r.Match.ToZones) != 1 {
		return "", ErrRender
	}
	from, e1 := token(string(r.Match.FromZones[0]))
	to, e2 := token(string(r.Match.ToZones[0]))
	name, e3 := token(nativeName(r.Object))
	if e1 != nil || e2 != nil || e3 != nil {
		return "", ErrRender
	}
	return "security policies from-zone " + from + " to-zone " + to + " policy " + name, nil
}
func addressName(fw *fm.Firewall, zone fm.ID, ref fm.AddressRef) (string, error) {
	var object fm.Object
	switch ref.Kind {
	case fm.AddressObject:
		v := fw.Address(ref.ID)
		if v == nil {
			return "", ErrRender
		}
		object = v.Record().Object
	case fm.AddressGroupObject:
		v := fw.AddressGroup(ref.ID)
		if v == nil {
			return "", ErrRender
		}
		object = v.Record().Object
	default:
		return "", ErrRender
	}
	name, err := token(nativeName(object))
	if err != nil {
		return "", err
	}
	z := fw.Zone(zone)
	if z == nil {
		return "", ErrRender
	}
	// Resolve the native name again in its target zone. An identically named
	// object from another book, or a global name shadowed locally, is not reusable.
	for _, scope := range []string{z.Record().AddressScope, ""} {
		id := addressID(scope, name)
		if a := fw.Address(id); a != nil {
			if ref.Kind == fm.AddressObject && ref.ID == id {
				return name, nil
			}
			return "", ErrRender
		}
		if g := fw.AddressGroup(id); g != nil {
			if ref.Kind == fm.AddressGroupObject && ref.ID == id {
				return name, nil
			}
			return "", ErrRender
		}
	}
	// Builtin family selectors have no native object declaration.
	if (name == "any-ipv4" || name == "any-ipv6") && ref.ID == fm.ID("$"+name) {
		return name, nil
	}
	return "", ErrRender
}
func applicationName(fw *fm.Firewall, ref fm.ServiceRef) (string, error) {
	var o fm.Object
	if ref.Kind == fm.ServiceObject {
		s := fw.Service(ref.ID)
		if s == nil {
			return "", ErrRender
		}
		o = s.Record().Object
	} else if ref.Kind == fm.ServiceGroupObject {
		s := fw.ServiceGroup(ref.ID)
		if s == nil {
			return "", ErrRender
		}
		o = s.Record().Object
	} else {
		return "", ErrRender
	}
	if o.Scope != "" || o.ID != fm.ID(nativeName(o)) {
		return "", ErrRender
	}
	return token(nativeName(o))
}

func (Renderer) Render(ctx context.Context, before, after *fm.Firewall, changes []plan.Change) ([]string, error) {
	batch, err := render.Prepare(ctx, "srx", before, after, changes)
	if err != nil {
		return nil, err
	}
	changes = batch.Changes()
	if len(changes) == 0 {
		return nil, nil
	}
	commands := []string{"configure"}
	for _, a := range after.Addresses() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		r := a.Record()
		if before.Address(r.ID) != nil || !batch.DeclaresAddress(r.ID) {
			continue
		}
		if r.Scope != "" || r.ID != fm.ID(r.Name) || len(r.Ranges) != 1 || r.FQDN != "" || len(r.Unsupported) > 0 {
			return nil, ErrRender
		}
		name, err := token(r.Name)
		if err != nil {
			return nil, err
		}
		v := r.Ranges[0]
		value := "range-address " + v.First.String() + " to " + v.Last.String()
		if p, ok := rangePrefix(v); ok {
			value = p.String()
		}
		commands = append(commands, "set security address-book global address "+name+" "+value)
	}
	for _, s := range after.Services() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		r := s.Record()
		if before.Service(r.ID) != nil || !batch.DeclaresService(r.ID) {
			continue
		}
		if r.Scope != "" || r.ID != fm.ID(r.Name) || len(r.Terms) != 1 || len(r.Unsupported) > 0 {
			return nil, ErrRender
		}
		name, err := token(r.Name)
		if err != nil {
			return nil, err
		}
		term := r.Terms[0]
		if term.Protocol.Low != term.Protocol.High || term.ICMPType != (flow.Interval{High: 255}) || term.ICMPCode != (flow.Interval{High: 255}) {
			return nil, ErrRender
		}
		prefix := "set applications application " + name
		commands = append(commands, prefix+" protocol "+strconv.Itoa(int(term.Protocol.Low)))
		for _, side := range []struct {
			field string
			port  flow.Interval
		}{{"source-port", term.SourcePort}, {"destination-port", term.DestinationPort}} {
			if side.port == (flow.Interval{High: 65535}) {
				continue
			}
			if term.Protocol.Low != 6 && term.Protocol.Low != 17 && term.Protocol.Low != 132 {
				return nil, ErrRender
			}
			commands = append(commands, prefix+" "+side.field+" "+portText(side.port))
		}
	}
	ordered := slices.Collect(before.OrderedRules())
	for _, change := range changes {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if change.Kind == plan.RemoveRule {
			r := before.Rule(change.Rule)
			if r == nil || after.Rule(change.Rule) != nil {
				return nil, ErrRender
			}
			path, err := policyPath(r.Record())
			if err != nil {
				return nil, err
			}
			commands = append(commands, "delete "+path)
			continue
		}
		rule := after.Rule(change.Rule)
		if rule == nil {
			return nil, ErrRender
		}
		r := rule.Record()
		path, err := policyPath(r)
		if err != nil {
			return nil, err
		}
		if r.Disabled || len(r.Unsupported) > 0 || len(r.Match.Unsupported) > 0 || len(r.Match.Users) > 0 || len(r.Match.Applications) > 0 || r.Match.Schedule != "" || r.Match.ZoneRelation != fm.AnyZoneRelation {
			return nil, ErrRender
		}
		var source, destination []fm.AddressRef
		var services []fm.ServiceRef
		switch change.Kind {
		case plan.CreateRule:
			source, destination, services = r.Match.Sources, r.Match.Destinations, r.Match.Services
		case plan.AppendMembers:
			source, destination, services = change.Sources, change.Destinations, change.Services
		default:
			return nil, ErrRender
		}
		for _, side := range []struct {
			field string
			zone  fm.ID
			refs  []fm.AddressRef
			any   bool
		}{{"source-address", r.Match.FromZones[0], source, r.Match.AnySource}, {"destination-address", r.Match.ToZones[0], destination, r.Match.AnyDestination}} {
			if change.Kind == plan.CreateRule && side.any {
				commands = append(commands, "set "+path+" match "+side.field+" any")
				continue
			}
			for _, ref := range side.refs {
				name, err := addressName(after, side.zone, ref)
				if err != nil {
					return nil, err
				}
				commands = append(commands, "set "+path+" match "+side.field+" "+name)
			}
		}
		if change.Kind == plan.CreateRule && r.Match.AnyService {
			commands = append(commands, "set "+path+" match application any")
		} else {
			for _, ref := range services {
				name, err := applicationName(after, ref)
				if err != nil {
					return nil, err
				}
				commands = append(commands, "set "+path+" match application "+name)
			}
		}
		if change.Kind != plan.CreateRule {
			continue
		}
		action := map[fm.Action]string{fm.Permit: "permit", fm.Deny: "deny", fm.Reject: "reject"}[r.Action]
		if action == "" {
			return nil, ErrRender
		}
		commands = append(commands, "set "+path+" then "+action)
		for _, log := range []struct {
			field  string
			status fm.Status
		}{{"session-init", r.LogStart}, {"session-close", r.LogEnd}} {
			if log.status == fm.Known {
				commands = append(commands, "set "+path+" then log "+log.field)
			} else if log.status != fm.Irrelevant {
				return nil, ErrRender
			}
		}
		if (r.Log == fm.Known) != (r.LogStart == fm.Known || r.LogEnd == fm.Known) || r.Log != fm.Known && r.Log != fm.Irrelevant || r.Description != "" {
			return nil, ErrRender
		}
		for _, prior := range ordered {
			p := prior.Record()
			if after.Rule(p.ID) == nil || p.Builtin || p.Scope != r.Scope || p.RuleSet != r.RuleSet || !slices.Equal(p.Match.FromZones, r.Match.FromZones) || !slices.Equal(p.Match.ToZones, r.Match.ToZones) {
				continue
			}
			name, err := token(nativeName(p.Object))
			if err != nil {
				return nil, err
			}
			commands = append(commands, "insert "+path+" before policy "+name)
			break
		}
	}
	if len(commands) == 1 {
		return nil, ErrRender
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return append(commands, "exit"), nil
}
