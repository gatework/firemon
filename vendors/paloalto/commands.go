package paloalto

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"unicode"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/vendors/internal/render"
)

var ErrRender = fmt.Errorf("%w: unsupported PAN command representation", plan.ErrRender)

type Renderer struct{}

// quoted emits one literal native CLI argument; JSON/Go backslash escapes are
// intentionally not used because they are not the PAN CLI's string grammar.
func quoted(value string) (string, error) {
	if value == "" || len(value) > 127 {
		return "", ErrRender
	}
	for _, r := range value {
		if unicode.IsControl(r) || r == '"' || r == '\\' {
			return "", ErrRender
		}
	}
	return "\"" + value + "\"", nil
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

func (Renderer) Render(ctx context.Context, before, after *fm.Firewall, changes []plan.Change) ([]string, error) {
	changes, err := render.Prepare(ctx, "paloalto", before, after, changes)
	if err != nil {
		return nil, err
	}
	if len(changes) == 0 {
		return nil, nil
	}
	commands := []string{"configure"}
	for _, a := range after.Addresses() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		r := a.Record()
		if before.Address(r.ID) != nil {
			continue
		}
		if len(r.Ranges) != 1 || r.FQDN != "" || r.Scope != "" || len(r.Unsupported) > 0 {
			return nil, ErrRender
		}
		name, err := quoted(nativeName(r.Object))
		if err != nil {
			return nil, err
		}
		v := r.Ranges[0]
		field, value := "ip-range", v.First.String()+"-"+v.Last.String()
		if v.First == v.Last {
			field = "ip-netmask"
			value = fmt.Sprintf("%s/%d", v.First, v.First.BitLen())
		}
		commands = append(commands, "set address "+name+" "+field+" "+value)
	}
	for _, s := range after.Services() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		r := s.Record()
		if before.Service(r.ID) != nil {
			continue
		}
		if len(r.Terms) != 1 || r.Scope != "" || len(r.Unsupported) > 0 {
			return nil, ErrRender
		}
		name, err := quoted(nativeName(r.Object))
		if err != nil {
			return nil, err
		}
		t := r.Terms[0]
		if t.Protocol.Low != t.Protocol.High || t.ICMPType != (flow.Interval{High: 255}) || t.ICMPCode != (flow.Interval{High: 255}) {
			return nil, ErrRender
		}
		protocol := map[uint16]string{6: "tcp", 17: "udp"}[t.Protocol.Low]
		if protocol == "" {
			return nil, ErrRender
		}
		prefix := "set service " + name + " protocol " + protocol
		commands = append(commands, prefix+" port "+portText(t.DestinationPort), prefix+" source-port "+portText(t.SourcePort))
	}
	ordered := before.Rules()
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
	first := ""
	for _, rule := range ordered {
		r := rule.Record()
		if r.Scope == "" && r.RuleSet == "security" && !r.Builtin && after.Rule(r.ID) != nil {
			first = nativeName(r.Object)
			break
		}
	}
	for _, change := range changes {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if change.Kind == plan.RemoveRule {
			rule := before.Rule(change.Rule)
			if rule == nil || after.Rule(change.Rule) != nil {
				return nil, ErrRender
			}
			r := rule.Record()
			if r.Scope != "" || r.RuleSet != "security" || r.Builtin {
				return nil, ErrRender
			}
			name, err := quoted(nativeName(r.Object))
			if err != nil {
				return nil, err
			}
			commands = append(commands, "delete rulebase security rules "+name)
			continue
		}
		rule := after.Rule(change.Rule)
		if rule == nil {
			return nil, ErrRender
		}
		r := rule.Record()
		if r.Scope != "" || r.RuleSet != "security" || r.Builtin || len(r.Unsupported) > 0 {
			return nil, ErrRender
		}
		name, err := quoted(nativeName(r.Object))
		if err != nil {
			return nil, err
		}
		prefix := "set rulebase security rules " + name
		switch change.Kind {
		case plan.CreateRule:
			action := map[fm.Action]string{fm.Permit: "allow", fm.Deny: "deny", fm.Drop: "drop", fm.ResetClient: "reset-client", fm.ResetServer: "reset-server", fm.ResetBoth: "reset-both"}[r.Action]
			if action == "" || r.Disabled || r.Match.Schedule != "" || len(r.Match.Applications) > 0 || len(r.Match.Users) > 0 || len(r.Match.Unsupported) > 0 || r.Match.ZoneRelation != fm.AnyZoneRelation {
				return nil, ErrRender
			}
			for _, status := range []fm.Status{r.Log, r.LogStart, r.LogEnd} {
				if status != fm.Known && status != fm.Irrelevant {
					return nil, ErrRender
				}
			}
			for _, side := range []struct {
				field string
				zones []fm.ID
				any   bool
			}{{"from", r.Match.FromZones, r.Match.AnyFromZone}, {"to", r.Match.ToZones, r.Match.AnyToZone}} {
				if side.any {
					commands = append(commands, prefix+" "+side.field+" any")
					continue
				}
				if len(side.zones) == 0 {
					return nil, ErrRender
				}
				for _, id := range side.zones {
					z := after.Zone(id)
					if z == nil {
						return nil, ErrRender
					}
					v, err := quoted(nativeName(z.Record().Object))
					if err != nil {
						return nil, err
					}
					commands = append(commands, prefix+" "+side.field+" "+v)
				}
			}
			start, end := "no", "no"
			if r.LogStart == fm.Known {
				start = "yes"
			}
			if r.LogEnd == fm.Known {
				end = "yes"
			}
			commands = append(commands, prefix+" application any", prefix+" action "+action, prefix+" rule-type universal", prefix+" log-start "+start, prefix+" log-end "+end)
		case plan.AppendMembers:
			if before.Rule(r.ID) == nil {
				return nil, ErrRender
			}
		default:
			return nil, ErrRender
		}
		for _, side := range []struct {
			field string
			refs  []fm.AddressRef
		}{{"source", change.Sources}, {"destination", change.Destinations}} {
			for _, ref := range side.refs {
				var object fm.Object
				switch ref.Kind {
				case fm.AddressObject:
					a := after.Address(ref.ID)
					if a == nil {
						return nil, ErrRender
					}
					object = a.Record().Object
				case fm.AddressGroupObject:
					g := after.AddressGroup(ref.ID)
					if g == nil {
						return nil, ErrRender
					}
					object = g.Record().Object
				default:
					return nil, ErrRender
				}
				v, err := quoted(nativeName(object))
				if err != nil {
					return nil, err
				}
				commands = append(commands, prefix+" "+side.field+" "+v)
			}
		}
		for _, ref := range change.Services {
			var object fm.Object
			switch ref.Kind {
			case fm.ServiceObject:
				s := after.Service(ref.ID)
				if s == nil {
					return nil, ErrRender
				}
				object = s.Record().Object
			case fm.ServiceGroupObject:
				g := after.ServiceGroup(ref.ID)
				if g == nil {
					return nil, ErrRender
				}
				object = g.Record().Object
			default:
				return nil, ErrRender
			}
			v, err := quoted(nativeName(object))
			if err != nil {
				return nil, err
			}
			commands = append(commands, prefix+" service "+v)
		}
		if change.Kind == plan.CreateRule && first != "" {
			blocker, err := quoted(first)
			if err != nil {
				return nil, err
			}
			commands = append(commands, "move rulebase security rules "+name+" before "+blocker)
		}
	}
	// Persistence is a separately journaled deploy phase with commit completion.
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return append(commands, "exit"), nil
}
