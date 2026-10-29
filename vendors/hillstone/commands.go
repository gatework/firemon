package hillstone

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"unicode"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/plan"
)

var ErrRender = errors.New("unsupported Hillstone command representation")

type Renderer struct{}

func quoted(name string) (string, error) {
	if name == "" || len(name) > 128 {
		return "", ErrRender
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return "", ErrRender
		}
	}
	return strconv.Quote(name), nil
}
func nativeName(o fm.Object) string {
	if o.Name != "" {
		return o.Name
	}
	return string(o.ID)
}
func (Renderer) Render(ctx context.Context, before, after *fm.Firewall, changes []plan.Change) ([]string, error) {
	if before == nil || after == nil || before.Metadata().Vendor != "hillstone" || after.Metadata().Vendor != "hillstone" {
		return nil, ErrRender
	}
	commands := []string{"configure"}
	for _, a := range after.Addresses() {
		r := a.Record()
		if before.Address(r.ID) != nil {
			continue
		}
		name, err := quoted(nativeName(r.Object))
		if err != nil {
			return nil, err
		}
		if r.FQDN != "" || len(r.Unsupported) > 0 || len(r.Ranges) == 0 {
			return nil, ErrRender
		}
		commands = append(commands, "address "+name)
		for _, v := range r.Ranges {
			if v.First == v.Last {
				commands = append(commands, fmt.Sprintf("ip %s/%d", v.First, v.First.BitLen()))
			} else {
				commands = append(commands, fmt.Sprintf("range %s %s", v.First, v.Last))
			}
		}
		commands = append(commands, "exit")
	}
	for _, s := range after.Services() {
		r := s.Record()
		if before.Service(r.ID) != nil {
			continue
		}
		name, err := quoted(nativeName(r.Object))
		if err != nil {
			return nil, err
		}
		if len(r.Unsupported) > 0 || len(r.Terms) == 0 {
			return nil, ErrRender
		}
		commands = append(commands, "service "+name)
		for _, term := range r.Terms {
			if term.Protocol.Low != term.Protocol.High || term.ICMPType != (flow.Interval{Low: 0, High: 255}) || term.ICMPCode != (flow.Interval{Low: 0, High: 255}) {
				return nil, ErrRender
			}
			protocol := map[uint16]string{6: "tcp", 17: "udp", 132: "sctp"}[term.Protocol.Low]
			if protocol == "" {
				if term.SourcePort != (flow.Interval{Low: 0, High: 65535}) || term.DestinationPort != (flow.Interval{Low: 0, High: 65535}) {
					return nil, ErrRender
				}
				commands = append(commands, fmt.Sprintf("protocol %d", term.Protocol.Low))
			} else {
				commands = append(commands, fmt.Sprintf("%s dst-port %d %d src-port %d %d", protocol, term.DestinationPort.Low, term.DestinationPort.High, term.SourcePort.Low, term.SourcePort.High))
			}
		}
		commands = append(commands, "exit")
	}
	// Native rule top prepends: render newly created rules in reverse desired order.
	for i := len(changes) - 1; i >= 0; i-- {
		change := changes[i]
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if change.Kind == plan.RemoveRule {
			rule := before.Rule(change.Rule)
			if rule == nil || rule.Record().Scope != "" || rule.Record().Builtin || after.Rule(change.Rule) != nil {
				return nil, ErrRender
			}
			if _, err := strconv.ParseUint(string(change.Rule), 10, 32); err != nil {
				return nil, ErrRender
			}
			commands = append(commands, "no rule id "+string(change.Rule))
			continue
		}
		rule := after.Rule(change.Rule)
		if rule == nil {
			return nil, ErrRender
		}
		r := rule.Record()
		switch change.Kind {
		case plan.AppendMembers:
			if _, err := strconv.ParseUint(string(change.Rule), 10, 32); err != nil {
				return nil, ErrRender
			}
			commands = append(commands, "rule id "+string(change.Rule))
		case plan.CreateRule:
			action := map[fm.Action]string{fm.Permit: "permit", fm.Deny: "deny"}[r.Action]
			if action == "" || r.Match.Schedule != "" || r.Match.ZoneRelation != fm.AnyZoneRelation {
				return nil, ErrRender
			}
			for _, status := range []fm.Status{r.Log, r.LogStart, r.LogEnd} {
				if status != fm.Known && status != fm.Irrelevant {
					return nil, ErrRender
				}
			}
			if r.Log == fm.Known && r.Action != fm.Permit {
				return nil, ErrRender
			}
			if r.Scope != "" && (len(r.Match.FromZones) != 1 || len(r.Match.ToZones) != 1) {
				return nil, ErrRender
			}
			commands = append(commands, "rule top", "action "+action)
			if r.LogStart == fm.Known {
				commands = append(commands, "log session-start")
			}
			if r.LogEnd == fm.Known {
				commands = append(commands, "log session-end")
			}
			for _, side := range []struct {
				word  string
				zones []fm.ID
				any   bool
			}{{"src-zone", r.Match.FromZones, r.Match.AnyFromZone}, {"dst-zone", r.Match.ToZones, r.Match.AnyToZone}} {
				if side.any {
					commands = append(commands, side.word+" \"any\"")
				} else {
					if len(side.zones) != 1 {
						return nil, ErrRender
					}
					z := after.Zone(side.zones[0])
					if z == nil {
						return nil, ErrRender
					}
					name, err := quoted(nativeName(z.Record().Object))
					if err != nil {
						return nil, err
					}
					commands = append(commands, side.word+" "+name)
				}
			}
		default:
			return nil, ErrRender
		}
		for _, side := range []struct {
			word string
			refs []fm.AddressRef
		}{{"src-addr", change.Sources}, {"dst-addr", change.Destinations}} {
			for _, ref := range side.refs {
				var o fm.Object
				switch ref.Kind {
				case fm.AddressObject:
					a := after.Address(ref.ID)
					if a == nil {
						return nil, ErrRender
					}
					o = a.Record().Object
				case fm.AddressGroupObject:
					g := after.AddressGroup(ref.ID)
					if g == nil {
						return nil, ErrRender
					}
					o = g.Record().Object
				default:
					return nil, ErrRender
				}
				name, err := quoted(nativeName(o))
				if err != nil {
					return nil, err
				}
				commands = append(commands, side.word+" "+name)
			}
		}
		for _, ref := range change.Services {
			var o fm.Object
			switch ref.Kind {
			case fm.ServiceObject:
				s := after.Service(ref.ID)
				if s == nil {
					return nil, ErrRender
				}
				o = s.Record().Object
			case fm.ServiceGroupObject:
				g := after.ServiceGroup(ref.ID)
				if g == nil {
					return nil, ErrRender
				}
				o = g.Record().Object
			default:
				return nil, ErrRender
			}
			name, err := quoted(nativeName(o))
			if err != nil {
				return nil, err
			}
			commands = append(commands, "service "+name)
		}
		commands = append(commands, "exit")
	}
	return append(commands, "exit"), nil
}
