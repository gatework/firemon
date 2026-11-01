package hillstone

import (
	"context"
	"fmt"
	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/vendors/internal/render"
	"reflect"
	"strings"
)

func nativeCommands(ctx context.Context, before, after *fm.Firewall, c plan.NativeChanges) (render.Native, error) {
	out := render.NewNative(c)
	version := strings.TrimPrefix(before.Metadata().Software, "StoneOS ")
	if version != "5.5R8" && !strings.HasPrefix(version, "5.5R8P") {
		return out, ErrRender
	}
	usedPools := map[fm.ID]bool{}
	refName := func(ref fm.AddressRef) (string, error) {
		if ref.Kind != fm.AddressObject {
			return "", ErrRender
		}
		a := after.Address(ref.ID)
		if a == nil {
			return "", ErrRender
		}
		r := a.Record()
		if strings.HasPrefix(string(r.ID), "$literal:") {
			value := strings.TrimPrefix(string(r.ID), "$literal:")
			v, e := literal(value)
			if e != nil || r.Name != value || r.Scope != "" || r.Inline || len(r.Unsupported) != 0 || r.FQDN != "" || r.VIP != (fm.NATRef{}) || len(r.Ranges) != 1 || r.Ranges[0] != v {
				return "", ErrRender
			}
			out.Addresses[r.ID] = true
			return quoted(value)
		}
		return quoted(nativeName(r.Object))
	}
	match := func(m fm.Match) (string, error) {
		if !render.PlainMatch(m) || !m.AnyFromZone || !m.AnyToZone || len(m.FromZones) != 0 || len(m.ToZones) != 0 {
			return "", ErrRender
		}
		var values []string
		for _, side := range []struct {
			any  bool
			refs []fm.AddressRef
		}{{m.AnySource, m.Sources}, {m.AnyDestination, m.Destinations}} {
			v := "\"any\""
			if side.any {
				if len(side.refs) != 0 {
					return "", ErrRender
				}
			} else {
				if len(side.refs) != 1 {
					return "", ErrRender
				}
				var err error
				v, err = refName(side.refs[0])
				if err != nil {
					return "", err
				}
			}
			values = append(values, v)
		}
		svc := "\"any\""
		if !m.AnyService {
			if len(m.Services) != 1 || m.Services[0].Kind != fm.ServiceObject {
				return "", ErrRender
			}
			s := after.Service(m.Services[0].ID)
			if s == nil {
				return "", ErrRender
			}
			var err error
			svc, err = quoted(nativeName(s.Record().Object))
			if err != nil {
				return "", err
			}
		} else if len(m.Services) != 0 {
			return "", ErrRender
		}
		return "from " + values[0] + " to " + values[1] + " service " + svc, nil
	}
	emit := func(scope, line string) error {
		if scope != "" {
			v, e := quoted(scope)
			if e != nil {
				return e
			}
			out.Commands = append(out.Commands, "ip vrouter "+v)
		}
		out.Commands = append(out.Commands, "nat", line, "exit")
		if scope != "" {
			out.Commands = append(out.Commands, "exit")
		}
		return nil
	}
	if err := render.AppendNAT(before, after); err != nil {
		return out, err
	}
	for _, entry := range after.NATSequence() {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		if entry.Kind == fm.StaticNATObject {
			if before.StaticNAT(entry.ID) != nil {
				continue
			}
			r := after.StaticNAT(entry.ID).Record()
			if !render.PlainObject(r.Object) || !render.Number(r.Name) || r.Disabled || !r.Bidirectional || r.Order.Section != "bnat" || r.Order.Stage != 0 || len(r.Source) != 1 || r.Source[0].Mode != fm.Offset || len(r.Destination) != 0 || len(r.SourcePorts) != 0 || len(r.DestinationPorts) != 0 || r.Interface != "" || r.SourceVIP != (fm.AddressRef{}) {
				return out, ErrRender
			}
			want := fm.Match{Sources: r.Match.Sources, AnyDestination: true, AnyService: true, AnyFromZone: true, AnyToZone: true}
			if !reflect.DeepEqual(want, r.Match) || len(want.Sources) != 1 {
				return out, ErrRender
			}
			a := after.Address(want.Sources[0].ID)
			if a == nil || len(a.Record().Ranges) != 1 || a.Record().Ranges[0] != r.Source[0].Original {
				return out, ErrRender
			}
			real, err := refName(want.Sources[0])
			if err != nil {
				return out, err
			}
			mapped, err := render.Prefix(r.Source[0].Translated)
			if err != nil {
				return out, err
			}
			if err := emit(r.Scope, "bnatrule id "+r.Name+" virtual ip "+mapped+" real ip "+real); err != nil {
				return out, err
			}
		} else {
			if before.DynamicNAT(entry.ID) != nil {
				continue
			}
			r := after.DynamicNAT(entry.ID).Record()
			if !render.PlainObject(r.Object) || !render.Number(r.Name) || r.Disabled || r.Rule != "" || r.InterfaceAddress.IsValid() || len(r.SourcePorts) != 0 || r.DestinationPool != "" {
				return out, ErrRender
			}
			m, err := match(r.Match)
			if err != nil {
				return out, err
			}
			line := ""
			switch r.Order.Section {
			case "snat":
				if r.Order.Stage != 2 || r.DestinationMode != fm.NoTranslation || len(r.Destination) != 0 || len(r.DestinationPorts) != 0 {
					return out, ErrRender
				}
				target := "eif-ip"
				if r.SourceMode == fm.InterfaceIP {
					if r.SourcePool != "" || r.Interface == "" {
						return out, ErrRender
					}
				} else {
					if r.SourceMode != fm.DynamicIPPort {
						return out, ErrRender
					}
					p := after.NATPool(r.SourcePool)
					if p == nil {
						return out, ErrRender
					}
					v := p.Record()
					if v.ID != fm.ID("$snat:"+string(r.ID)) || v.Name != "" || v.Scope != r.Scope || !render.PlainObject(v.Object) || len(v.Ranges) != 1 || v.Interface != "" || v.Ports != (flow.Interval{}) {
						return out, ErrRender
					}
					target, err = render.Range(v.Ranges[0])
					if err != nil {
						return out, err
					}
					usedPools[v.ID] = true
				}
				line = "snatrule id " + r.Name + " " + m + " trans-to " + target + " mode dynamicport"
			case "dnat":
				if r.Order.Stage != 1 || r.SourceMode != fm.NoTranslation || r.SourcePool != "" || r.DestinationMode != fm.StaticIP || len(r.Destination) != 1 || r.Destination[0].Mode != fm.Constant || r.Destination[0].Translated.First != r.Destination[0].Translated.Last {
					return out, ErrRender
				}
				ranges, err := render.Addresses(ctx, after, r.Match.Destinations, r.Match.AnyDestination)
				if err != nil || len(ranges) != 1 || ranges[0] != r.Destination[0].Original {
					return out, ErrRender
				}
				line = "dnatrule id " + r.Name + " " + m + " trans-to " + r.Destination[0].Translated.First.String()
				if len(r.DestinationPorts) > 0 {
					terms, err := render.Services(ctx, after, r.Match)
					if err != nil || len(terms) != 1 || len(r.DestinationPorts) != 1 {
						return out, ErrRender
					}
					p := r.DestinationPorts[0]
					if p.Mode != fm.Constant || p.Translated.Low != p.Translated.High || p.Original != terms[0].DestinationPort {
						return out, ErrRender
					}
					line += fmt.Sprintf(" port %d", p.Translated.Low)
				}
			default:
				return out, ErrRender
			}
			if r.Interface != "" {
				i := after.Interface(r.Interface)
				if i == nil || i.Scope() != r.Scope {
					return out, ErrRender
				}
				v, err := quoted(i.Name())
				if err != nil {
					return out, err
				}
				line += " eif " + v
			}
			if err := emit(r.Scope, line); err != nil {
				return out, err
			}
		}
	}
	for _, p := range c.Additions.NATPools {
		if !usedPools[p.ID] {
			return out, ErrRender
		}
	}
	return out, nil
}
