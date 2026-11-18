package hillstone

import (
	"fmt"
	"slices"
	"strconv"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/design"
	"github.com/gatework/firemon/traffic"
)

// Renderer writes design plans as StoneOS configuration commands.
type Renderer struct{}

// Render returns the commands of plan's changes and their rollback.
func (Renderer) Render(plan *design.Plan) (design.Script, error) {
	var s design.Script
	var rollback [][]string
	for _, ch := range plan.Changes {
		var do, undo []string
		var err error
		switch c := ch.(type) {
		case design.AddAddress:
			do, err = renderAddress(c.Address)
			undo = []string{"no address " + q(c.Address.Name)}
		case design.AddService:
			do, err = renderService(c.Service)
			undo = []string{"no service " + q(c.Service.Name)}
		case design.ExtendRule:
			do, undo, err = renderExtend(c)
		case design.AddRule:
			do = renderRule(c)
			undo = []string{"no rule id " + c.Rule.ID}
		default:
			err = fmt.Errorf("hillstone: unsupported change %T", ch)
		}
		if err != nil {
			return design.Script{}, err
		}
		s.Commands = append(s.Commands, do...)
		rollback = append(rollback, undo)
	}
	slices.Reverse(rollback)
	s.Rollback = slices.Concat(rollback...)
	return s, nil
}

func renderAddress(a firemon.Address) ([]string, error) {
	head := "address " + q(a.Name)
	if len(a.Entries) > 0 && (a.Entries[0].Prefix.Addr().Is6() || a.Entries[0].From.Is6()) {
		head += " ipv6"
	}
	out := []string{head}
	for _, e := range a.Entries {
		switch e.Kind {
		case firemon.AddressKindPrefix:
			out = append(out, "  ip "+e.Prefix.String())
		case firemon.AddressKindRange:
			out = append(out, "  range "+e.From.String()+" "+e.To.String())
		case firemon.AddressKindFQDN, firemon.AddressKindUnset:
			return nil, fmt.Errorf("hillstone: cannot render %s entry of %q", e.Kind, a.Name)
		}
	}
	return append(out, "exit"), nil
}

func renderService(svc firemon.Service) ([]string, error) {
	out := []string{"service " + q(svc.Name)}
	for _, e := range svc.Entries {
		line, err := serviceLine(e)
		if err != nil {
			return nil, fmt.Errorf("hillstone: service %q: %w", svc.Name, err)
		}
		out = append(out, "  "+line)
	}
	return append(out, "exit"), nil
}

func serviceLine(e firemon.ServiceEntry) (string, error) {
	switch {
	case e.AnyProtocol:
		return "protocol any", nil
	case e.Protocol.HasPorts():
		line := e.Protocol.String() + " dst-port " + portRange(e.Dst)
		if !e.Src.IsAny() {
			line += " src-port " + portRange(e.Src)
		}
		return line, nil
	case e.Protocol.IsICMP():
		if e.Dst.IsAny() {
			return e.Protocol.String(), nil
		}
		if e.Dst.Low>>8 != e.Dst.High>>8 {
			return "", fmt.Errorf("icmp entry spans several types")
		}
		return fmt.Sprintf("%s type %d code %d %d", e.Protocol, e.Dst.Low>>8, e.Dst.Low&0xff, e.Dst.High&0xff), nil
	default:
		return "protocol " + strconv.Itoa(int(e.Protocol)), nil
	}
}

func portRange(r traffic.PortRange) string {
	if r.Low == r.High {
		return strconv.Itoa(int(r.Low))
	}
	return strconv.Itoa(int(r.Low)) + " " + strconv.Itoa(int(r.High))
}

func renderExtend(c design.ExtendRule) (do, undo []string, err error) {
	keyword := map[design.Field]string{design.FieldSource: "src-addr", design.FieldDestination: "dst-addr", design.FieldService: "service"}[c.Field]
	if keyword == "" {
		return nil, nil, fmt.Errorf("hillstone: extend rule %s: field %s", c.RuleID, c.Field)
	}
	do, undo = []string{"rule id " + c.RuleID}, []string{"rule id " + c.RuleID}
	for _, n := range c.Names {
		do = append(do, "  "+keyword+" "+q(n))
		undo = append(undo, "  no "+keyword+" "+q(n))
	}
	return append(do, "exit"), append(undo, "exit"), nil
}

func renderRule(c design.AddRule) []string {
	r := c.Rule
	head := "rule id " + r.ID
	if c.Before != "" {
		head += " before " + c.Before
	}
	out := []string{head, "  action " + map[firemon.Action]string{firemon.ActionPermit: "permit", firemon.ActionDeny: "deny"}[r.Action]}
	out = append(out, zoneLines("src-zone", r.From)...)
	out = append(out, zoneLines("dst-zone", r.To)...)
	out = append(out, refLines("src-addr", r.Source)...)
	out = append(out, refLines("dst-addr", r.Destination)...)
	if len(r.Services) == 0 {
		out = append(out, "  service "+q(anyName))
	}
	for _, s := range r.Services {
		out = append(out, "  service "+q(s))
	}
	if r.Name != "" {
		out = append(out, "  name "+q(r.Name))
	}
	if r.Description != "" {
		out = append(out, "  description "+q(r.Description))
	}
	if r.Schedule != "" {
		out = append(out, "  schedule "+q(r.Schedule))
	}
	return append(out, "exit")
}

func zoneLines(keyword string, zones []string) []string {
	if len(zones) == 0 {
		return []string{"  " + keyword + " " + q(anyName)}
	}
	out := make([]string, len(zones))
	for i, z := range zones {
		out[i] = "  " + keyword + " " + q(z)
	}
	return out
}

func refLines(keyword string, refs []firemon.AddressRef) []string {
	if len(refs) == 0 {
		return []string{"  " + keyword + " " + q(anyName)}
	}
	out := make([]string, 0, len(refs))
	for _, r := range refs {
		out = append(out, "  "+keyword+" "+q(r.Name))
	}
	return out
}

func q(s string) string { return strconv.Quote(s) }

// DeployCommands returns the commands a deployment session sends, one per
// write: configuration mode, the rendered lines, and leaving configuration
// mode. Saving is a separate, confirmed step.
func DeployCommands(s design.Script) []string {
	return slices.Concat([]string{"configure"}, s.Commands, []string{"exit"})
}
