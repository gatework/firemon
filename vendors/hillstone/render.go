package hillstone

import (
	"cmp"
	"errors"
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
		case design.AddAddressGroup:
			do = []string{"address " + q(c.Group.Name)}
			for _, m := range c.Group.Members {
				do = append(do, "  member "+q(m))
			}
			do = append(do, "exit")
			undo = []string{"no address " + q(c.Group.Name)}
		case design.AddServiceGroup:
			do = []string{"servgroup " + q(c.Group.Name)}
			for _, m := range c.Group.Members {
				do = append(do, "  service "+q(m))
			}
			do = append(do, "exit")
			undo = []string{"no servgroup " + q(c.Group.Name)}
		case design.ExtendRule:
			do, undo, err = renderExtend(c)
		case design.AddRule:
			do = renderRule(c)
			undo = []string{"no rule id " + c.Rule.ID}
		case design.AddNAT:
			do, undo, err = renderNAT(c)
		case design.AddStaticNAT:
			do, undo, err = renderStaticNAT(c.Mapping)
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

// renderNAT writes a snatrule or dnatrule inside its virtual router. The
// rule is placed before c.Before, since NAT rules match in order.
func renderNAT(c design.AddNAT) (do, undo []string, err error) {
	r := c.Rule
	kind := "snatrule"
	t := r.TranslatedSource
	if design.NATSide(r) == firemon.NATKindDestination {
		kind, t = "dnatrule", r.TranslatedDestination
	}
	if len(r.Services) > 1 {
		return nil, nil, fmt.Errorf("hillstone: %s %s: one service", kind, r.ID)
	}
	from, err1 := natOperandText(r.Source)
	to, err2 := natOperandText(r.Destination)
	if err := errors.Join(err1, err2); err != nil {
		return nil, nil, fmt.Errorf("hillstone: %s %s: %w", kind, r.ID, err)
	}
	line := kind + " id " + r.ID
	if c.Before != "" {
		line += " before " + c.Before
	}
	service := anyName
	if len(r.Services) == 1 {
		service = r.Services[0]
	}
	line += " from " + from + " to " + to + " service " + q(service)
	if r.Egress != "" {
		line += " eif " + r.Egress
	}
	switch t.Mode {
	case firemon.TranslationModeInterface:
		line += " trans-to eif-ip"
	case firemon.TranslationModeAddress:
		to, err := natOperandText(t.Addresses)
		if err != nil || len(t.Addresses) != 1 {
			return nil, nil, fmt.Errorf("hillstone: %s %s: one translated address", kind, r.ID)
		}
		line += " trans-to " + to
	case firemon.TranslationModeUnset, firemon.TranslationModeNone:
		return nil, nil, fmt.Errorf("hillstone: %s %s: no translation", kind, r.ID)
	}
	if kind == "snatrule" {
		line += " mode " + map[bool]string{true: "dynamicport", false: "dynamicip"}[t.PortTranslation]
	} else if t.Port != 0 {
		line += " port " + strconv.Itoa(int(t.Port))
	}
	vr := "ip vrouter " + q(cmp.Or(r.VirtualRouter, DefaultVirtualRouter))
	return []string{vr, "  " + line, "exit"}, []string{vr, "  no " + kind + " id " + r.ID, "exit"}, nil
}

// renderStaticNAT writes a bnatrule inside its virtual router.
func renderStaticNAT(m firemon.StaticNAT) (do, undo []string, err error) {
	virtual, err1 := natOperandText([]firemon.AddressRef{m.Mapped})
	inside, err2 := natOperandText([]firemon.AddressRef{m.Real})
	if err := errors.Join(err1, err2); err != nil {
		return nil, nil, fmt.Errorf("hillstone: bnatrule %s: %w", m.ID, err)
	}
	vr := "ip vrouter " + q(cmp.Or(m.VirtualRouter, DefaultVirtualRouter))
	line := "bnatrule id " + m.ID + " virtual " + virtual + " real " + inside
	return []string{vr, "  " + line, "exit"}, []string{vr, "  no bnatrule id " + m.ID, "exit"}, nil
}

// natOperandText writes one NAT operand: an address book entry, an inline
// prefix or range, or Any for an empty list.
func natOperandText(refs []firemon.AddressRef) (string, error) {
	switch {
	case len(refs) == 0:
		return "address-book " + q(anyName), nil
	case len(refs) > 1:
		return "", errors.New("one address operand")
	case !refs[0].IsInline():
		return "address-book " + q(refs[0].Name), nil
	}
	e := refs[0].Entry
	switch e.Kind {
	case firemon.AddressKindPrefix:
		return "ip " + e.Prefix.String(), nil
	case firemon.AddressKindRange:
		return "range " + e.From.String() + " " + e.To.String(), nil
	case firemon.AddressKindFQDN, firemon.AddressKindUnset:
	}
	return "", fmt.Errorf("cannot write %s entry", e.Kind)
}
