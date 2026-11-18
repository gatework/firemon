package paloalto

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/design"
)

// Renderer writes design plans as PAN-OS set commands.
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
			undo = []string{"delete address " + name(c.Address.Name)}
		case design.AddService:
			do, err = renderService(c.Service)
			undo = []string{"delete service " + name(c.Service.Name)}
		case design.ExtendRule:
			do, undo, err = renderExtend(c)
		case design.AddRule:
			do = renderRule(c)
			undo = []string{"delete rulebase security rules " + name(c.Rule.ID)}
		default:
			err = fmt.Errorf("paloalto: unsupported change %T", ch)
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
	if len(a.Entries) != 1 {
		return nil, fmt.Errorf("paloalto: address %q must have exactly one entry", a.Name)
	}
	e := a.Entries[0]
	switch e.Kind {
	case firemon.AddressKindPrefix:
		return []string{"set address " + name(a.Name) + " ip-netmask " + e.Prefix.String()}, nil
	case firemon.AddressKindRange:
		return []string{"set address " + name(a.Name) + " ip-range " + e.From.String() + "-" + e.To.String()}, nil
	case firemon.AddressKindFQDN:
		return []string{"set address " + name(a.Name) + " fqdn " + e.FQDN}, nil
	case firemon.AddressKindUnset:
	}
	return nil, fmt.Errorf("paloalto: address %q has no value", a.Name)
}

func renderService(svc firemon.Service) ([]string, error) {
	if len(svc.Entries) == 0 {
		return nil, fmt.Errorf("paloalto: service %q has no entry", svc.Name)
	}
	proto := svc.Entries[0].Protocol
	var dst []string
	src := svc.Entries[0].Src
	for _, e := range svc.Entries {
		if !e.Protocol.HasPorts() || e.Protocol != proto || e.Src != src {
			return nil, fmt.Errorf("paloalto: service %q: only one TCP, UDP or SCTP port set per service", svc.Name)
		}
		dst = append(dst, portText(e.Dst.Low, e.Dst.High))
	}
	line := "set service " + name(svc.Name) + " protocol " + proto.String() + " port " + strings.Join(dst, ",")
	if !src.IsAny() {
		line += " source-port " + portText(src.Low, src.High)
	}
	return []string{line}, nil
}

func renderExtend(c design.ExtendRule) (do, undo []string, err error) {
	attr := map[design.Field]string{design.FieldSource: "source", design.FieldDestination: "destination", design.FieldService: "service"}[c.Field]
	if attr == "" {
		return nil, nil, fmt.Errorf("paloalto: extend rule %s: field %s", c.RuleID, c.Field)
	}
	prefix := "rulebase security rules " + name(c.RuleID) + " " + attr + " "
	return []string{"set " + prefix + list(c.Names)}, []string{"delete " + prefix + list(c.Names)}, nil
}

func renderRule(c design.AddRule) []string {
	r := c.Rule
	p := "set rulebase security rules " + name(r.ID) + " "
	action := map[firemon.Action]string{firemon.ActionPermit: "allow", firemon.ActionDeny: "deny"}[r.Action]
	services := r.Services
	if len(services) == 0 {
		services = []string{"any"}
	}
	out := []string{
		p + "from " + list(orAny(r.From)),
		p + "to " + list(orAny(r.To)),
		p + "source " + list(orAny(refNames(r.Source))),
		p + "destination " + list(orAny(refNames(r.Destination))),
		p + "application any",
		p + "service " + list(services),
		p + "action " + action,
	}
	if r.Description != "" {
		out = append(out, p+"description "+strconv.Quote(r.Description))
	}
	if r.Schedule != "" {
		out = append(out, p+"schedule "+name(r.Schedule))
	}
	if c.Before != "" {
		out = append(out, "move rulebase security rules "+name(r.ID)+" before "+name(c.Before))
	}
	return out
}

func refNames(refs []firemon.AddressRef) []string {
	out := make([]string, len(refs))
	for i, r := range refs {
		out[i] = r.Name
	}
	return out
}

func orAny(values []string) []string {
	if len(values) == 0 {
		return []string{"any"}
	}
	return values
}

// list writes one value or a bracketed list.
func list(values []string) string {
	if len(values) == 1 {
		return name(values[0])
	}
	quoted := make([]string, len(values))
	for i, v := range values {
		quoted[i] = name(v)
	}
	return "[ " + strings.Join(quoted, " ") + " ]"
}

// name quotes a name that contains spaces.
func name(s string) string {
	if strings.ContainsAny(s, " \t\"") {
		return strconv.Quote(s)
	}
	return s
}

func portText(lo, hi uint16) string {
	if lo == hi {
		return strconv.Itoa(int(lo))
	}
	return strconv.Itoa(int(lo)) + "-" + strconv.Itoa(int(hi))
}

// DeployCommands returns the rendered commands as one candidate batch: the
// deployment session commits it atomically, so it is a single write.
func DeployCommands(s design.Script) []string {
	if len(s.Commands) == 0 {
		return nil
	}
	return []string{strings.Join(s.Commands, "\n")}
}

// maxNameLength is the PAN-OS limit for object and rule names.
const maxNameLength = 63

// Naming returns the design naming policy for PAN-OS: names may hold
// letters, digits, '.', '_', '-' and spaces, up to 63 characters, so IPv6
// colons and prefix slashes become '_'.
func Naming() design.Naming {
	return design.Naming{Sanitize: func(name string) string {
		b := []byte(name)
		for i, c := range b {
			ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-' || c == ' '
			if !ok {
				b[i] = '_'
			}
		}
		if len(b) > maxNameLength {
			b = b[:maxNameLength]
		}
		return string(b)
	}}
}
