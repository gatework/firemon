package paloalto

import (
	"cmp"
	"errors"
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
		case design.AddAddressGroup:
			do = []string{"set address-group " + name(c.Group.Name) + " static " + bracket(c.Group.Members)}
			undo = []string{"delete address-group " + name(c.Group.Name)}
		case design.AddServiceGroup:
			do = []string{"set service-group " + name(c.Group.Name) + " members " + bracket(c.Group.Members)}
			undo = []string{"delete service-group " + name(c.Group.Name)}
		case design.ExtendRule:
			do, undo, err = renderExtend(c)
		case design.AddRule:
			do, err = renderRule(c)
			undo = []string{"delete rulebase security rules " + name(c.Rule.ID)}
		case design.AddNAT:
			do, err = renderNAT(c)
			undo = []string{"delete rulebase nat rules " + name(c.Rule.ID)}
		default:
			var ok bool
			if do, undo, ok, err = renderCleanup(ch); !ok {
				err = fmt.Errorf("paloalto: unsupported change %T", ch)
			}
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

// renderRule writes every attribute of a rule, so that a rule removed by a
// cleanup can be restored as it was.
func renderRule(c design.AddRule) ([]string, error) {
	r := c.Rule
	if len(r.ServiceEntries) > 0 || r.Window != (firemon.TimeWindow{}) {
		return nil, fmt.Errorf("paloalto: rule %s: inline services and validity windows need objects (service, schedule)", r.ID)
	}
	src, err1 := operandTexts(r.Source)
	dst, err2 := operandTexts(r.Destination)
	if err := errors.Join(err1, err2); err != nil {
		return nil, fmt.Errorf("paloalto: rule %s: %w", r.ID, err)
	}
	p := "set rulebase security rules " + name(r.ID) + " "
	action := map[firemon.Action]string{firemon.ActionPermit: "allow", firemon.ActionDeny: "deny"}[r.Action]
	services := r.Services
	if r.ApplicationDefault {
		services = append(slices.Clone(services), "application-default")
	}
	out := []string{
		p + "from " + list(orAny(r.From)),
		p + "to " + list(orAny(r.To)),
		p + "source " + list(orAny(src)),
		p + "destination " + list(orAny(dst)),
		p + "application " + list(orAny(r.Applications)),
		p + "service " + list(orAny(services)),
	}
	if action != "" {
		out = append(out, p+"action "+action)
	}
	out = append(out, ruleOptions(p, r)...)
	if c.Before != "" {
		out = append(out, "move rulebase security rules "+name(r.ID)+" before "+name(c.Before))
	}
	return out, nil
}

// ruleOptions writes the attributes that do not match addresses.
func ruleOptions(p string, r firemon.SecurityRule) []string {
	var out []string
	switch r.Scope {
	case firemon.ZoneScopeIntra:
		out = append(out, p+"rule-type intrazone")
	case firemon.ZoneScopeInter:
		out = append(out, p+"rule-type interzone")
	case firemon.ZoneScopeAny:
	}
	if r.NegateSource {
		out = append(out, p+"negate-source yes")
	}
	if r.NegateDestination {
		out = append(out, p+"negate-destination yes")
	}
	if r.Description != "" {
		out = append(out, p+"description "+strconv.Quote(r.Description))
	}
	if r.Schedule != "" {
		out = append(out, p+"schedule "+name(r.Schedule))
	}
	if r.Group != "" {
		out = append(out, p+"group-tag "+name(r.Group))
	}
	if r.Log {
		out = append(out, p+"log-end yes")
	}
	if r.Disabled {
		out = append(out, p+"disabled yes")
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

// bracket always writes a bracketed list, as group members require.
func bracket(values []string) string {
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

// renderNAT writes a NAT rule and moves it before c.Before: the NAT
// rulebase is one first-match list.
func renderNAT(c design.AddNAT) ([]string, error) {
	r := c.Rule
	p := "set rulebase nat rules " + name(r.ID) + " "
	src, err1 := operandTexts(r.Source)
	dst, err2 := operandTexts(r.Destination)
	if err := errors.Join(err1, err2); err != nil {
		return nil, fmt.Errorf("paloalto: nat rule %s: %w", r.ID, err)
	}
	egress := cmp.Or(r.Egress, "any")
	out := []string{
		p + "from " + list(orAny(r.From)),
		p + "to " + list(orAny(r.To)),
		p + "source " + list(orAny(src)),
		p + "destination " + list(orAny(dst)),
		p + "service " + list(orAny(r.Services)),
		p + "to-interface " + name(egress),
	}
	switch t := r.TranslatedSource; t.Mode {
	case firemon.TranslationModeInterface:
		out = append(out, p+"source-translation dynamic-ip-and-port interface-address interface "+name(t.Interface))
	case firemon.TranslationModeAddress:
		addrs, err := operandTexts(t.Addresses)
		if err != nil {
			return nil, fmt.Errorf("paloalto: nat rule %s: %w", r.ID, err)
		}
		kind := "dynamic-ip"
		switch {
		case c.Bidirectional:
			kind = "static-ip"
		case t.PortTranslation:
			kind = "dynamic-ip-and-port"
		}
		out = append(out, p+"source-translation "+kind+" translated-address "+list(addrs))
		if c.Bidirectional {
			out = append(out, p+"source-translation static-ip bi-directional yes")
		}
	case firemon.TranslationModeUnset, firemon.TranslationModeNone:
	}
	if t := r.TranslatedDestination; t.Mode == firemon.TranslationModeAddress {
		addrs, err := operandTexts(t.Addresses)
		if err != nil || len(addrs) != 1 {
			return nil, fmt.Errorf("paloalto: nat rule %s: one translated destination", r.ID)
		}
		out = append(out, p+"destination-translation translated-address "+name(addrs[0]))
		if t.Port != 0 {
			out = append(out, p+"destination-translation translated-port "+strconv.Itoa(int(t.Port)))
		}
	}
	if c.Before != "" {
		out = append(out, "move rulebase nat rules "+name(r.ID)+" before "+name(c.Before))
	}
	return out, nil
}

// operandTexts writes address references: object names, or inline
// addresses and ranges.
func operandTexts(refs []firemon.AddressRef) ([]string, error) {
	out := make([]string, 0, len(refs))
	for _, r := range refs {
		if !r.IsInline() {
			out = append(out, r.Name)
			continue
		}
		switch e := r.Entry; e.Kind {
		case firemon.AddressKindPrefix:
			out = append(out, e.Prefix.String())
		case firemon.AddressKindRange:
			out = append(out, e.From.String()+"-"+e.To.String())
		case firemon.AddressKindFQDN, firemon.AddressKindUnset:
			return nil, fmt.Errorf("cannot write %s entry inline", e.Kind)
		}
	}
	return out, nil
}
