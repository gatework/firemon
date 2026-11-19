package paloalto

import (
	"net/netip"
	"slices"
	"strings"

	"github.com/gatework/firemon"
)

// rulebase records security and NAT rule statements for the second pass:
//
//	rulebase security rules NAME ATTRIBUTE VALUE...
//	rulebase nat rules NAME ATTRIBUTE VALUE...
//	rulebase default-security-rules rules intrazone-default|interzone-default action A
func (s *state) rulebase(p *path, st statement) {
	switch base := p.next(); base {
	case "security", "nat":
		if p.next() != "rules" {
			return
		}
		name := p.next()
		book := s.security
		if base == "nat" {
			book = s.nat
		}
		book.add(name, st.first, p.value())
	case "default-security-rules":
		s.defaultRules(p)
	default:
		// pbf, qos, dos, decryption, authentication, application-override,
		// tunnel-inspect, ...: pbf is modelled; for the others only their
		// references to objects matter.
		if p.next() != "rules" {
			return
		}
		name := p.next()
		book := s.pbf
		if base != "pbf" {
			if s.others[base] == nil {
				s.others[base] = newRulebook()
			}
			book = s.others[base]
		}
		book.add(name, st.first, p.value())
	}
}

// buildSecurityRules materializes the security rule drafts in order.
func (s *state) buildSecurityRules() {
	for _, d := range s.security.drafts {
		// PAN-OS logs at session end unless the rule says log-end no.
		r := firemon.SecurityRule{ID: d.name, Name: d.name, Log: firemon.Logging{End: true}}
		for _, attr := range d.attrs {
			s.securityAttribute(&r, attr)
		}
		if r.Scope == firemon.ZoneScopeIntra && len(r.To) == 0 {
			r.To = slices.Clone(r.From) // intrazone rules leave "to" implied
		}
		s.cfg.Rules = append(s.cfg.Rules, r)
	}
}

func (s *state) securityAttribute(r *firemon.SecurityRule, attr []string) {
	if len(attr) == 0 {
		return
	}
	key, values := attr[0], attr[1:]
	switch key {
	case "from":
		r.From = append(r.From, anyless(values)...)
	case "to":
		r.To = append(r.To, anyless(values)...)
	case "source":
		r.Source = append(r.Source, s.operands(values)...)
		s.externalOperands(r, values)
	case "destination":
		r.Destination = append(r.Destination, s.operands(values)...)
		s.externalOperands(r, values)
	case "service":
		for _, v := range anyless(values) {
			if v == "application-default" {
				r.ApplicationDefault = true
				continue
			}
			r.Services = append(r.Services, v)
		}
	case "application":
		r.Applications = append(r.Applications, anyless(values)...)
	case "action":
		r.Action = securityAction(strings.Join(values, " "))
	case "disabled":
		r.Disabled = yes(values)
	case "negate-source":
		r.NegateSource = yes(values)
	case "negate-destination":
		r.NegateDestination = yes(values)
	case "schedule":
		r.Schedule = strings.Join(values, " ")
	case "description":
		r.Description = strings.Join(values, " ")
	case "rule-type":
		switch strings.Join(values, " ") {
		case "intrazone":
			r.Scope = firemon.ZoneScopeIntra
		case "interzone":
			r.Scope = firemon.ZoneScopeInter
		}
	case "log-start":
		r.Log.Start = yes(values)
	case "log-end":
		r.Log.End = yes(values)
	case "log-setting":
		r.Log.Setting = strings.Join(values, " ")
	case "group-tag":
		r.Group = strings.Join(values, " ")
	case "source-user", "category", "source-hip", "destination-hip", "source-imei", "source-imsi", "source-nw-slice":
		if vs := anyless(values); len(vs) > 0 {
			r.Unsupported = append(r.Unsupported, key+" "+strings.Join(vs, ","))
		}
	}
}

// buildNATRules materializes the NAT rule drafts. A static-ip translation
// marked bi-directional becomes a static NAT; every other rule becomes an
// ordered dynamic NAT, one per translated side.
func (s *state) buildNATRules() {
	for i, d := range s.nat.drafts {
		n := firemon.DynamicNAT{ID: d.name, Name: d.name, Precedence: i + 1}
		var src, dst firemon.Translation
		bidirectional := false
		for _, attr := range d.attrs {
			if len(attr) == 0 {
				continue
			}
			key, values := attr[0], attr[1:]
			switch key {
			case "from":
				n.From = append(n.From, anyless(values)...)
			case "to":
				n.To = append(n.To, anyless(values)...)
			case "source":
				n.Source = append(n.Source, s.operands(values)...)
			case "destination":
				n.Destination = append(n.Destination, s.operands(values)...)
			case "service":
				n.Services = append(n.Services, anyless(values)...)
			case "to-interface":
				if v := strings.Join(values, " "); v != "any" {
					n.Egress = v
				}
			case "disabled":
				n.Disabled = yes(values)
			case "description":
				n.Description = strings.Join(values, " ")
			case "nat-type":
				if t := strings.Join(values, " "); t != "ipv4" {
					n.Unsupported = append(n.Unsupported, "nat-type "+t)
				}
			case "source-translation":
				// fallback addresses apply when the pool runs out and a
				// floating IP follows HA state: neither is in the model.
				for _, v := range values {
					if v == "fallback" || v == "floating-ip" {
						n.Unsupported = append(n.Unsupported, "source-translation "+strings.Join(values, " "))
						break
					}
				}
				bidirectional = s.sourceTranslation(&src, values) || bidirectional
			case "destination-translation", "dynamic-destination-translation":
				s.destinationTranslation(&dst, values)
			}
		}
		s.emitNAT(n, src, dst, bidirectional)
	}
}

// emitNAT records one PAN-OS NAT rule. The rulebase is a single
// first-match list, so the rule keeps both translations; a rule without
// translation exempts traffic. A bi-directional static-ip rule also adds
// its reverse half as an inbound-only static mapping at the same precedence.
func (s *state) emitNAT(n firemon.DynamicNAT, src, dst firemon.Translation, bidirectional bool) {
	if src.Mode == firemon.TranslationModeUnset && dst.Mode == firemon.TranslationModeUnset {
		src.Mode, dst.Mode = firemon.TranslationModeNone, firemon.TranslationModeNone
	}
	n.TranslatedSource, n.TranslatedDestination = src, dst
	s.cfg.DynamicNATs = append(s.cfg.DynamicNATs, n)
	if bidirectional && (len(n.Source) != 1 || len(src.Addresses) != 1) {
		s.cfg.Diagnostics = append(s.cfg.Diagnostics, firemon.Diagnostic{Text: "nat rule " + n.Name + " bi-directional",
			Reason: "bi-directional static NAT with several or any sources: the reverse mapping is not modelled"})
	}
	if bidirectional && len(n.Source) == 1 && len(src.Addresses) == 1 {
		s.cfg.StaticNATs = append(s.cfg.StaticNATs, firemon.StaticNAT{
			ID: n.ID, Name: n.Name, Real: n.Source[0], Mapped: src.Addresses[0], Zones: slices.Clone(n.To),
			Disabled: n.Disabled, Precedence: n.Precedence, InboundOnly: true,
		})
	}
}

// sourceTranslation parses the words after "source-translation" and
// reports whether the rule is a bi-directional static mapping:
//
//	dynamic-ip-and-port interface-address interface IF [ip A]
//	dynamic-ip-and-port translated-address [ ADDRS ]
//	dynamic-ip translated-address [ ADDRS ]
//	static-ip translated-address A [bi-directional yes|no]
func (s *state) sourceTranslation(t *firemon.Translation, values []string) bool {
	if len(values) < 2 {
		return false
	}
	t.PortTranslation = values[0] == "dynamic-ip-and-port"
	rest := values[1:]
	switch rest[0] {
	case "interface-address":
		if t.Mode != firemon.TranslationModeAddress {
			t.Mode = firemon.TranslationModeInterface
		}
		if len(rest) >= 3 && rest[1] == "interface" {
			t.Interface = rest[2]
		}
		if len(rest) >= 3 && rest[1] == "ip" {
			// The interface address is written with the interface mask
			// (103.24.178.130/28): it is one host, not the subnet.
			t.Mode = firemon.TranslationModeAddress
			t.Addresses = s.operands(s.hostAddresses(rest[2:]))
		}
	case "translated-address":
		t.Mode = firemon.TranslationModeAddress
		t.Addresses = append(t.Addresses, s.operands(rest[1:])...)
	case "bi-directional":
		return len(rest) > 1 && rest[1] == "yes"
	}
	return false
}

// destinationTranslation parses translated-address A | translated-port N.
func (s *state) destinationTranslation(t *firemon.Translation, values []string) {
	if len(values) < 2 {
		return
	}
	switch values[0] {
	case "translated-address":
		t.Mode = firemon.TranslationModeAddress
		t.Addresses = s.operands(values[1:])
	case "translated-port":
		if p, err := parseUint32(values[1]); err == nil && p <= 0xffff {
			t.Port = uint16(p)
		}
	}
}

// operands classifies rule address values: object and group names first,
// then inline addresses, prefixes and ranges. Unknown names stay named so
// compilation reports them.
func (s *state) operands(values []string) []firemon.AddressRef {
	var out []firemon.AddressRef
	for _, v := range anyless(values) {
		_, isAddr := s.addresses[v]
		_, isGroup := s.groups[v]
		if !isAddr && !isGroup {
			if e, ok := inlineEntry(v); ok {
				out = append(out, firemon.InlineAddress(e))
				continue
			}
		}
		out = append(out, firemon.NamedAddress(v))
	}
	return out
}

// externalOperands notes the operands that are external lists or regions:
// their addresses are not in the configuration, so the side stays
// undecidable (they do not resolve) and the rule says why.
func (s *state) externalOperands(r *firemon.SecurityRule, values []string) {
	for _, v := range anyless(values) {
		if kind := s.externalKind(v); kind != "" {
			r.Unsupported = append(r.Unsupported, kind+" "+v)
		}
	}
}

// externalKind is "external-list" or "region" for such a name; a
// two-letter code no object defines is a predefined region.
func (s *state) externalKind(name string) string {
	if kind, ok := s.external[name]; ok {
		return kind
	}
	_, isAddr := s.addresses[name]
	_, isGroup := s.groups[name]
	if !isAddr && !isGroup && len(name) == 2 && strings.ToUpper(name) == name && strings.Trim(name, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") == "" {
		return "region"
	}
	return ""
}

func securityAction(text string) firemon.Action {
	switch text {
	case "allow":
		return firemon.ActionPermit
	case "deny", "drop", "reset-client", "reset-server", "reset-both":
		return firemon.ActionDeny
	default:
		return firemon.ActionUnset
	}
}

// anyless drops the "any" keyword: an empty list means any.
func anyless(values []string) []string {
	return slices.DeleteFunc(slices.Clone(values), func(v string) bool { return v == "any" })
}

func yes(values []string) bool { return len(values) == 1 && values[0] == "yes" }

// hostAddresses rewrites interface addresses written with their mask to
// the host itself; object names pass unchanged.
func (s *state) hostAddresses(values []string) []string {
	out := make([]string, len(values))
	for i, v := range values {
		out[i] = v
		if raw, ok := s.hostBits[v]; ok {
			// An address object written with the interface mask names
			// the interface address too.
			v = raw
		}
		if p, err := netip.ParsePrefix(v); err == nil {
			out[i] = netip.PrefixFrom(p.Addr(), p.Addr().BitLen()).String()
		}
	}
	return out
}

// defaultRules reads the actions of the predefined intrazone and interzone
// default rules.
func (s *state) defaultRules(p *path) {
	if p.next() != "rules" {
		return
	}
	rule := p.next()
	if p.next() != "action" {
		return
	}
	action := securityAction(p.scalar())
	switch rule {
	case "intrazone-default":
		s.cfg.Semantics.IntrazoneAction = action
	case "interzone-default":
		s.cfg.Semantics.InterzoneAction = action
	}
}
