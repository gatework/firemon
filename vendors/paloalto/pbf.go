package paloalto

import (
	"maps"
	"net/netip"
	"slices"
	"strings"

	"github.com/gatework/firemon"
)

// pbfPolicyID is the entry ID of a PBF rule: every PBF rule is its own
// policy, bound to its own source zones or interfaces, and the rules keep
// their order across policies.
const pbfPolicyID = "pbf"

// buildPBF materializes policy-based forwarding rules:
//
//	rulebase pbf rules NAME from zone [ Z ] | from interface [ IF ]
//	  source | destination | service | source-user | application
//	  negate-source | negate-destination yes
//	  action forward egress-interface IF | action forward nexthop ip-address A
//	  enforce-symmetric-return ... | disabled yes | description D
func (s *state) buildPBF() {
	for _, d := range s.pbf.drafts {
		r := firemon.PolicyRoute{Policy: d.name, ID: pbfPolicyID}
		for _, attr := range d.attrs {
			if len(attr) == 0 {
				continue
			}
			key, values := attr[0], attr[1:]
			switch key {
			case "from":
				s.pbfFrom(d.name, values)
			case "source":
				r.Source = append(r.Source, s.operands(values)...)
			case "destination":
				r.Destination = append(r.Destination, s.operands(values)...)
			case "service":
				r.Services = append(r.Services, anyless(values)...)
			case "source-user", "application":
				if vs := anyless(values); len(vs) > 0 {
					r.Conditions = append(r.Conditions, firemon.Criterion(criterionKind(key), key+" "+strings.Join(vs, ","), vs...))
				}
			case "negate-source":
				r.NegateSource = yes(values)
			case "negate-destination":
				r.NegateDestination = yes(values)
			case "action":
				s.pbfAction(&r, values)
			case "disabled":
				r.Disabled = yes(values)
			case "schedule":
				for _, v := range anyless(values) {
					s.cfg.ExternalUses = append(s.cfg.ExternalUses, firemon.ExternalUse{Site: firemon.UseSitePolicyRoute, ID: "pbf " + d.name, Kind: firemon.ObjectKindSchedule, Name: v})
				}
			}
		}
		r.VirtualRouter = s.ifaceVR[r.Interface]
		s.cfg.PolicyRoutes = append(s.cfg.PolicyRoutes, r)
	}
}

// pbfFrom binds the rule to its source zones or interfaces.
func (s *state) pbfFrom(policy string, values []string) {
	if len(values) < 2 {
		return
	}
	kind := values[0]
	for _, v := range anyless(values[1:]) {
		b := firemon.PolicyBinding{Policy: policy}
		if kind == "zone" {
			b.Zone = v
		} else {
			b.Interface = v
		}
		s.cfg.PolicyBindings = append(s.cfg.PolicyBindings, b)
	}
}

// pbfAction reads "forward egress-interface IF", "forward nexthop
// ip-address A" and their monitor settings; other actions (discard,
// no-pbf) cannot be modelled as a forwarding choice.
func (s *state) pbfAction(r *firemon.PolicyRoute, values []string) {
	if len(values) < 3 || values[0] != "forward" {
		if len(values) > 0 && values[0] != "forward" {
			r.Conditions = append(r.Conditions, firemon.Criterion(firemon.ConditionOther, "action "+strings.Join(values, " ")))
		}
		return
	}
	switch values[1] {
	case "egress-interface":
		r.Interface = values[2]
	case "nexthop":
		if len(values) >= 4 && values[2] == "ip-address" {
			if a, err := netip.ParseAddr(values[3]); err == nil {
				r.NextHop = a
			}
		}
	}
}

// externalUses records the objects the rulebases the model does not
// evaluate refer to (qos, dos, decryption, authentication,
// application-override, tunnel-inspect, ...).
func (s *state) externalUses() {
	for _, base := range slices.Sorted(maps.Keys(s.others)) {
		book := s.others[base]
		site := firemon.UseSiteQoS
		if base != "qos" {
			site = firemon.UseSiteOther
		}
		for _, d := range book.drafts {
			for _, attr := range d.attrs {
				s.externalAttr(site, base+" "+d.name, attr)
			}
		}
	}
}

// externalAttr records the object names of one rule attribute.
func (s *state) externalAttr(site firemon.UseSite, id string, attr []string) {
	if len(attr) == 0 {
		return
	}
	var kind firemon.ObjectKind
	switch attr[0] {
	case "source", "destination":
		kind = firemon.ObjectKindAddress
	case "service":
		kind = firemon.ObjectKindService
	case "schedule":
		kind = firemon.ObjectKindSchedule
	default:
		return
	}
	for _, v := range anyless(attr[1:]) {
		if v == "application-default" || (kind == firemon.ObjectKindAddress && !s.isAddressName(v)) {
			continue
		}
		s.cfg.ExternalUses = append(s.cfg.ExternalUses, firemon.ExternalUse{Site: site, ID: id, Kind: kind, Name: v})
	}
}

func (s *state) isAddressName(v string) bool {
	_, a := s.addresses[v]
	_, g := s.groups[v]
	return a || g
}
