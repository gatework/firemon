package hillstone

import (
	"net/netip"
	"strings"

	"github.com/gatework/firemon"
)

// pbrPolicy parses a policy-based routing policy:
//
//	pbr-policy "NAME" vrouter "VR"
//	  match id N
//	    src-addr "A" | src-ip P | dst-addr "A" | dst-ip P | service "S"
//	    nexthop A | disable | log enable | user-group "G"... | application "X"
//	  exit
//	exit
//
// Entries are evaluated in the order they appear.
func (s *state) pbrPolicy(b block, head *words) {
	name := head.next()
	vr := DefaultVirtualRouter
	if head.next() == "vrouter" {
		vr = head.next()
	}
	for i := 0; i < len(b.body); i++ {
		w := newWords(b.body[i].Text)
		if w.next() != "match" || w.next() != "id" {
			continue
		}
		r := firemon.PolicyRoute{Policy: name, ID: w.next(), VirtualRouter: vr}
		s.mark(b.body[i])
		for i++; i < len(b.body) && strings.TrimSpace(b.body[i].Text) != "exit"; i++ {
			if s.pbrLine(&r, b.body[i].Text) {
				s.mark(b.body[i])
			}
		}
		if i < len(b.body) {
			s.mark(b.body[i])
		}
		s.cfg.PolicyRoutes = append(s.cfg.PolicyRoutes, r)
	}
}

// pbrLine reads one attribute of a policy route and reports whether it was
// recognized; unrecognized criteria make the entry undecidable.
func (s *state) pbrLine(r *firemon.PolicyRoute, line string) bool {
	w := newWords(line)
	switch kw := w.next(); {
	case kw == "nexthop":
		hop, err := netip.ParseAddr(w.next())
		if err != nil {
			r.Unsupported = append(r.Unsupported, strings.TrimSpace(line))
			return false
		}
		r.NextHop = hop
	case kw == "disable":
		r.Disabled = true
	case kw == "log":
	case kw == "service":
		r.Services = append(r.Services, w.next())
	case kw == "schedule":
		// The entry applies only within the schedule, which the policy
		// route model does not hold; the schedule stays in use.
		name := w.next()
		r.Unsupported = append(r.Unsupported, "schedule "+name)
		s.cfg.ExternalUses = append(s.cfg.ExternalUses, firemon.ExternalUse{
			Site: firemon.UseSitePolicyRoute, ID: r.Policy + "/" + r.ID, Kind: firemon.ObjectKindSchedule, Name: name,
		})
	case strings.HasPrefix(kw, "src-") || strings.HasPrefix(kw, "dst-"):
		var rule firemon.SecurityRule
		if !s.ruleOperand(&rule, kw, w) || len(rule.From)+len(rule.To) > 0 {
			r.Unsupported = append(r.Unsupported, strings.TrimSpace(line))
			return false
		}
		r.Source = append(r.Source, rule.Source...)
		r.Destination = append(r.Destination, rule.Destination...)
	default:
		r.Unsupported = append(r.Unsupported, strings.TrimSpace(line))
	}
	return true
}

// bindPolicy records "bind pbr-policy NAME" in a zone or interface.
func (s *state) bindPolicy(w *words, zone, iface string) bool {
	if w.next() != "pbr-policy" {
		return false
	}
	s.cfg.PolicyBindings = append(s.cfg.PolicyBindings, firemon.PolicyBinding{Policy: w.next(), Zone: zone, Interface: iface})
	return true
}
