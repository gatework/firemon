package hillstone

import (
	"slices"
	"strings"

	"github.com/gatework/firemon"
)

// anyName is the StoneOS predefined object meaning every zone, address
// or service.
const anyName = "Any"

// rule parses a top-level policy rule:
//
//	rule id N
//	  action permit|deny | disable | name "N" | description "D"
//	  src-zone "Z" | dst-zone "Z"
//	  src-addr "A" | src-ip PREFIX | src-range A B | src-host "FQDN" (and dst-)
//	  service "S" | application "APP" | schedule "S"
//	  start-time M/D/YYYY HH:MM:SS | expire-time M/D/YYYY HH:MM:SS
//	  aggregate-type | aggregate-rule N | log ... | av/ips/url profiles
//
// A rule with aggregate-type is a rule-group header; it names the group of
// the rules that reference it with aggregate-rule and is not itself a rule.
func (s *state) rule(b block, head *words) { s.ruleIn(b, head, nil, nil) }

// policy parses the legacy zone-pair form, whose rules inherit its zones:
//
//	policy from "ZONE" to "ZONE"
//	  rule id N
//	    ...
//	  exit
//	exit
func (s *state) policy(b block, head *words) {
	var from, to []string
	for !head.done() {
		switch head.next() {
		case "from":
			from = []string{head.next()}
		case "to":
			to = []string{head.next()}
		}
	}
	for i := 0; i < len(b.body); i++ {
		w := newWords(b.body[i].Text)
		if w.next() != "rule" {
			continue
		}
		sub := block{head: b.body[i]}
		for i++; i < len(b.body) && strings.TrimSpace(b.body[i].Text) != "exit"; i++ {
			sub.body = append(sub.body, b.body[i])
		}
		s.mark(sub.head)
		if i < len(b.body) {
			s.mark(b.body[i])
		}
		s.ruleIn(sub, w, from, to)
	}
}

// ruleIn parses one rule; from and to are the zones of an enclosing policy
// block, used when the rule names none.
func (s *state) ruleIn(b block, head *words, from, to []string) {
	if head.next() != "id" {
		return
	}
	r := firemon.SecurityRule{ID: head.next()}
	header := false
	for _, l := range b.body {
		w := newWords(l.Text)
		kw := w.next()
		switch {
		case kw == "aggregate-type":
			header = true
		case kw == "aggregate-rule":
			r.Group = w.next()
		case strings.HasPrefix(kw, "src-") || strings.HasPrefix(kw, "dst-"):
			if !s.ruleOperand(&r, kw, w) {
				// An operand the model cannot read narrows the rule on the
				// device; never let it widen the model.
				s.diagnose(l, "invalid rule operand")
				r.Unsupported = append(r.Unsupported, "unparsed "+strings.TrimSpace(l.Text))
				continue
			}
		case !s.ruleAttribute(&r, kw, w):
			r.Unsupported = append(r.Unsupported, "unrecognized "+strings.TrimSpace(l.Text))
			continue
		}
		s.mark(l)
	}
	if header {
		name := firstNonEmpty(r.Name, "rule group "+r.ID)
		s.ruleGroup[r.ID] = name
		s.cfg.RuleGroups = append(s.cfg.RuleGroups, firemon.RuleGroup{ID: r.ID, Name: name})
		return
	}
	if len(r.From) == 0 {
		r.From = from
	}
	if len(r.To) == 0 {
		r.To = to
	}
	r.From, r.To = anyZones(r.From), anyZones(r.To)
	if r.Incomplete = incomplete(r); r.Incomplete != "" {
		s.diagnose(b.head, "incomplete rule, ignored by the device: "+r.Incomplete)
	}
	s.ruleIndex[r.ID] = len(s.cfg.Rules)
	s.cfg.Rules = append(s.cfg.Rules, r)
}

// ruleAttribute handles non-operand rule lines and reports whether kw was
// recognized.
func (s *state) ruleAttribute(r *firemon.SecurityRule, kw string, w *words) bool {
	switch kw {
	case "action":
		r.Action = ruleAction(w.next())
		if r.Action == firemon.ActionUnset {
			r.Unsupported = append(r.Unsupported, "action "+w.rest())
		}
	case "disable":
		r.Disabled = true
	case "name":
		r.Name = w.next()
	case "description":
		r.Description = w.next()
	case "service":
		r.Services = append(r.Services, w.next())
	case "application":
		r.Applications = append(r.Applications, w.next())
	case "schedule":
		r.Schedule = w.next()
	case "start-time", "expire-time":
		t, ok := s.dateTime(w)
		if !ok {
			r.Unsupported = append(r.Unsupported, "invalid "+kw)
			break
		}
		if kw == "start-time" {
			r.Window.Start = t
		} else {
			r.Window.End = t
		}
	case "log":
		r.Log = true
	case "service-rule":
		e, ok := inlineService(w)
		if !ok {
			r.Unsupported = append(r.Unsupported, kw+" "+w.rest())
			break
		}
		r.ServiceEntries = append(r.ServiceEntries, e)
	case "domain-book", "vlan-id", "user", "role", "usergroup":
		r.Unsupported = append(r.Unsupported, kw+" "+w.rest())
	case "av", "ips", "url", "assistant", "sandbox", "wbl", "spam", "ssl-proxy", "qos-tag", "session-limit":
		// Security profiles inspect allowed traffic; they do not change matching.
	default:
		return false
	}
	return true
}

func (s *state) ruleOperand(r *firemon.SecurityRule, kw string, w *words) bool {
	side, kind, _ := strings.Cut(kw, "-")
	switch kind {
	case "zone":
		z := w.next()
		if side == "src" {
			r.From = append(r.From, z)
		} else {
			r.To = append(r.To, z)
		}
		return true
	case "addr", "ip", "range", "host":
	default:
		return false
	}
	var ref firemon.AddressRef
	if kind == "addr" {
		ref = firemon.NamedAddress(w.next())
	} else {
		e, ok := addressEntry(kind, w)
		if !ok {
			return false
		}
		ref = firemon.InlineAddress(e)
	}
	if side == "src" {
		r.Source = append(r.Source, ref)
	} else {
		r.Destination = append(r.Destination, ref)
	}
	return true
}

func ruleAction(text string) firemon.Action {
	switch text {
	case "permit":
		return firemon.ActionPermit
	case "deny", "reject":
		return firemon.ActionDeny
	default:
		return firemon.ActionUnset
	}
}

// anyZones returns nil, meaning every zone, when zones contains "Any".
func anyZones(zones []string) []string {
	if slices.Contains(zones, anyName) {
		return nil
	}
	return zones
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// incomplete returns which required part a rule lacks. StoneOS only
// enforces a rule that has an action, a source, a destination and a
// service or application; the running configuration still lists rules
// created without them.
func incomplete(r firemon.SecurityRule) string {
	var missing []string
	if r.Action == firemon.ActionUnset && !slices.ContainsFunc(r.Unsupported, func(u string) bool { return strings.HasPrefix(u, "action ") }) {
		missing = append(missing, "action")
	}
	// An operand the parser could not read is still present on the device.
	unread := func(prefix string) bool {
		return slices.ContainsFunc(r.Unsupported, func(u string) bool { return strings.HasPrefix(u, "unparsed "+prefix) })
	}
	if len(r.Source) == 0 && !unread("src-") {
		missing = append(missing, "source")
	}
	if len(r.Destination) == 0 && !unread("dst-") {
		missing = append(missing, "destination")
	}
	if len(r.Services) == 0 && len(r.ServiceEntries) == 0 && len(r.Applications) == 0 {
		missing = append(missing, "service")
	}
	if len(missing) == 0 {
		return ""
	}
	return "no " + strings.Join(missing, ", ")
}
