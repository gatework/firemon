package migrate

import (
	"strconv"
	"strings"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/design"
	"github.com/gatework/firemon/traffic"
)

// ruleResult is the translation of one source rule.
type ruleResult struct {
	rules    []firemon.SecurityRule
	fidelity Fidelity
	notes    []string
}

func (r *ruleResult) approximate(note string) {
	r.notes = append(r.notes, note)
	r.fidelity = max(r.fidelity, FidelityApproximate)
}

func (r *ruleResult) untranslatable(note string) {
	r.notes = append(r.notes, note)
	r.fidelity = FidelityUntranslatable
}

// rules translates the rulebase in order. A rule the target cannot express
// is carried over disabled, with the reason in its description.
func (tr *translator) rules() {
	tr.ruleMap = map[string][]string{}
	compiled := tr.fw.Rules() // by position: rule IDs may repeat
	for i, src := range tr.src.Rules {
		if src.Incomplete != "" {
			tr.item(ItemKindRule, src.ID, FidelityExact, "ignored by the source device ("+src.Incomplete+"); not carried over")
			continue
		}
		res := tr.rule(src, compiled[i])
		var ids []string
		for _, r := range res.rules {
			if res.fidelity == FidelityUntranslatable {
				r.Disabled = true
				r.Description = strings.TrimSpace("[migrate: " + strings.Join(res.notes, "; ") + "] " + r.Description)
			}
			r.ID = tr.ruleID(src, len(ids))
			if tr.t.Vendor == firemon.VendorPaloAlto {
				r.Name = r.ID
			}
			tr.out.Rules = append(tr.out.Rules, r)
			tr.changes.rules = append(tr.changes.rules, design.AddRule{Rule: r})
			ids = append(ids, r.ID)
		}
		if res.fidelity != FidelityUntranslatable {
			tr.ruleMap[src.ID] = ids
		}
		tr.item(ItemKindRule, src.ID, max(res.fidelity, FidelityExact), strings.Join(res.notes, "; "), ids...)
	}
}

// ruleID returns the target identifier of the n-th rule made from src.
func (tr *translator) ruleID(src firemon.SecurityRule, n int) string {
	if tr.caps.NumericRuleIDs {
		return strconv.Itoa(len(tr.out.Rules) + 1)
	}
	base := src.Name
	if base == "" {
		base = "rule-" + src.ID
	}
	if n > 0 {
		base += "-" + strconv.Itoa(n+1)
	}
	return tr.names.fresh(nsRule, base)
}

func (tr *translator) rule(src firemon.SecurityRule, compiled *firemon.Rule) ruleResult {
	res := ruleResult{fidelity: FidelityExact}
	out := firemon.SecurityRule{
		Name: src.Name, Description: src.Description, From: tr.zones(src.From), To: tr.zones(src.To),
		Action: src.Action, Disabled: src.Disabled, Log: src.Log, Applications: nil,
	}
	if tr.caps.NumericRuleIDs && out.Name == "" {
		out.Name = src.ID
	}
	out.Source = tr.operands(&res, src.Source, src.NegateSource, compiled, "source", src.ID)
	out.Destination = tr.operands(&res, src.Destination, src.NegateDestination, compiled, "destination", src.ID)
	if tr.caps.NegateAddresses {
		out.NegateSource, out.NegateDestination = src.NegateSource, src.NegateDestination
	}
	tr.ruleServices(&res, &out, src)
	tr.ruleApplications(&res, &out, src)
	tr.ruleTime(&res, &out, src)
	for _, u := range src.Unsupported {
		res.untranslatable("criterion not translated: " + u)
	}
	if src.Group != "" {
		res.notes = append(res.notes, "rule group "+tr.groupName(src.Group)+" not carried over")
	}
	res.rules = tr.scoped(&res, out, src.Scope)
	return res
}

func (tr *translator) groupName(id string) string {
	for _, g := range tr.src.RuleGroups {
		if g.ID == id {
			return g.Name
		}
	}
	return id
}

// operands translates one address side. Negation the target lacks becomes
// an object of the complement, taken from the compiled source rule.
func (tr *translator) operands(res *ruleResult, refs []firemon.AddressRef, negate bool, compiled *firemon.Rule, side, ruleID string) []firemon.AddressRef {
	if negate && !tr.caps.NegateAddresses {
		if compiled == nil || !compiled.Decidable() {
			res.untranslatable("negated " + side + " cannot be resolved exactly")
			return nil
		}
		set := compiled.Match().Src
		if side == "destination" {
			set = compiled.Match().Dst
		}
		name := tr.names.fresh(nsAddress, "NOT_"+ruleID+"_"+side)
		a := firemon.Address{Name: name, Description: "complement of the negated " + side + " of rule " + ruleID, Entries: entriesOf(set)}
		tr.out.Addresses = append(tr.out.Addresses, a)
		tr.changes.addresses = append(tr.changes.addresses, design.AddAddress{Address: a})
		res.notes = append(res.notes, "negated "+side+" written as its complement "+name)
		return []firemon.AddressRef{firemon.NamedAddress(name)}
	}
	var out []firemon.AddressRef
	for _, ref := range refs {
		switch {
		case ref.IsInline() && ref.Entry.Kind == firemon.AddressKindFQDN && !tr.caps.InlineFQDN:
			if isWildcard(ref.Entry) && !tr.caps.WildcardFQDN {
				res.untranslatable("wildcard domain " + ref.Entry.FQDN + " has no address object form")
				continue
			}
			name := tr.names.fresh(nsAddress, ref.Entry.FQDN)
			a := firemon.Address{Name: name, Entries: []firemon.AddressEntry{ref.Entry}}
			tr.out.Addresses = append(tr.out.Addresses, a)
			tr.changes.addresses = append(tr.changes.addresses, design.AddAddress{Address: a})
			out = append(out, firemon.NamedAddress(name))
		case ref.IsInline():
			out = append(out, ref)
		default:
			r, ok := tr.addressRef(res, ref.Name)
			if ok && r == nil {
				return nil // a predefined any: the whole side is any
			}
			if ok {
				out = append(out, *r)
			}
		}
	}
	return out
}

// addressRef translates a named address; nil with ok means any.
func (tr *translator) addressRef(res *ruleResult, name string) (*firemon.AddressRef, bool) {
	if reason, bad := tr.broken[nsAddress][name]; bad {
		res.untranslatable(name + ": " + reason)
		return nil, false
	}
	if t, ok := tr.names.lookup(nsAddress, name); ok {
		ref := firemon.NamedAddress(t)
		return &ref, true
	}
	// A predefined source object, such as StoneOS Any.
	set, ok := tr.fw.Address(name)
	switch {
	case !ok:
		res.untranslatable("address " + name + " cannot be resolved")
		return nil, false
	case set.Equal(traffic.AnyAddress()):
		return nil, true
	}
	tr.address(name, "predefined "+name+" on the source", entriesOf(set), false)
	t, _ := tr.names.lookup(nsAddress, name)
	ref := firemon.NamedAddress(t)
	return &ref, true
}

func (tr *translator) ruleServices(res *ruleResult, out *firemon.SecurityRule, src firemon.SecurityRule) {
	for _, s := range src.Services {
		if set, ok := tr.fw.Service(s); ok && set.IsAny() {
			out.Services = nil // a predefined any: the whole field is any
			return
		}
		name, why, ok := tr.serviceName(s)
		switch {
		case !ok:
			res.untranslatable("service " + s + ": " + why)
		case why != "":
			res.approximate(why)
			out.Services = append(out.Services, name)
		default:
			out.Services = append(out.Services, name)
		}
	}
	if len(src.ServiceEntries) > 0 {
		if tr.caps.InlineServices {
			out.ServiceEntries = src.ServiceEntries
		} else {
			name := "inline-" + src.ID
			tr.service(name, "inline services of rule "+src.ID, src.ServiceEntries, false)
			if t, ok := tr.names.lookup(nsService, name); ok {
				out.Services = append(out.Services, t)
			} else {
				res.untranslatable("inline services of the rule have no target form")
			}
		}
	}
	if src.ApplicationDefault {
		if tr.caps.ApplicationDefault {
			out.ApplicationDefault = true
		} else {
			res.approximate("application-default dropped: the applications match on any port")
		}
	}
}

func (tr *translator) ruleApplications(res *ruleResult, out *firemon.SecurityRule, src firemon.SecurityRule) {
	for _, a := range src.Applications {
		t, ok := tr.m.Applications[a]
		if !ok {
			res.untranslatable("application " + a + " has no mapping")
			continue
		}
		out.Applications = append(out.Applications, t)
	}
}

// ruleTime carries the schedule and the validity window; a window the
// target cannot hold inline becomes a schedule.
func (tr *translator) ruleTime(res *ruleResult, out *firemon.SecurityRule, src firemon.SecurityRule) {
	if src.Schedule != "" {
		if reason, bad := tr.broken[nsSchedule][src.Schedule]; bad {
			res.untranslatable("schedule " + src.Schedule + ": " + reason)
		} else {
			name, ok := tr.names.lookup(nsSchedule, src.Schedule)
			if !ok {
				// Without its schedule the rule would apply all the time.
				res.untranslatable("schedule " + src.Schedule + " is not defined on the source")
			}
			out.Schedule = name
		}
	}
	if src.Window == (firemon.TimeWindow{}) {
		return
	}
	switch {
	case tr.caps.RuleWindows:
		out.Window = src.Window
	case src.Schedule != "":
		res.untranslatable("a rule with both a schedule and a validity window")
	case src.Window.Start.IsZero():
		res.untranslatable("a validity window without a start")
	default:
		s, reason, f := tr.schedule(firemon.Schedule{Windows: []firemon.TimeWindow{src.Window}})
		if f == FidelityUntranslatable {
			res.untranslatable(reason)
			return
		}
		s.Name = tr.names.fresh(nsSchedule, "window-"+src.ID)
		s.Description = "validity of rule " + src.ID
		tr.out.Schedules = append(tr.out.Schedules, s)
		tr.changes.schedules = append(tr.changes.schedules, design.AddSchedule{Schedule: s})
		out.Schedule = s.Name
		if f == FidelityApproximate {
			res.approximate(reason)
		}
	}
}

// scoped writes a rule-type the target lacks as explicit zone pairs.
func (tr *translator) scoped(res *ruleResult, r firemon.SecurityRule, scope firemon.ZoneScope) []firemon.SecurityRule {
	if scope == firemon.ZoneScopeAny || tr.caps.RuleTypes {
		r.Scope = scope
		return []firemon.SecurityRule{r}
	}
	from, to := r.From, r.To
	all := tr.allZones()
	if len(from) == 0 {
		from = all
	}
	if len(to) == 0 {
		to = all
	}
	var out []firemon.SecurityRule
	for _, f := range from {
		for _, t := range to {
			if (scope == firemon.ZoneScopeIntra) != (f == t) {
				continue
			}
			p := r
			p.From, p.To = []string{f}, []string{t}
			out = append(out, p)
		}
	}
	res.notes = append(res.notes, "rule-type "+scope.String()+" written as "+strconv.Itoa(len(out))+" zone pairs")
	return out
}

func (tr *translator) allZones() []string {
	out := make([]string, 0, len(tr.out.Zones))
	for _, z := range tr.out.Zones {
		out = append(out, z.Name)
	}
	return out
}

// defaults makes the source's default actions explicit where the target's
// differ, as last rules.
func (tr *translator) defaults() {
	src, dst := tr.src.Semantics, tr.t.Semantics
	add := func(scope firemon.ZoneScope, action firemon.Action, what string) {
		res := ruleResult{fidelity: FidelityExact}
		base := firemon.SecurityRule{Name: "migrated " + what + " default", Action: action, Description: "the source device's " + what + " default action"}
		rules := tr.scoped(&res, base, scope)
		var ids []string
		for _, r := range rules {
			r.ID = tr.ruleID(firemon.SecurityRule{ID: what + "-default", Name: "migrated-" + what + "-default"}, len(ids))
			if tr.t.Vendor == firemon.VendorPaloAlto {
				r.Name = r.ID
			}
			tr.out.Rules = append(tr.out.Rules, r)
			tr.changes.rules = append(tr.changes.rules, design.AddRule{Rule: r})
			ids = append(ids, r.ID)
		}
		tr.item(ItemKindDefault, what, FidelityExact, "the target's default differs: "+action.String()+" made explicit", ids...)
	}
	if src.IntrazoneAction != dst.IntrazoneAction && src.IntrazoneAction != firemon.ActionUnset {
		add(firemon.ZoneScopeIntra, src.IntrazoneAction, "intrazone")
	}
	if src.InterzoneAction != dst.InterzoneAction && src.InterzoneAction != firemon.ActionUnset {
		add(firemon.ZoneScopeInter, src.InterzoneAction, "interzone")
	}
}
