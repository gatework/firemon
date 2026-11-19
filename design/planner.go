package design

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/query"
	"github.com/gatework/firemon/traffic"
)

// ErrUnverifiable reports that no candidate change passed verification.
var ErrUnverifiable = errors.New("design: no verifiable change")

// Planner designs plans for one firewall. It is safe for concurrent use.
type Planner struct {
	fw        *firemon.Firewall
	naming    Naming
	now       func() time.Time
	threshold int
}

// New returns a planner for fw.
func New(fw *firemon.Firewall, opts Options) *Planner {
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	threshold := opts.GroupThreshold
	if threshold == 0 {
		threshold = DefaultGroupThreshold
	}
	return &Planner{fw: fw, naming: opts.Naming.withDefaults(), now: now, threshold: threshold}
}

// need is what one zone pair must newly permit.
type need struct {
	from, to string
	region   traffic.Region // policy-space packets to open
	scope    traffic.Region // policy-space packets of the intent on this pair
	conflict traffic.Region // packets that must stay as they are: specific denies and undecidable parts
	before   *firemon.Rule  // first deny deciding the need; nil means end
}

// Plan designs the changes that permit intent and, when it asks for one,
// translate it. The NAT part comes first: access is then designed on the
// configuration with the NAT change, for the traffic as it arrives.
func (p *Planner) Plan(intent Intent) (*Plan, error) {
	if intent.NAT == nil || intent.NAT.Mode == NATModeUnset {
		return p.planAccess(intent)
	}
	at := p.now()
	out, changes, access := p.planNAT(intent, at)
	plan := &Plan{Kind: PlanKindAccess, Intent: intent, Baseline: p.fw.Fingerprint(), NAT: &out}
	switch out.Status {
	case NATStatusNeedsAddress, NATStatusIndeterminate:
		plan.Status = StatusIndeterminate
		plan.Unknown = append(plan.Unknown, "NAT: "+out.Reason)
		return plan, nil
	case NATStatusConflict:
		plan.Status = StatusConflict
		return plan, nil
	case NATStatusSatisfied:
		ap, err := p.planAccess(access)
		if err != nil {
			return nil, err
		}
		ap.Intent, ap.NAT = intent, &out
		return ap, nil
	case NATStatusAdded, NATStatusUnset:
	}
	cfg := p.fw.Config()
	if err := Apply(cfg, changes); err != nil {
		return nil, err
	}
	withNAT, err := firemon.Compile(cfg)
	if err != nil {
		return nil, err
	}
	sub := &Planner{fw: withNAT, naming: p.naming, now: func() time.Time { return at }, threshold: p.threshold}
	ap, err := sub.planAccess(access)
	if err != nil {
		return nil, err
	}
	ap.Intent, ap.Baseline, ap.NAT = intent, plan.Baseline, &out
	ap.Changes = append(changes, ap.Changes...)
	if ap.Status == StatusNoChange {
		ap.Status = StatusChange
	}
	return ap, nil
}

// planAccess designs the security rule changes that permit intent.
func (p *Planner) planAccess(intent Intent) (*Plan, error) {
	at := p.now()
	res, err := p.engine(p.fw, intent).Query(intent.request(at))
	if err != nil {
		return nil, err
	}
	plan := &Plan{Kind: PlanKindAccess, Intent: intent, Baseline: p.fw.Fingerprint()}
	if res.Verdict == query.VerdictAllowed {
		plan.Status, plan.Verified = StatusNoChange, true
		return plan, nil
	}
	needs := p.needs(res, intent, plan)
	if len(needs) == 0 {
		plan.Status = p.blockedStatus(plan)
		plan.Verified = true
		return plan, nil
	}
	cat := newCatalog(p.fw, p.naming)
	cat.threshold = p.threshold
	var ruleChanges []Change
	var opened []need
	for _, n := range needs {
		changes, err := p.open(n, intent, cat, at)
		if err != nil {
			// One zone pair that cannot be opened safely does not hide the
			// plan for the others.
			plan.Unknown = append(plan.Unknown, n.from+" -> "+n.to+": "+err.Error())
			continue
		}
		ruleChanges = append(ruleChanges, changes...)
		opened = append(opened, n)
		for _, c := range changes {
			if x, ok := c.(ExtendRule); ok {
				if r, ok := p.fw.Rule(x.RuleID); ok && !r.Spec().Log.Enabled() {
					plan.Warnings = append(plan.Warnings, "rule "+x.RuleID+" does not log its sessions; consider enabling logging")
				}
			}
		}
	}
	plan.Changes = append(slices.Clone(cat.created), ruleChanges...)
	plan.Verified = true
	if len(plan.Changes) > 0 {
		if err := p.verify(plan.Changes, intent, opened, at); err != nil {
			plan.Verified, plan.VerifyError = false, err.Error()
		}
	}
	plan.Status = StatusChange
	if len(plan.Conflicts) > 0 {
		plan.Status = StatusConflict
	}
	if len(plan.Unknown) > 0 {
		plan.Status = StatusIndeterminate
	}
	return plan, nil
}

// engine evaluates fw for intent: permanent access ignores rules that
// permit or deny only part of the time; scheduled access assumes every
// unexpired scheduled rule is active.
func (p *Planner) engine(fw *firemon.Firewall, intent Intent) *query.Engine {
	mode := query.ScheduleNeverActive
	if intent.Schedule != "" {
		mode = query.ScheduleAlwaysActive
	}
	return query.New(fw, query.Options{Now: p.now, Schedules: mode})
}

func (p *Planner) blockedStatus(plan *Plan) Status {
	if len(plan.Unknown) > 0 {
		return StatusIndeterminate
	}
	return StatusConflict
}

// needs collects, per zone pair, the packets to open, the conflicts to keep
// and the placement of new rules.
func (p *Planner) needs(res *query.Result, intent Intent, plan *Plan) []need {
	if !res.Unrouted.IsEmpty() {
		plan.Unknown = append(plan.Unknown, "unrouted destinations "+res.Unrouted.String())
	}
	var out []need
	for _, path := range res.Paths {
		i := slices.IndexFunc(out, func(n need) bool { return n.from == path.From && n.to == path.To })
		if i < 0 {
			out = append(out, need{from: path.From, to: path.To})
			i = len(out) - 1
		}
		n := &out[i]
		n.scope = n.scope.Add(path.Policy)
		if len(path.NATUncertain) > 0 {
			// The packets the rules see depend on NAT that cannot be
			// decided: nothing on this path is opened blindly.
			plan.Unknown = append(plan.Unknown, n.from+" -> "+n.to+": NAT may apply ("+natIDs(path.NATUncertain)+")")
			n.conflict = n.conflict.Add(path.Policy)
			continue
		}
		for _, d := range path.Decisions {
			p.classify(n, d, intent, plan)
		}
	}
	if p.fw.Semantics().PortServicesOnly {
		for i := range out {
			p.dropPortless(&out[i], plan)
		}
	}
	return slices.DeleteFunc(out, func(n need) bool { return n.region.IsEmpty() })
}

// dropPortless removes protocols other than TCP, UDP and SCTP from a need on
// vendors whose service objects carry only ports; such traffic is permitted
// with application matching, which the plan reports instead of guessing.
func (p *Planner) dropPortless(n *need, plan *Plan) {
	ports := traffic.ProtocolService(traffic.ProtocolTCP).Union(traffic.ProtocolService(traffic.ProtocolUDP)).Union(traffic.ProtocolService(traffic.ProtocolSCTP))
	portless := traffic.Space{Src: traffic.AnyAddress(), Dst: traffic.AnyAddress(), Service: traffic.AnyService().Subtract(ports)}
	if rest := n.region.Intersect(portless); !rest.IsEmpty() {
		plan.Unknown = append(plan.Unknown, n.from+" -> "+n.to+": "+rest.String()+" needs an application match (no port service)")
		n.region = n.region.SubtractRegion(rest)
	}
}

func (p *Planner) classify(n *need, d query.Decision, intent Intent, plan *Plan) {
	outcome := d.Outcome
	switch {
	case outcome == query.OutcomeUnknown && onlyPermits(d.Possible):
		// Undecidable permit rules can only allow more; plan as if the
		// final decision applied and say so.
		outcome = d.Final
		if outcome != query.OutcomePermit {
			plan.Warnings = append(plan.Warnings, d.Space.String()+" may already be permitted by undecidable rules "+ruleIDs(d.Possible))
		}
	case outcome == query.OutcomeUnknown && onlyNarrowing(d.Possible):
		// The rules that may match first only add applications, URL
		// categories or users to their match: they act on part of any
		// traffic, and a permit for the rest is what the intent asks.
		// Verification accepts the same (onlyNarrowDenies).
		outcome = d.Final
		plan.Warnings = append(plan.Warnings, d.Space.String()+": rules "+ruleIDs(d.Possible)+
			" that match applications, URL categories or users may still decide part of it first")
	}
	switch outcome {
	case query.OutcomeDefault:
		n.region = n.region.Union(d.Space)
		if onlyNarrowDenies(d.Possible) {
			plan.Warnings = append(plan.Warnings, d.Space.String()+": deny rules "+ruleIDs(d.Possible)+
				" that match applications, URL categories or users still come first")
		}
	case query.OutcomeDeny:
		if !catchAll(d.Rule) && !intent.Override {
			n.conflict = n.conflict.Union(d.Space)
			plan.Conflicts = append(plan.Conflicts, Conflict{RuleID: d.Rule.ID(), From: n.from, To: n.to, Space: d.Space, Text: d.Space.String()})
			return
		}
		n.region = n.region.Union(d.Space)
		if n.before == nil || d.Rule.Position() < n.before.Position() {
			n.before = d.Rule
		}
		if onlyNarrowDenies(d.Possible) {
			plan.Warnings = append(plan.Warnings, d.Space.String()+": deny rules "+ruleIDs(d.Possible)+
				" that match applications, URL categories or users still come first")
		}
	case query.OutcomeUnknown:
		plan.Unknown = append(plan.Unknown, n.from+" -> "+n.to+": "+d.Space.String())
		n.conflict = n.conflict.Union(d.Space) // never opened blindly
	case query.OutcomePermit, query.OutcomeUnset:
	}
}

func onlyPermits(rules []*firemon.Rule) bool {
	for _, r := range rules {
		if r.Action() != firemon.ActionPermit {
			return false
		}
	}
	return len(rules) > 0
}

func ruleIDs(rules []*firemon.Rule) string {
	ids := make([]string, len(rules))
	for i, r := range rules {
		ids[i] = r.ID()
	}
	return strings.Join(ids, ",")
}

// catchAll reports whether a deny rule is a final "deny everything" rule:
// every zone, every service, and every address of a family on both sides.
// Narrower denies are deliberate and become conflicts.
func catchAll(r *firemon.Rule) bool {
	m, s := r.Match(), r.Spec()
	anyFamily := func(a traffic.AddressSet) bool {
		return a.ContainsSet(traffic.AnyIPv4()) || a.ContainsSet(traffic.AnyIPv6())
	}
	return anyFamily(m.Src) && anyFamily(m.Dst) && m.Service.IsAny() &&
		len(s.From) == 0 && len(s.To) == 0 && s.Scope == firemon.ZoneScopeAny
}

// maxTrials bounds the rule extensions verified per zone pair (ALG-2).
const maxTrials = 8

// open returns the cheapest verified changes that permit n.
func (p *Planner) open(n need, intent Intent, cat *catalog, at time.Time) ([]Change, error) {
	if n.from == "" || n.to == "" {
		return nil, fmt.Errorf("design: zones of %s are unknown; set the from and to zones", n.region)
	}
	target := n.region.Bounds()
	cands := p.extensions(n, target, cat)
	// Each trial recompiles the firewall; the cheapest few are enough.
	for _, cand := range cands[:min(len(cands), maxTrials)] {
		mark := cat.mark()
		changes := cand.changes(cat)
		all := append(slices.Clone(cat.created), changes...)
		if p.verify(all, intent, []need{n}, at) == nil {
			return changes, nil
		}
		cat.rollback(mark)
	}
	mark := cat.mark()
	rule := p.newRule(n, target, intent, cat)
	changes := []Change{rule}
	if p.verify(append(slices.Clone(cat.created), changes...), intent, []need{n}, at) == nil {
		return changes, nil
	}
	cat.rollback(mark)
	// The bounding box would reopen conflicting packets: one rule per space.
	changes = nil
	for _, s := range n.region.Spaces() {
		changes = append(changes, p.newRule(n, s, intent, cat))
	}
	if err := p.verify(append(slices.Clone(cat.created), changes...), intent, []need{n}, at); err != nil {
		cat.rollback(mark)
		return nil, fmt.Errorf("%w for %s -> %s: %w", ErrUnverifiable, n.from, n.to, err)
	}
	return changes, nil
}

// extension is a candidate: add the target's field set to one rule.
type extension struct {
	rule  *firemon.Rule
	field Field
	add   traffic.Space // only the field dimension is used
	// whole is the requested set of the field on this zone pair; an
	// existing object equal to it adds the same traffic as add.
	whole traffic.Space
	cost  int
}

// changes adds the missing part of the field, or one existing object
// holding the whole target set when there is one: a /24 stays one object
// rather than ranges around what the rule already has.
func (x extension) changes(cat *catalog) []Change {
	var names []string
	switch x.field {
	case FieldSource:
		names = cat.wholeOr(x.whole.Src, x.add.Src)
	case FieldDestination:
		names = cat.wholeOr(x.whole.Dst, x.add.Dst)
	case FieldService:
		if name, ok := cat.services[x.whole.Service.String()]; ok {
			names = []string{name}
		} else {
			names = cat.serviceNames(x.add.Service)
		}
	case FieldUnset:
	}
	return []Change{ExtendRule{RuleID: x.rule.ID(), Field: x.field, Names: names}}
}

// extensions lists the rules that can absorb target by growing one
// dimension, cheapest first.
func (p *Planner) extensions(n need, target traffic.Space, cat *catalog) []extension {
	var out []extension
	scope := n.scope.Bounds()
	for _, r := range p.fw.Rules() {
		if n.before != nil && r.Position() >= n.before.Position() {
			break
		}
		if !extendable(r, n.from, n.to) {
			continue
		}
		m := r.Match()
		fits := func(a, b traffic.Space) bool { return a.ContainsSpace(b) }
		if m.Dst.ContainsSet(target.Dst) && m.Service.ContainsSet(target.Service) && fits(scope, traffic.Space{Src: scope.Src, Dst: m.Dst, Service: m.Service}) {
			add := target.Src.Subtract(m.Src)
			out = append(out, extension{rule: r, field: FieldSource, add: traffic.Space{Src: add}, whole: scope, cost: len(add.Ranges())})
		}
		if m.Src.ContainsSet(target.Src) && m.Service.ContainsSet(target.Service) && fits(scope, traffic.Space{Src: m.Src, Dst: scope.Dst, Service: m.Service}) {
			add := target.Dst.Subtract(m.Dst)
			out = append(out, extension{rule: r, field: FieldDestination, add: traffic.Space{Dst: add}, whole: scope, cost: len(add.Ranges())})
		}
		if m.Src.ContainsSet(target.Src) && m.Dst.ContainsSet(target.Dst) && fits(scope, traffic.Space{Src: m.Src, Dst: m.Dst, Service: scope.Service}) {
			add := target.Service.Subtract(m.Service)
			cost := 0
			for range add.All() {
				cost++
			}
			out = append(out, extension{rule: r, field: FieldService, add: traffic.Space{Service: add}, whole: scope, cost: cost})
		}
	}
	slices.SortStableFunc(out, func(a, b extension) int { return CompareCandidates(a.key(), b.key()) })
	return out
}

func (x extension) key() CandidateKey {
	return CandidateKey{BothEnds: x.field == FieldService, Logs: x.rule.Spec().Log.Enabled(), Cost: x.cost, Position: x.rule.Position()}
}

// extendable reports whether growing r cannot affect other zone pairs and
// r's match is exact and unconditional.
func extendable(r *firemon.Rule, from, to string) bool {
	s := r.Spec()
	return r.Action() == firemon.ActionPermit && r.Decidable() && !r.Scheduled() && !r.Ignored() &&
		slices.Equal(s.From, []string{from}) && slices.Equal(s.To, []string{to}) &&
		!s.NegateSource && !s.NegateDestination && len(s.ServiceEntries) == 0 && len(s.Applications) == 0
}

func (p *Planner) newRule(n need, s traffic.Space, intent Intent, cat *catalog) AddRule {
	index := cat.nextRule()
	name := p.naming.Rule(intent, index)
	if intent.Name == "" {
		name = cat.dated(p.now()) // P-20261118-001: the day and its sequence
	}
	r := firemon.SecurityRule{
		Name: cat.unique(name), Description: intent.Description,
		From: []string{n.from}, To: []string{n.to}, Action: firemon.ActionPermit, Schedule: intent.Schedule,
	}
	// Best practice: a rule says why it exists and logs its sessions.
	if r.Description == "" {
		r.Description = r.Name + "-By-Firemon"
	}
	if !intent.NoLog {
		r.Log = firemon.Logging{Start: true, End: true, Setting: intent.LogSetting}
	}
	for _, name := range cat.groupAddresses(cat.addressNames(s.Src), s.Src, p.naming.Group(r.Name, FieldSource)) {
		r.Source = append(r.Source, firemon.NamedAddress(name))
	}
	for _, name := range cat.groupAddresses(cat.addressNames(s.Dst), s.Dst, p.naming.Group(r.Name, FieldDestination)) {
		r.Destination = append(r.Destination, firemon.NamedAddress(name))
	}
	r.Services = cat.groupServices(cat.serviceNames(s.Service), s.Service, p.naming.Group(r.Name, FieldService))
	r.ID = p.ruleID(r.Name, index)
	add := AddRule{Rule: r}
	if n.before != nil {
		add.Before = n.before.ID()
	}
	return add
}

// ruleID assigns a numeric ID above every existing rule and rule group on
// vendors with device-numbered rules, and the rule name elsewhere.
func (p *Planner) ruleID(name string, index int) string {
	if !p.fw.Semantics().NumericRuleIDs {
		return name
	}
	highest := 0
	for _, r := range p.fw.Rules() {
		if n, err := strconv.Atoi(r.ID()); err == nil && n > highest {
			highest = n
		}
	}
	for _, g := range p.fw.RuleGroups() {
		if n, err := strconv.Atoi(g.ID); err == nil && n > highest {
			highest = n
		}
	}
	return strconv.Itoa(highest + 1 + index)
}

// boundingBox returns the smallest space containing every space of r.
func natIDs(refs []query.NATRef) string {
	ids := make([]string, len(refs))
	for i, r := range refs {
		ids[i] = r.String()
	}
	return strings.Join(ids, ",")
}

// onlyNarrowing reports whether every rule is a permit, or a deny that
// only narrows by application, URL category or user.
func onlyNarrowing(rules []*firemon.Rule) bool {
	for _, r := range rules {
		if r.Action() != firemon.ActionPermit && !onlyNarrowDenies([]*firemon.Rule{r}) {
			return false
		}
	}
	return len(rules) > 0
}
