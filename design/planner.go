package design

import (
	"errors"
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
	caps      firemon.Capabilities
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
	return &Planner{fw: fw, naming: opts.Naming.withDefaults(), now: now, threshold: threshold, caps: opts.Capabilities}
}

// need is what one zone pair must newly permit.
type need struct {
	from, to string
	region   traffic.Region // policy-space packets to open
	scope    traffic.Region // policy-space packets of the intent on this pair
	conflict traffic.Region // packets that must stay as they are: specific denies and undecidable parts
	before   *firemon.Rule  // first deny deciding the need; nil means end
	// bypass are the deny rules the new rules go before: definite denies
	// and denies that match applications, URL categories or users first.
	bypass []*firemon.Rule
	// opens and keeps gather the disjoint pieces of one path for region
	// and conflict, merged once the path is classified.
	opens, keeps []traffic.Space
}

// Plan designs the changes that permit intent and, when it asks for one,
// translate it. The NAT part comes first: access is then designed on the
// configuration with the NAT change, for the traffic as it arrives.
func (p *Planner) Plan(intent Intent) (*Plan, error) {
	plan, err := p.plan(intent)
	if err != nil {
		return nil, err
	}
	if err := plan.recordPart(p.fw, intent); err != nil {
		return nil, err
	}
	return plan, nil
}

func (p *Planner) plan(intent Intent) (*Plan, error) {
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
	var until []Change
	if !intent.Until.IsZero() && !p.caps.RuleWindows && intent.Schedule == "" {
		// The vendor's rules carry no validity window: a one-time schedule
		// ends the access instead.
		s := untilSchedule(at, intent.Until)
		if _, exists := p.scheduleNamed(s.Name); !exists {
			until = append(until, AddSchedule{Schedule: s})
		}
		intent.Schedule = s.Name
	}
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
		// Nothing can be opened: no change is proved to permit the intent.
		plan.Status = p.blockedStatus(plan)
		return plan, nil
	}
	cat := newCatalog(p.fw, p.naming)
	cat.threshold = p.threshold
	// Every trial is verified with the catalog's changes: the schedule a
	// temporary access creates goes first.
	cat.created = append(cat.created, until...)
	var ruleChanges []Change
	var opened []need
	for _, n := range needs {
		changes, err := p.open(n, intent, cat, at, plan)
		if err != nil {
			// One zone pair that cannot be opened safely does not hide the
			// plan for the others.
			plan.Unknown = append(plan.Unknown, n.from+" -> "+n.to+": "+err.Error())
			continue
		}
		ruleChanges = append(ruleChanges, changes...)
		opened = append(opened, n)
		plan.bypassed(n, changes)
		for _, c := range changes {
			if x, ok := c.(ExtendRule); ok {
				if r, ok := p.fw.Rule(x.RuleID); ok && !r.Spec().Log.Enabled() {
					plan.Warnings = append(plan.Warnings, "rule "+x.RuleID+" does not log its sessions; consider enabling logging")
				}
			}
		}
	}
	plan.Changes = append(slices.Clone(cat.created), ruleChanges...)
	if len(ruleChanges) == 0 {
		plan.Changes = nil // the schedule alone changes nothing
	}
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

// engine evaluates fw for intent over the period the access must hold:
// from now on, within the intent's schedule and before its end. A timed
// rule that is in force only part of that period counts against the
// access: such a deny blocks it and such a permit does not grant it.
func (p *Planner) engine(fw *firemon.Firewall, intent Intent) *query.Engine {
	at := p.now()
	return query.New(fw, query.Options{
		Now: p.now, Schedules: query.ScheduleWorstCase,
		Activity: activities(fw, intent, at),
	})
}

// activities classifies every timed rule of fw over the period of intent.
// A rule whose activity cannot be proved is partial.
func activities(fw *firemon.Firewall, intent Intent, at time.Time) func(*firemon.Rule) query.Activity {
	schedule := intent.Schedule
	if schedule != "" && !hasSchedule(fw, schedule) && !intent.Until.IsZero() {
		// The one-time schedule of a temporary access is not created
		// yet: the period is bounded by Until alone.
		schedule = ""
	}
	out := map[*firemon.Rule]query.Activity{}
	for _, r := range fw.Rules() {
		if r.Ignored() || !r.Scheduled() {
			continue
		}
		out[r] = activity(fw, r, schedule, intent.Until, at)
	}
	return func(r *firemon.Rule) query.Activity { return out[r] }
}

func activity(fw *firemon.Firewall, r *firemon.Rule, schedule string, until, at time.Time) query.Activity {
	times, err := fw.PolicyTimes(at, schedule, []*firemon.Rule{r})
	if err != nil || !r.Decidable() {
		return query.ActivityPartial
	}
	var active, inactive bool
	for _, t := range times {
		if !until.IsZero() && !t.Before(until) {
			continue
		}
		if r.ActiveAt(t) {
			active = true
		} else {
			inactive = true
		}
	}
	switch {
	case active && !inactive:
		return query.ActivityAlways
	case inactive && !active:
		return query.ActivityNever
	}
	return query.ActivityPartial
}

func hasSchedule(fw *firemon.Firewall, name string) bool {
	return slices.ContainsFunc(fw.Config().Schedules, func(s firemon.Schedule) bool { return s.Name == name })
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
		// The decisions of one path are disjoint: they are gathered on a
		// scratch need without overlap checks and merged once per path.
		scratch := need{from: n.from, to: n.to, before: n.before, bypass: n.bypass}
		for _, d := range path.Decisions {
			p.classify(&scratch, d, intent, plan)
		}
		n.region = n.region.Union(traffic.DisjointRegion(scratch.opens...))
		n.conflict = n.conflict.Union(traffic.DisjointRegion(scratch.keeps...))
		n.before, n.bypass = scratch.before, scratch.bypass
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
		outcome = d.FallbackOutcome
		if outcome != query.OutcomePermit {
			plan.Warnings = append(plan.Warnings, d.Space.String()+" may already be permitted by undecidable rules "+ruleIDs(d.Possible))
		}
	}
	switch outcome {
	case query.OutcomeDefault:
		n.opens = append(n.opens, d.Space.Spaces()...)
		p.narrowDenies(n, d, intent, plan)
	case query.OutcomeDeny:
		if !catchAll(d.Rule) && !intent.Override {
			n.keeps = append(n.keeps, d.Space.Spaces()...)
			plan.Conflicts = append(plan.Conflicts, Conflict{RuleID: d.Rule.ID(), From: n.from, To: n.to, Space: d.Space, Text: d.Space.String()})
			return
		}
		n.opens = append(n.opens, d.Space.Spaces()...)
		n.goBefore(d.Rule)
		p.narrowDenies(n, d, intent, plan)
	case query.OutcomeUnknown:
		// A rule that may match first could decide all of it, as an
		// application deny on a port no application claims (ADR 0017).
		plan.Unknown = append(plan.Unknown, n.from+" -> "+n.to+": "+d.Space.String()+" may be decided by rules "+ruleIDs(d.Possible))
		n.keeps = append(n.keeps, d.Space.Spaces()...) // never opened blindly
	case query.OutcomePermit, query.OutcomeUnset:
	}
}

// narrowDenies handles the deny rules that match applications, URL
// categories or users and come before the decision: an override places the
// new rules before them too, since the traffic asked for may be exactly
// what they block (SSH denied by application before tcp/22 is permitted);
// otherwise the plan warns that they still come first.
func (p *Planner) narrowDenies(n *need, d query.Decision, intent Intent, plan *Plan) {
	if !onlyNarrowDenies(d.Possible) {
		return
	}
	if !intent.Override {
		plan.Warnings = append(plan.Warnings, d.Space.String()+": deny rules "+ruleIDs(d.Possible)+
			" that match applications, URL categories or users still come first")
		return
	}
	for _, r := range d.Possible {
		n.goBefore(r)
	}
}

// goBefore places the need's new rules before deny rule r, when r comes
// earlier than the current place, and records that they bypass it.
func (n *need) goBefore(r *firemon.Rule) {
	if n.before == nil || r.Position() < n.before.Position() {
		n.before = r
	}
	if !slices.Contains(n.bypass, r) {
		n.bypass = append(n.bypass, r)
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

// extendable reports whether growing r cannot affect other zone pairs and
// r's match is exact and unconditional.
func extendable(r *firemon.Rule, from, to string, intent Intent) bool {
	s := r.Spec()
	return r.Action() == firemon.ActionPermit && r.Decidable() && !r.Ignored() && sameTime(r, intent) &&
		slices.Equal(s.From, []string{from}) && slices.Equal(s.To, []string{to}) &&
		!s.NegateSource && !s.NegateDestination && len(s.ServiceEntries) == 0 && len(s.Applications()) == 0
}

// sameTime reports whether r is in force exactly when the intent asks:
// growing a rule extends the new traffic to the rule's own schedule, so a
// permanent intent grows only permanent rules and a scheduled one only rules
// on the same schedule.
func sameTime(r *firemon.Rule, intent Intent) bool {
	s := r.Spec()
	if s.Window != (firemon.TimeWindow{}) || !intent.Until.IsZero() {
		return false
	}
	return s.Schedule == intent.Schedule
}

func (p *Planner) newRule(n need, s traffic.Space, intent Intent, cat *catalog) AddRule {
	index := cat.nextRule()
	name := p.naming.Rule(intent, index)
	if intent.Name == "" {
		name = cat.dated("P", p.now()) // P-20261118-001: the day and its sequence
	}
	r := firemon.SecurityRule{
		Name: cat.unique(name), Description: intent.Description,
		From: []string{n.from}, To: []string{n.to}, Action: firemon.ActionPermit, Schedule: intent.Schedule,
	}
	if !intent.Until.IsZero() && p.caps.RuleWindows && intent.Schedule == "" {
		r.Window = firemon.TimeWindow{End: intent.Until}
	}
	s.Src, s.Dst = cat.anyFor(s.Src, s.Dst), cat.anyFor(s.Dst, s.Src)
	// Best practice: a rule says why it exists and logs its sessions.
	if r.Description == "" {
		r.Description = r.Name + "-By-Firemon"
	}
	if !intent.NoLog {
		r.Log = firemon.Logging{Start: true, End: true, Forward: intent.LogSetting}
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

// untilSchedule is the one-time schedule from now to until, named after
// its end so that requests ending the same day share it.
func untilSchedule(now, until time.Time) firemon.Schedule {
	return firemon.Schedule{
		Name:        "Until-" + until.Format("20060102-1504"),
		Description: "firemon: temporary access until " + until.Format("2006-01-02 15:04"),
		Windows:     []firemon.TimeWindow{{Start: now.Truncate(time.Minute), End: until}},
	}
}

// scheduleNamed returns the schedule of the configuration with name.
func (p *Planner) scheduleNamed(name string) (firemon.Schedule, bool) {
	for _, s := range p.fw.Config().Schedules {
		if s.Name == name {
			return s, true
		}
	}
	return firemon.Schedule{}, false
}
