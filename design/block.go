package design

import (
	"errors"
	"slices"
	"time"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/query"
	"github.com/gatework/firemon/traffic"
)

// ErrNotBlocked reports a block plan whose traffic is still permitted, or
// possibly permitted, on some zone pair once applied.
var ErrNotBlocked = errors.New("design: traffic is not blocked on every zone pair")

// BlockPlan is the change that blocks traffic on a firewall.
type BlockPlan struct {
	*Plan
	// BlockedBy are the deny rules that already block the traffic, when
	// no change is needed.
	BlockedBy []string
}

// PlanBlock designs the change that denies the traffic of intent between
// every pair of zones of the firewall, whatever the rules below would do:
// one deny rule for any zone, placed before the first rule that may match
// any of that traffic, so it decides first. Nothing else changes: the rule
// matches only that traffic. When every zone pair already denies all of
// it, the plan has no change and BlockedBy names the rules that do.
func (p *Planner) PlanBlock(intent Intent) (*BlockPlan, error) {
	space := traffic.Space{Src: orAny(intent.Src), Dst: orAny(intent.Dst), Service: intent.Service}
	if space.Service.IsEmpty() {
		space.Service = traffic.AnyService()
	}
	at := p.now()
	plan := &Plan{Kind: PlanKindAccess, Intent: intent, Baseline: p.fw.Fingerprint()}
	open, by, proofErr := blocked(p.fw, space, at, intent.Schedule)
	if proofErr != nil && intent.Schedule != "" {
		plan.Status, plan.VerifyError = StatusIndeterminate, proofErr.Error()
		return &BlockPlan{Plan: plan}, nil
	}
	if !open {
		plan.Status, plan.Verified = StatusNoChange, true
		if err := plan.recordPart(p.fw, intent); err != nil {
			return nil, err
		}
		plan.parts[0].block = &space
		return &BlockPlan{Plan: plan, BlockedBy: by}, nil
	}
	cat := newCatalog(p.fw, p.naming)
	space.Src, space.Dst = cat.anyFor(space.Src, space.Dst), cat.anyFor(space.Dst, space.Src)
	index := cat.nextRule()
	name := p.naming.Rule(intent, index)
	if intent.Name == "" {
		name = cat.dated("B", at) // B-20261118-001: a block of the day
	}
	r := firemon.SecurityRule{Name: cat.unique(name), Description: intent.Description, Action: firemon.ActionDeny, Schedule: intent.Schedule}
	if r.Description == "" {
		r.Description = r.Name + "-By-Firemon"
	}
	if !intent.NoLog {
		r.Log = firemon.Logging{End: true, Deny: p.caps.LogDeny, Forward: intent.LogSetting}
	}
	for _, n := range cat.groupAddresses(cat.addressNames(space.Src), space.Src, p.naming.Group(r.Name, FieldSource)) {
		r.Source = append(r.Source, firemon.NamedAddress(n))
	}
	for _, n := range cat.groupAddresses(cat.addressNames(space.Dst), space.Dst, p.naming.Group(r.Name, FieldDestination)) {
		r.Destination = append(r.Destination, firemon.NamedAddress(n))
	}
	r.Services = cat.groupServices(cat.serviceNames(space.Service), space.Service, p.naming.Group(r.Name, FieldService))
	r.ID = p.ruleID(r.Name, index)
	add := AddRule{Rule: r}
	if first := firstOverlapping(p.fw, space); first != nil {
		add.Before = first.ID()
	}
	plan.Changes = append(slices.Clone(cat.created), add)
	plan.Status = StatusChange
	// A plan that fails verification is returned with the reason, not as
	// an error: the caller reports it and prints no commands.
	verr := p.verifyBlock(plan.Changes, space, intent.Schedule)
	plan.Verified = verr == nil
	if verr != nil {
		plan.VerifyError = verr.Error()
	}
	if err := plan.recordPart(p.fw, intent); err != nil {
		return nil, err
	}
	plan.parts[0].block = &space
	return &BlockPlan{Plan: plan}, nil
}

// orAny is s, or every address when s is empty.
func orAny(s traffic.AddressSet) traffic.AddressSet {
	if s.IsEmpty() {
		return traffic.AnyAddress()
	}
	return s
}

// firstOverlapping is the first rule, in force or not decidable, that may
// match some of the space on any zone pair.
func firstOverlapping(fw *firemon.Firewall, s traffic.Space) *firemon.Rule {
	for _, r := range fw.Rules() {
		if !r.Ignored() && r.Bound().Overlaps(s) {
			return r
		}
	}
	return nil
}

// blocked checks for an explicit deny on every zone pair throughout the
// requested schedule. A permanent rule covering the whole space ends the
// search for relevant schedules, since later rules cannot decide a packet.
func blocked(fw *firemon.Firewall, s traffic.Space, at time.Time, schedule string) (bool, []string, error) {
	var timed []*firemon.Rule
	for _, r := range fw.Rules() {
		if r.Ignored() || !r.Bound().Overlaps(s) {
			continue
		}
		if r.Scheduled() {
			timed = append(timed, r)
			continue
		}
		from, to := r.Zones()
		if len(from) == 0 && len(to) == 0 && r.Scope() == firemon.ZoneScopeAny && r.Decidable() && r.Match().ContainsSpace(s) {
			break
		}
	}
	times, err := fw.PolicyTimes(at, schedule, timed)
	if err != nil {
		return true, nil, err
	}
	e := query.New(fw, query.Options{})
	zones := zoneNames(fw)
	var rules []string
	for _, instant := range times {
		open, by := blockedAt(e, zones, s, instant)
		if open {
			return true, nil, nil
		}
		for _, id := range by {
			if !slices.Contains(rules, id) {
				rules = append(rules, id)
			}
		}
	}
	return false, rules, nil
}

func blockedAt(e *query.Engine, zones []string, s traffic.Space, at time.Time) (open bool, by []string) {
	// Zone pairs are independent: each keeps only its outcome, read back
	// in order so the result does not depend on scheduling.
	type pair struct {
		open bool
		by   []string
	}
	pairs := make([]pair, len(zones)*len(zones))
	query.Each(len(pairs), func(i int) {
		for _, d := range e.Evaluate(zones[i/len(zones)], zones[i%len(zones)], s, at).Decisions {
			switch {
			case d.Outcome != query.OutcomeDeny:
				// Permitted, possibly permitted, or denied only by the
				// default: a block needs a rule of its own, which a permit
				// added later cannot get around.
				pairs[i].open = true
			case !slices.Contains(pairs[i].by, d.Rule.ID()):
				pairs[i].by = append(pairs[i].by, d.Rule.ID())
			}
		}
	})
	for _, p := range pairs {
		open = open || p.open
		for _, id := range p.by {
			if !slices.Contains(by, id) {
				by = append(by, id)
			}
		}
	}
	return open, by
}

// verifyBlock applies the changes to a copy and checks that the space is
// denied on every zone pair.
func (p *Planner) verifyBlock(changes []Change, s traffic.Space, schedule string) error {
	cfg := p.fw.Config()
	if err := Apply(cfg, changes); err != nil {
		return err
	}
	fw, err := firemon.Compile(cfg)
	if err != nil {
		return err
	}
	open, _, err := blocked(fw, s, p.now(), schedule)
	if err != nil {
		return err
	}
	if open {
		return ErrNotBlocked
	}
	return nil
}

// zoneNames are the firewall's zones; a firewall without zones is
// evaluated on one unnamed pair.
func zoneNames(fw *firemon.Firewall) []string {
	var out []string
	for _, z := range fw.Config().Zones {
		out = append(out, z.Name)
	}
	if len(out) == 0 {
		return []string{""}
	}
	return out
}
