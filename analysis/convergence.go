package analysis

import (
	"cmp"
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/policy"
)

type Converger struct {
	Planner        plan.Planner
	MaxComparisons int
}

type ConvergenceKind uint8

const (
	ContainRules ConvergenceKind = iota + 1
	CombineRules
)

type ConvergenceCandidate struct {
	Rules     []fm.ID
	Kind      ConvergenceKind
	Reason    string
	Plan      *plan.Plan
	Rejection error
}

// Candidates discovers compatible pairs in native order. Each returned Plan
// carries the same whole-rulebase proof as Plan; rejected candidates retain
// their rationale. It never applies or combines independently proven plans.
func (c Converger) Candidates(ctx context.Context, fw *fm.Firewall, from time.Time) ([]ConvergenceCandidate, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if fw == nil || !fw.Complete() {
		return nil, ErrInvalid
	}
	budget := c.MaxComparisons
	if budget <= 0 {
		budget = 4096
	}
	limits := c.Planner.Engine.Limits.WithDefaults()
	visits := visitBudget(limits.MaxVisits)
	if err := visits.take(ctx, fw.RuleCount()); err != nil {
		return nil, err
	}
	var rules []fm.RuleRecord
	for rule := range fw.OrderedRules() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		r := rule.Record()
		if eligibleForConvergence(r) {
			rules = append(rules, r)
		}
	}
	if err := visits.take(ctx, len(rules)); err != nil {
		return nil, err
	}
	signatures := make([]fm.RuleRecord, len(rules))
	for i, rule := range rules {
		signatures[i] = convergenceSignature(rule)
	}
	var contexts []policy.Request
	contextsReady := false
	var candidates []ConvergenceCandidate
	for i, a := range rules {
		for offset, b := range rules[i+1:] {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if budget <= 0 {
				return nil, policy.ErrBudget
			}
			budget--
			if !sameConvergenceSignature(signatures[i], signatures[i+1+offset]) {
				continue
			}
			if !contextsReady {
				var err error
				contexts, err = c.Planner.Engine.Contexts(ctx, from, fw)
				if err != nil {
					return nil, err
				}
				contextsReady = true
			}
			candidate := ConvergenceCandidate{Rules: []fm.ID{a.ID, b.ID}, Kind: CombineRules, Reason: "combine compatible declarations with whole-rulebase preservation"}
			contained, err := c.containsRule(ctx, fw, a, b, contexts, &visits)
			if err != nil {
				return nil, err
			}
			if contained {
				candidate.Kind, candidate.Reason = ContainRules, "one compatible declaration contains the other"
			}
			candidate.Plan, candidate.Rejection = c.plan(ctx, fw, candidate.Rules, from, contexts, &visits)
			if errors.Is(candidate.Rejection, context.Canceled) || errors.Is(candidate.Rejection, context.DeadlineExceeded) || errors.Is(candidate.Rejection, policy.ErrBudget) || errors.Is(candidate.Rejection, flow.ErrBudget) {
				return nil, candidate.Rejection
			}
			if candidate.Rejection != nil {
				// Only this attempt's direct refusal is retryable. errors.As
				// would also find refusals nested in failed renderer dependencies.
				if _, expected := candidate.Rejection.(*plan.RejectionError); !expected {
					return nil, candidate.Rejection
				}
			}
			candidates = append(candidates, candidate)
		}
	}
	return candidates, nil
}

func compareConvergenceRules(a, b fm.RuleRecord) int {
	if c := cmp.Compare(a.Position, b.Position); c != 0 {
		return c
	}
	return strings.Compare(string(a.ID), string(b.ID))
}

// eligibleForConvergence checks declarations before comparing merge constraints.
// Compatibility and containment are only candidate filters; Plan still proves
// the declaration union and the complete ordered rulebase.
func eligibleForConvergence(rule fm.RuleRecord) bool {
	loggingKnown := rule.Log != fm.Unknown && rule.LogStart != fm.Unknown && rule.LogEnd != fm.Unknown
	return !rule.Builtin && loggingKnown && len(rule.Unsupported) == 0
}

// convergenceSignature excludes only identity, position and member lists.
// Members are unioned separately, then checked for accidental cross-pairs.
func convergenceSignature(r fm.RuleRecord) fm.RuleRecord {
	r.Object = fm.Object{Scope: r.Scope}
	r.Position = 0
	r.Match.Sources, r.Match.Destinations, r.Match.Services = nil, nil, nil
	return r
}

func (c Converger) containsRule(ctx context.Context, fw *fm.Firewall, a, b fm.RuleRecord, contexts []policy.Request, visits *visitBudget) (bool, error) {
	limit := c.Planner.Engine.Limits.WithDefaults().MaxRegions
	aContains, bContains := true, true
	for _, q := range contexts {
		if err := visits.take(ctx, 1); err != nil {
			return false, err
		}
		if q.Scope != a.Scope || q.RuleSet != a.RuleSet {
			continue
		}
		if err := visits.take(ctx, 2); err != nil {
			return false, err
		}
		x, knownA, err := c.Planner.Engine.Match(ctx, fw, a.Match, q, q.Traffic)
		if err != nil {
			return false, err
		}
		y, knownB, err := c.Planner.Engine.Match(ctx, fw, b.Match, q, q.Traffic)
		if err != nil {
			return false, err
		}
		if !knownA || !knownB {
			return false, nil
		}
		ab, err := x.Contains(y, limit)
		if err != nil {
			return false, err
		}
		ba, err := y.Contains(x, limit)
		if err != nil {
			return false, err
		}
		aContains, bContains = aContains && ab, bContains && ba
		if !aContains && !bContains {
			return false, nil
		}
	}
	return aContains || bContains, nil
}

// Plan merges an explicit selection into the earliest native rule. Both the
// declaration union and the entire resulting rulebase must be equivalent.
func (c Converger) Plan(ctx context.Context, fw *fm.Firewall, ids []fm.ID, from time.Time) (*plan.Plan, error) {
	visits := visitBudget(c.Planner.Engine.Limits.WithDefaults().MaxVisits)
	return c.plan(ctx, fw, ids, from, nil, &visits)
}

func (c Converger) plan(ctx context.Context, fw *fm.Firewall, ids []fm.ID, from time.Time, contexts []policy.Request, visits *visitBudget) (*plan.Plan, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if fw == nil || !fw.Complete() || len(ids) < 2 || len(ids) > 100 {
		return nil, ErrInvalid
	}
	limit := c.Planner.Engine.Limits.WithDefaults().MaxRegions
	if err := visits.take(ctx, len(ids)); err != nil {
		return nil, err
	}
	selected := make(map[fm.ID]bool)
	var rules []fm.RuleRecord
	for _, id := range ids {
		if selected[id] || fw.Rule(id) == nil {
			return nil, ErrInvalid
		}
		selected[id] = true
		r := fw.Rule(id).Record()
		if !eligibleForConvergence(r) {
			return nil, &plan.RejectionError{Stage: plan.DeclarationRejection, Err: plan.ErrUnsafe}
		}
		rules = append(rules, r)
	}
	slices.SortFunc(rules, compareConvergenceRules)
	merged := rules[0]
	change := plan.Change{Kind: plan.AppendMembers, Rule: merged.ID}
	signature := convergenceSignature(rules[0])
	for _, r := range rules[1:] {
		if err := visits.take(ctx, len(r.Match.Sources)+len(r.Match.Destinations)+len(r.Match.Services)); err != nil {
			return nil, err
		}
		if !sameConvergenceSignature(signature, convergenceSignature(r)) {
			return nil, &plan.RejectionError{Stage: plan.DeclarationRejection, Err: plan.ErrUnsafe}
		}
		for _, ref := range r.Match.Sources {
			if !slices.Contains(merged.Match.Sources, ref) {
				merged.Match.Sources = append(merged.Match.Sources, ref)
				change.Sources = append(change.Sources, ref)
			}
		}
		for _, ref := range r.Match.Destinations {
			if !slices.Contains(merged.Match.Destinations, ref) {
				merged.Match.Destinations = append(merged.Match.Destinations, ref)
				change.Destinations = append(change.Destinations, ref)
			}
		}
		for _, ref := range r.Match.Services {
			if !slices.Contains(merged.Match.Services, ref) {
				merged.Match.Services = append(merged.Match.Services, ref)
				change.Services = append(change.Services, ref)
			}
		}
	}
	if contexts == nil {
		var err error
		contexts, err = c.Planner.Engine.Contexts(ctx, from, fw)
		if err != nil {
			return nil, err
		}
	}
	for _, q := range contexts {
		if err := visits.take(ctx, 1); err != nil {
			return nil, err
		}
		if q.Scope != merged.Scope || q.RuleSet != merged.RuleSet {
			continue
		}
		if err := visits.take(ctx, len(rules)+1); err != nil {
			return nil, err
		}
		var union flow.Traffic
		for _, r := range rules {
			hit, known, err := c.Planner.Engine.Match(ctx, fw, r.Match, q, q.Traffic)
			if err != nil {
				return nil, err
			}
			if !known {
				return nil, &plan.RejectionError{Stage: plan.DeclarationRejection, Err: plan.ErrUnsafe}
			}
			union, err = union.Union(hit, limit)
			if err != nil {
				return nil, err
			}
		}
		hit, known, err := c.Planner.Engine.Match(ctx, fw, merged.Match, q, q.Traffic)
		if err != nil {
			return nil, err
		}
		if !known {
			return nil, &plan.RejectionError{Stage: plan.DeclarationRejection, Err: plan.ErrUnsafe}
		}
		if equal, err := union.Equal(hit, limit); err != nil {
			return nil, err
		} else if !equal {
			return nil, &plan.RejectionError{Stage: plan.DeclarationRejection, Err: plan.ErrUnsafe}
		}
	}
	if err := visits.take(ctx, fw.RecordCount()); err != nil {
		return nil, err
	}
	d := fw.Export()
	if err := visits.take(ctx, len(d.Rules)); err != nil {
		return nil, err
	}
	kept := d.Rules[:0]
	for _, row := range d.Rules {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if row.ID == merged.ID {
			kept = append(kept, merged)
		} else if !selected[row.ID] {
			kept = append(kept, row)
		}
	}
	d.Rules = kept
	var changes []plan.Change
	if len(change.Sources)+len(change.Destinations)+len(change.Services) > 0 {
		changes = append(changes, change)
	}
	for _, r := range rules[1:] {
		changes = append(changes, plan.Change{Kind: plan.RemoveRule, Rule: r.ID})
	}
	after, err := fm.Seal(d)
	if err != nil {
		return nil, err
	}
	return c.Planner.Preserve(ctx, fw, after, changes, from)
}

// Keep nil distinct from empty, as the previous structural comparison did.
func equalSignatureSlice[T comparable](a, b []T) bool {
	return (a == nil) == (b == nil) && slices.Equal(a, b)
}

func sameConvergenceSignature(a, b fm.RuleRecord) bool {
	x, y := a.Match, b.Match
	return a.Scope == b.Scope && a.RuleSet == b.RuleSet &&
		a.Action == b.Action && a.Disabled == b.Disabled && a.Log == b.Log &&
		a.LogStart == b.LogStart && a.LogEnd == b.LogEnd && a.MatchVIP == b.MatchVIP &&
		a.Builtin == b.Builtin && a.Description == b.Description &&
		x.AnySource == y.AnySource && x.AnyDestination == y.AnyDestination &&
		x.AnyService == y.AnyService && x.AnyFromZone == y.AnyFromZone && x.AnyToZone == y.AnyToZone &&
		x.Schedule == y.Schedule && x.ZoneRelation == y.ZoneRelation &&
		equalSignatureSlice(x.FromZones, y.FromZones) && equalSignatureSlice(x.ToZones, y.ToZones) &&
		equalSignatureSlice(x.Applications, y.Applications) && equalSignatureSlice(x.Users, y.Users) &&
		equalSignatureSlice(x.Unsupported, y.Unsupported)
}
