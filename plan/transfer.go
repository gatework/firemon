package plan

import (
	"context"
	"slices"
	"strings"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/internal/dependency"
	"github.com/gatework/firemon/policy"
)

// RuleIntent states an exact traffic partition and its required observable
// action/logging. It never maps drop or a directional reset to generic deny.
type RuleIntent struct {
	Request               policy.Request
	Action                fm.Action
	Log, LogStart, LogEnd fm.Status
}

// Transfer inserts disjoint explicit partitions, preserving every prior rule's
// ownership outside their union across all zones/chains and future times.
func (p Planner) Transfer(ctx context.Context, before *fm.Firewall, intents []RuleIntent, from time.Time) (*Plan, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if before == nil || len(intents) == 0 || len(intents) > 100 || dependency.Nil(p.Renderer) {
		return nil, ErrInvalid
	}
	if !before.Complete() {
		return nil, ErrUnsafe
	}
	limits := p.Engine.Limits.WithDefaults()
	visits := visitBudget(limits.MaxVisits)
	if err := visits.take(ctx, before.RecordCount()); err != nil {
		return nil, err
	}
	d := before.Export()
	objects := len(d.Addresses) + len(d.Services)
	catalog, err := newObjectCatalog(ctx, &d, &visits)
	if err != nil {
		return nil, err
	}
	var rules []fm.RuleRecord
	var changes []Change
	for index, intent := range intents {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !intent.Action.Valid() || intent.Request.Traffic.Empty() {
			return nil, ErrInvalid
		}
		if intent.Request.EgressInterface != "" {
			return nil, ErrUnsafe
		}
		for _, s := range []fm.Status{intent.Log, intent.LogStart, intent.LogEnd} {
			if s != fm.Known && s != fm.Irrelevant {
				return nil, ErrUnsafe
			}
		}
		if (intent.Log == fm.Known) != (intent.LogStart == fm.Known || intent.LogEnd == fm.Known) {
			return nil, ErrUnsafe
		}
		q := intent.Request
		if q.RuleSet == "" {
			q.RuleSet = "security"
		}
		if q.Traffic.RegionCount() > limits.MaxRegions-len(rules) {
			return nil, policy.ErrBudget
		}
		if err := visits.take(ctx, q.Traffic.RegionCount()); err != nil {
			return nil, err
		}
		for _, box := range q.Traffic.Boxes() {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if err := visits.take(ctx, len(rules)); err != nil {
				return nil, err
			}
			id := generatedID("fm-transfer-", struct {
				Index int
				Box   flow.Box
			}{index, box})
			for before.Rule(id) != nil || slices.ContainsFunc(rules, func(r fm.RuleRecord) bool { return r.ID == id }) {
				if err := visits.take(ctx, len(rules)+1); err != nil {
					return nil, err
				}
				id += "-new"
			}
			m, err := catalog.match(ctx, box, q)
			if err != nil {
				return nil, err
			}
			r := fm.RuleRecord{Object: fm.Object{ID: id, Name: string(id), Scope: q.Scope}, RuleSet: q.RuleSet, Position: len(rules), Match: m, Action: intent.Action, Log: intent.Log, LogStart: intent.LogStart, LogEnd: intent.LogEnd}
			rules = append(rules, r)
			changes = append(changes, Change{Kind: CreateRule, Rule: id, Sources: m.Sources, Destinations: m.Destinations, Services: m.Services})
		}
	}
	if err := visits.take(ctx, len(d.Rules)); err != nil {
		return nil, err
	}
	slices.SortStableFunc(d.Rules, func(a, b fm.RuleRecord) int {
		if a.Position < b.Position {
			return -1
		}
		if a.Position > b.Position {
			return 1
		}
		return strings.Compare(string(a.ID), string(b.ID))
	})
	if err := visits.take(ctx, len(d.Rules)); err != nil {
		return nil, err
	}
	for i := range d.Rules {
		d.Rules[i].Position = i + len(rules)
	}
	d.Rules = append(rules, d.Rules...)
	after, err := fm.Seal(d)
	if err != nil {
		return nil, err
	}
	proof, err := p.proveTransfers(ctx, before, after, changes, from, &visits)
	if err != nil {
		return nil, err
	}
	commands, err := p.Renderer.Render(ctx, before, after, changes)
	if err != nil {
		return nil, err
	}
	if len(commands) == 0 {
		return nil, ErrUnsafe
	}
	result := &Plan{before: before, after: after, changes: changes, commands: slices.Clone(commands), proof: proof, engine: p.Engine, transfers: slices.Clone(intents), transferFrom: from, cost: Cost{NewRules: len(rules), NewObjects: len(d.Addresses) + len(d.Services) - objects}}
	if err := result.seal(); err != nil {
		return nil, err
	}
	return result, nil
}

func (p Planner) proveTransfers(ctx context.Context, before, after *fm.Firewall, changes []Change, from time.Time, visits *visitBudget) (Proof, error) {
	if err := p.Engine.PreserveNAT(ctx, before, after, from); err != nil {
		return Proof{}, err
	}
	contexts, err := p.Engine.Contexts(ctx, from, before, after)
	if err != nil {
		return Proof{}, err
	}
	if err := visits.take(ctx, len(changes)); err != nil {
		return Proof{}, err
	}
	allPermit := true
	for _, c := range changes {
		r := after.Rule(c.Rule)
		if r == nil || c.Kind != CreateRule {
			return Proof{}, ErrUnsafe
		}
		allPermit = allPermit && r.Action() == fm.Permit
	}
	limits := p.Engine.Limits.WithDefaults()
	cost := before.RuleCount() + after.RuleCount() + len(changes)
	for _, q := range contexts {
		if err := visits.take(ctx, cost); err != nil {
			return Proof{}, err
		}
		prior, err := p.Engine.Query(ctx, before, q)
		if err != nil {
			return Proof{}, err
		}
		next, err := p.Engine.Query(ctx, after, q)
		if err != nil {
			return Proof{}, err
		}
		if !prior.Complete || !next.Complete || !prior.Unknown.Empty() || !next.Unknown.Empty() {
			return Proof{}, ErrUnsafe
		}
		if err := visits.take(ctx, len(next.Trace)); err != nil {
			return Proof{}, err
		}
		owned := make(map[fm.ID]flow.Traffic)
		for _, trace := range next.Trace {
			if err := ctx.Err(); err != nil {
				return Proof{}, err
			}
			owned[trace.Rule] = trace.Traffic
		}
		var target flow.Traffic
		for _, change := range changes {
			if err := ctx.Err(); err != nil {
				return Proof{}, err
			}
			r := after.Rule(change.Rule).Record()
			if r.Scope != q.Scope || r.RuleSet != q.RuleSet {
				continue
			}
			hit, known, err := p.Engine.Match(ctx, after, r.Match, q, q.Traffic)
			if err != nil {
				return Proof{}, err
			}
			if !known {
				return Proof{}, ErrUnsafe
			}
			// Every intended partition must retain its complete declaration. A
			// conflicting earlier transfer must not silently consume any of it.
			if same, err := equal(hit, owned[r.ID], limits.MaxRegions); err != nil {
				return Proof{}, err
			} else if !same {
				return Proof{}, ErrUnsafe
			}
			target, err = target.Union(hit, limits.MaxRegions)
			if err != nil {
				return Proof{}, err
			}
		}
		if err := preservedOutside(ctx, prior, next, target, limits.MaxRegions, visits); err != nil {
			return Proof{}, err
		}
	}
	return Proof{BaseDigest: before.SemanticDigest(), ResultDigest: after.SemanticDigest(), TargetAllowed: allPermit, TargetSatisfied: true, OutsidePreserved: true, NATUnchanged: true}, nil
}

func preservedOutside(ctx context.Context, prior, next policy.Result, target flow.Traffic, limit int, visits *visitBudget) error {
	if err := visits.take(ctx, len(next.Trace)+len(prior.Trace)); err != nil {
		return err
	}
	traces := make(map[fm.ID]flow.Traffic)
	for _, trace := range next.Trace {
		if err := ctx.Err(); err != nil {
			return err
		}
		traces[trace.Rule] = trace.Traffic
	}
	for _, trace := range prior.Trace {
		if err := ctx.Err(); err != nil {
			return err
		}
		a, err := trace.Traffic.Difference(target, limit)
		if err != nil {
			return err
		}
		b, err := traces[trace.Rule].Difference(target, limit)
		if err != nil {
			return err
		}
		if same, err := equal(a, b, limit); err != nil {
			return err
		} else if !same {
			return ErrUnsafe
		}
		delete(traces, trace.Rule)
	}
	for _, traffic := range traces {
		if err := visits.take(ctx, 1); err != nil {
			return err
		}
		outside, err := traffic.Difference(target, limit)
		if err != nil {
			return err
		}
		if !outside.Empty() {
			return ErrUnsafe
		}
	}
	a, err := prior.Unmatched.Difference(target, limit)
	if err != nil {
		return err
	}
	b, err := next.Unmatched.Difference(target, limit)
	if err != nil {
		return err
	}
	if same, err := equal(a, b, limit); err != nil {
		return err
	} else if !same {
		return ErrUnsafe
	}
	return nil
}
