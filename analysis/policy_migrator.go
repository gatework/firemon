package analysis

import (
	"context"
	"strings"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/policy"
)

type ZonePair struct{ From, To fm.ID }

type PolicyMigrator struct {
	Planner plan.Planner
	// Zones maps source zones to target zones. An explicitly present empty
	// destination value omits that target predicate, and requires an explicit
	// Chains entry. An absent map entry never means any zone. Ingress mappings
	// must remain concrete; the renderer enforces native chain bindings.
	Zones map[fm.ID]fm.ID
	// Chains maps native source chains to target chains. When omitted, only a
	// unique selected security chain may be inferred. ASA ACLs require mapping.
	Chains map[fm.PolicyChain]fm.PolicyChain
	At     time.Time
}

// Plan translates effective user-rule partitions in explicit zone pairs. Source
// terminal/default rules stay baseline behavior. Unsupported or changing-time
// declarations reject the batch; selecting a subset is always explicit.
func (t PolicyMigrator) Plan(ctx context.Context, source, target *fm.Firewall, pairs []ZonePair, selection []fm.ID) (*plan.Plan, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if source == nil || target == nil || !source.Complete() || !target.Complete() || len(pairs) == 0 || len(pairs) > 100 {
		return nil, ErrInvalid
	}
	if len(source.StaticNATs())+len(source.DynamicNATs())+len(target.StaticNATs())+len(target.DynamicNATs()) > 0 {
		return nil, plan.ErrUnsafe
	}
	seenTargets := make(map[fm.ID]bool)
	for from, to := range t.Zones {
		if source.Zone(from) == nil || to != "" && (target.Zone(to) == nil || seenTargets[to]) || to == "" && len(t.Chains) == 0 {
			return nil, ErrInvalid
		}
		if to != "" {
			seenTargets[to] = true
		}
	}
	seenPairs := make(map[ZonePair]bool)
	for _, pair := range pairs {
		_, destinationMapped := t.Zones[pair.To]
		if pair.From == "" || pair.To == "" || t.Zones[pair.From] == "" || !destinationMapped || seenPairs[pair] {
			return nil, ErrInvalid
		}
		seenPairs[pair] = true
	}
	selected := make(map[fm.ID]bool)
	for _, id := range selection {
		if selected[id] || source.Rule(id) == nil || source.Rule(id).Record().Builtin {
			return nil, ErrInvalid
		}
		selected[id] = true
	}
	rules := source.Rules()
	if len(rules) > 100000 {
		return nil, policy.ErrBudget
	}
	contexts, err := t.Planner.Engine.Contexts(ctx, t.At, source)
	if err != nil {
		return nil, err
	}
	for from, to := range t.Chains {
		found := false
		for _, q := range contexts {
			found = found || from == (q.Chain())
		}
		if !found || strings.TrimSpace(to.RuleSet) == "" || !targetChainExists(target, to) {
			return nil, ErrInvalid
		}
	}
	var intents []plan.RuleIntent
	visits := 0
	for _, q := range contexts {
		if !q.At.Equal(t.At) || !seenPairs[ZonePair{q.FromZone, q.ToZone}] {
			continue
		}
		if len(rules) > 100000-visits {
			return nil, policy.ErrBudget
		}
		visits += len(rules)
		// Time-varying shadowing also changes a selected rule's future effective
		// partitions, so reject any schedule in this source chain for now.
		for _, rule := range rules {
			r := rule.Record()
			if r.Scope == q.Scope && r.RuleSet == q.RuleSet && r.Match.Schedule != "" {
				return nil, plan.ErrUnsafe
			}
		}
		result, err := t.Planner.Engine.Query(ctx, source, q)
		if err != nil {
			return nil, err
		}
		if !result.Complete || !result.Unknown.Empty() {
			return nil, plan.ErrUnsafe
		}
		for _, trace := range result.Trace {
			r := source.Rule(trace.Rule).Record()
			if r.Builtin || len(selection) > 0 && !selected[r.ID] {
				continue
			}
			if len(intents) >= 100 {
				return nil, policy.ErrBudget
			}
			// A vendor's generic deny/reject can have application-dependent side
			// effects. Keep those within a vendor; explicit drop/reset stays typed.
			if source.Metadata().Vendor != target.Metadata().Vendor && (r.Action == fm.Deny || r.Action == fm.Reject) {
				return nil, plan.ErrUnsafe
			}
			if r.Disabled || r.Log == fm.Unknown || r.LogStart == fm.Unknown || r.LogEnd == fm.Unknown {
				return nil, plan.ErrUnsafe
			}
			chain, err := t.targetChain(target, q.Chain())
			if err != nil {
				return nil, err
			}
			request := policy.Request{Scope: chain.Scope, RuleSet: chain.RuleSet, FromZone: t.Zones[q.FromZone], ToZone: t.Zones[q.ToZone], Traffic: trace.Traffic, At: t.At}
			intents = append(intents, plan.RuleIntent{Request: request, Action: r.Action, Log: r.Log, LogStart: r.LogStart, LogEnd: r.LogEnd})
		}
	}
	if len(intents) == 0 {
		return nil, plan.ErrUnsafe
	}
	// Different source chains can overlap the same target context. Preserve
	// only a single unambiguous effect; do not invent a cross-chain precedence.
	for i, a := range intents {
		for _, b := range intents[:i] {
			if !sameContext(a.Request, b.Request) {
				continue
			}
			hit, err := a.Request.Traffic.Intersection(b.Request.Traffic, 4096)
			if err != nil {
				return nil, err
			}
			if !hit.Empty() {
				return nil, plan.ErrUnsafe
			}
		}
	}
	return t.Planner.Transfer(ctx, target, intents, t.At)
}

func targetChainExists(target *fm.Firewall, chain fm.PolicyChain) bool {
	if selected := target.Metadata().Context; selected != "" && selected != chain.Scope {
		return false
	}
	rules := target.Rules()
	if len(rules) == 0 {
		return chain == (fm.PolicyChain{Scope: target.Metadata().Context, RuleSet: "security"})
	}
	for _, rule := range rules {
		r := rule.Record()
		if chain == (fm.PolicyChain{Scope: r.Scope, RuleSet: r.RuleSet}) {
			return true
		}
	}
	return false
}

func (t PolicyMigrator) targetChain(target *fm.Firewall, source fm.PolicyChain) (fm.PolicyChain, error) {
	if chain, ok := t.Chains[source]; ok {
		return chain, nil
	}
	if len(t.Chains) > 0 || target.Metadata().Vendor == "asa" {
		return fm.PolicyChain{}, ErrInvalid
	}
	selectedScope := target.Metadata().Context
	chain := fm.PolicyChain{Scope: selectedScope, RuleSet: "security"}
	found := false
	for _, rule := range target.Rules() {
		r := rule.Record()
		if selectedScope != "" && r.Scope != selectedScope {
			continue
		}
		candidate := fm.PolicyChain{Scope: r.Scope, RuleSet: r.RuleSet}
		if r.RuleSet != "security" || found && candidate != chain {
			return fm.PolicyChain{}, ErrInvalid
		}
		chain, found = candidate, true
	}
	if !targetChainExists(target, chain) {
		return fm.PolicyChain{}, ErrInvalid
	}
	return chain, nil
}
