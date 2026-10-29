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
}

// MigrationRequest maps one explicit selection into target native contexts.
type MigrationRequest struct {
	// Zones maps source zones to target zones. An explicitly present empty
	// destination value omits that target predicate, and requires an explicit
	// Chains entry. An absent map entry never means any zone. Ingress mappings
	// must remain concrete; the renderer enforces native chain bindings.
	Zones map[fm.ID]fm.ID
	// Chains maps native source chains to target chains. When omitted, only a
	// unique selected security chain may be inferred. ASA ACLs require mapping.
	Chains map[fm.PolicyChain]fm.PolicyChain
	At     time.Time
	Pairs  []ZonePair
	Rules  []fm.ID
}

// Plan translates effective user-rule partitions in explicit zone pairs. Source
// terminal/default rules stay baseline behavior. Unsupported or changing-time
// declarations reject the batch; selecting a subset is always explicit.
func (t PolicyMigrator) Plan(ctx context.Context, source, target *fm.Firewall, request MigrationRequest) (*plan.Plan, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if source == nil || target == nil || !source.Complete() || !target.Complete() || len(request.Pairs) == 0 || len(request.Pairs) > 100 {
		return nil, ErrInvalid
	}
	if len(source.StaticNATs())+len(source.DynamicNATs())+len(target.StaticNATs())+len(target.DynamicNATs()) > 0 {
		return nil, plan.ErrUnsafe
	}
	limits := t.Planner.Engine.Limits.WithDefaults()
	visits := visitBudget(limits.MaxVisits)
	for _, count := range []int{len(request.Zones), len(request.Pairs), len(request.Rules), source.RuleCount(), len(request.Chains)} {
		if err := visits.take(ctx, count); err != nil {
			return nil, err
		}
	}
	seenTargets := make(map[fm.ID]bool)
	for from, to := range request.Zones {
		if source.Zone(from) == nil || to != "" && (target.Zone(to) == nil || seenTargets[to]) || to == "" && len(request.Chains) == 0 {
			return nil, ErrInvalid
		}
		if to != "" {
			seenTargets[to] = true
		}
	}
	seenPairs := make(map[ZonePair]bool)
	for _, pair := range request.Pairs {
		_, destinationMapped := request.Zones[pair.To]
		if pair.From == "" || pair.To == "" || request.Zones[pair.From] == "" || !destinationMapped || seenPairs[pair] {
			return nil, ErrInvalid
		}
		seenPairs[pair] = true
	}
	selected := make(map[fm.ID]bool)
	for _, id := range request.Rules {
		if selected[id] || source.Rule(id) == nil || source.Rule(id).Builtin() {
			return nil, ErrInvalid
		}
		selected[id] = true
	}
	rules := source.Rules()
	contexts, err := t.Planner.Engine.Contexts(ctx, request.At, source)
	if err != nil {
		return nil, err
	}
	for from, to := range request.Chains {
		found := false
		for _, q := range contexts {
			if err := visits.take(ctx, 1); err != nil {
				return nil, err
			}
			found = found || from == (q.Chain())
		}
		exists, err := targetChainExists(ctx, target, to, &visits)
		if err != nil {
			return nil, err
		}
		if !found || strings.TrimSpace(to.RuleSet) == "" || !exists {
			return nil, ErrInvalid
		}
	}
	var intents []plan.RuleIntent
	for _, q := range contexts {
		if err := visits.take(ctx, 1); err != nil {
			return nil, err
		}
		if !q.At.Equal(request.At) || !seenPairs[ZonePair{q.FromZone, q.ToZone}] {
			continue
		}
		if err := visits.take(ctx, len(rules)); err != nil {
			return nil, err
		}
		// Time-varying shadowing also changes a selected rule's future effective
		// partitions, so reject any schedule in this source chain for now.
		for _, rule := range rules {
			if rule.Chain() == q.Chain() && rule.Schedule() != nil {
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
		if err := visits.take(ctx, len(result.Decisions)); err != nil {
			return nil, err
		}
		for _, decision := range result.Decisions {
			r := source.Rule(decision.Rule).Record()
			if r.Builtin || len(request.Rules) > 0 && !selected[r.ID] {
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
			chain, err := targetChain(ctx, target, q.Chain(), request.Chains, &visits)
			if err != nil {
				return nil, err
			}
			intentRequest := policy.Request{Scope: chain.Scope, RuleSet: chain.RuleSet, FromZone: request.Zones[q.FromZone], ToZone: request.Zones[q.ToZone], Traffic: decision.Traffic, At: request.At}
			intents = append(intents, plan.RuleIntent{Request: intentRequest, Action: r.Action, Log: r.Log, LogStart: r.LogStart, LogEnd: r.LogEnd})
		}
	}
	if len(intents) == 0 {
		return nil, plan.ErrUnsafe
	}
	// Different source chains can overlap the same target context. Preserve
	// only a single unambiguous effect; do not invent a cross-chain precedence.
	for i, a := range intents {
		for _, b := range intents[:i] {
			if err := visits.take(ctx, 1); err != nil {
				return nil, err
			}
			if !a.Request.SameContext(b.Request) {
				continue
			}
			hit, err := a.Request.Traffic.Intersection(b.Request.Traffic, limits.MaxRegions)
			if err != nil {
				return nil, err
			}
			if !hit.Empty() {
				return nil, plan.ErrUnsafe
			}
		}
	}
	return t.Planner.Transfer(ctx, target, intents, request.At)
}

func targetChainExists(ctx context.Context, target *fm.Firewall, chain fm.PolicyChain, visits *visitBudget) (bool, error) {
	if selected := target.Metadata().Context; selected != "" && selected != chain.Scope {
		return false, nil
	}
	if target.RuleCount() == 0 {
		return chain == (fm.PolicyChain{Scope: target.Metadata().Context, RuleSet: "security"}), nil
	}
	for rule := range target.OrderedRules() {
		if err := visits.take(ctx, 1); err != nil {
			return false, err
		}
		if chain == rule.Chain() {
			return true, nil
		}
	}
	return false, nil
}

func targetChain(ctx context.Context, target *fm.Firewall, source fm.PolicyChain, chains map[fm.PolicyChain]fm.PolicyChain, visits *visitBudget) (fm.PolicyChain, error) {
	if chain, ok := chains[source]; ok {
		return chain, nil
	}
	if len(chains) > 0 || target.Metadata().Vendor == "asa" {
		return fm.PolicyChain{}, ErrInvalid
	}
	selectedScope := target.Metadata().Context
	chain := fm.PolicyChain{Scope: selectedScope, RuleSet: "security"}
	found := false
	for rule := range target.OrderedRules() {
		if err := visits.take(ctx, 1); err != nil {
			return fm.PolicyChain{}, err
		}
		if selectedScope != "" && rule.Scope() != selectedScope {
			continue
		}
		candidate := rule.Chain()
		if candidate.RuleSet != "security" || found && candidate != chain {
			return fm.PolicyChain{}, ErrInvalid
		}
		chain, found = candidate, true
	}
	exists, err := targetChainExists(ctx, target, chain, visits)
	if err != nil {
		return fm.PolicyChain{}, err
	}
	if !exists {
		return fm.PolicyChain{}, ErrInvalid
	}
	return chain, nil
}
