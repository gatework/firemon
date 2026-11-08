package analysis

import (
	"context"
	"errors"
	"maps"
	"slices"
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
	Chains                  map[fm.PolicyChain]fm.PolicyChain
	At                      time.Time
	Pairs                   []ZonePair
	Rules                   []fm.ID
	StaticNATs, DynamicNATs []fm.ID
	Interfaces              map[fm.ID]fm.ID
	VRFs                    map[string]string
	VRF                     string
	Clock                   *fm.ScheduleClock
}

// MigrationResult is atomic: Issues always implies Plan is nil.
type MigrationResult struct {
	Plan   *plan.Plan            `json:"-"`
	Issues []plan.MigrationIssue `json:"issues,omitempty"`
}

// Plan translates effective user-rule partitions in explicit zone pairs. Source
// terminal/default rules stay baseline behavior. Unknown or unrepresentable
// selected effects yield issues and no executable plan.
func (t PolicyMigrator) Plan(ctx context.Context, source, target *fm.Firewall, request MigrationRequest) (*MigrationResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if source == nil || target == nil || len(request.Pairs) == 0 || len(request.Pairs) > 100 {
		return nil, ErrInvalid
	}
	if !source.Complete() || !target.Complete() {
		return &MigrationResult{Issues: []plan.MigrationIssue{{Code: "incomplete-snapshot", Reason: "source and target must retain complete evidence"}}}, nil
	}
	limits := t.Planner.Engine.Limits.WithDefaults()
	visits := visitBudget(limits.MaxVisits)
	for _, count := range []int{len(request.Zones), len(request.Pairs), len(request.Rules), source.RuleCount(), len(request.Chains), len(request.StaticNATs), len(request.DynamicNATs), len(request.Interfaces), len(request.VRFs)} {
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
	contexts, err := t.Planner.Engine.Contexts(ctx, request.At, source)
	if err != nil {
		return migrationResult(nil, err)
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
	input := plan.MigrationInput{From: request.At, Rules: slices.Clone(request.Rules), StaticNATs: slices.Clone(request.StaticNATs), DynamicNATs: slices.Clone(request.DynamicNATs), Clock: request.Clock}
	for _, from := range slices.Sorted(maps.Keys(request.Interfaces)) {
		input.Interfaces = append(input.Interfaces, plan.MigrationInterfaceMapping{Source: from, Target: request.Interfaces[from]})
	}
	for _, from := range slices.Sorted(maps.Keys(request.VRFs)) {
		input.VRFs = append(input.VRFs, plan.MigrationVRFMapping{Source: from, Target: request.VRFs[from]})
	}
	selectedChains := make(map[fm.PolicyChain]bool)
	for rule := range source.DeclaredRules() {
		if !rule.Builtin() && (len(request.Rules) == 0 || selected[rule.ID()]) {
			selectedChains[rule.Chain()] = true
		}
	}
	seenContexts := make(map[plan.MigrationContext]bool)
	for _, q := range contexts {
		if err := visits.take(ctx, 1); err != nil {
			return nil, err
		}
		if !seenPairs[ZonePair{q.FromZone, q.ToZone}] || !selectedChains[q.Chain()] {
			continue
		}
		sourceContext := plan.MigrationContext{Chain: q.Chain(), FromZone: q.FromZone, ToZone: q.ToZone, VRF: request.VRF}
		if seenContexts[sourceContext] {
			continue
		}
		seenContexts[sourceContext] = true
		chain, err := targetChain(ctx, target, q.Chain(), request.Chains, &visits)
		if err != nil {
			return nil, err
		}
		input.Contexts = append(input.Contexts, plan.MigrationContextMapping{Source: sourceContext, Target: plan.MigrationContext{Chain: chain, FromZone: request.Zones[q.FromZone], ToZone: request.Zones[q.ToZone], VRF: request.VRFs[request.VRF]}})
	}
	p, err := t.Planner.Migrate(ctx, source, target, input)
	return migrationResult(p, err)
}

// Classify semantic refusals consistently during both context discovery and
// compilation. Execution failures must not become ordinary migration findings.
func migrationResult(p *plan.Plan, err error) (*MigrationResult, error) {
	if err != nil {
		var rejection *plan.MigrationError
		if errors.As(err, &rejection) {
			return &MigrationResult{Issues: []plan.MigrationIssue{rejection.Issue}}, nil
		}
		if errors.Is(err, plan.ErrUnsafe) || errors.Is(err, plan.ErrRender) || errors.Is(err, policy.ErrNotEquivalent) || errors.Is(err, policy.ErrNAT) {
			return &MigrationResult{Issues: []plan.MigrationIssue{{Code: "unproven-selection", Reason: err.Error()}}}, nil
		}
		return nil, err
	}
	return &MigrationResult{Plan: p}, nil
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
