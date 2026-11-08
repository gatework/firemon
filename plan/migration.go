package plan

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/policy"
)

// MigrationContext identifies policy coordinates explicitly. Addresses are never
// renamed by migration; interface and routing mappings are separate evidence.
type MigrationContext struct {
	Chain            fm.PolicyChain
	FromZone, ToZone fm.ID
	VRF              string
}
type MigrationContextMapping struct{ Source, Target MigrationContext }
type MigrationInterfaceMapping struct{ Source, Target fm.ID }
type MigrationVRFMapping struct{ Source, Target string }

// MigrationInput is the resolved selection, not a proposed target graph. Empty
// Rules selects all declared rules in the listed source contexts. Empty NAT
// lists select the effective translation dependencies of those source rules;
// explicit lists must contain the complete dependency closure. Target identities
// are never inferred from similar source names.
type MigrationInput struct {
	Contexts                       []MigrationContextMapping
	Rules, StaticNATs, DynamicNATs []fm.ID
	Interfaces                     []MigrationInterfaceMapping
	VRFs                           []MigrationVRFMapping
	From                           time.Time
	Clock                          *fm.ScheduleClock
}

// MigrationIssue identifies a selected effect which cannot be represented or
// proved. It carries no executable partial result.
type MigrationIssue struct {
	Object fm.ID  `json:"object,omitempty"`
	Code   string `json:"code"`
	Reason string `json:"reason"`
}
type MigrationError struct{ Issue MigrationIssue }

func (e *MigrationError) Error() string { return "migration: " + e.Issue.Code + ": " + e.Issue.Reason }
func (e *MigrationError) Unwrap() error { return ErrUnsafe }
func migrationFailure(id fm.ID, code, reason string) error {
	return &MigrationError{MigrationIssue{Object: id, Code: code, Reason: reason}}
}

type migrationIntent struct {
	source  *fm.Firewall
	input   MigrationInput
	options NativeOptions
}

func cloneMigrationInput(in MigrationInput) MigrationInput {
	in.Contexts = slices.Clone(in.Contexts)
	in.Rules = slices.Clone(in.Rules)
	in.StaticNATs = slices.Clone(in.StaticNATs)
	in.DynamicNATs = slices.Clone(in.DynamicNATs)
	in.Interfaces = slices.Clone(in.Interfaces)
	in.VRFs = slices.Clone(in.VRFs)
	if in.Clock != nil {
		v := *in.Clock
		in.Clock = &v
	}
	return in
}
func (i migrationIntent) approval(p *Plan) ([]byte, error) {
	return encodeApproval(p, "migration", struct {
		SourceDigest   string
		SourceMetadata fm.Metadata
		TargetMetadata fm.Metadata
		Input          MigrationInput
		Options        NativeOptions
	}{i.source.SemanticDigest(), i.source.Metadata(), p.before.Metadata(), i.input, i.options})
}
func (i migrationIntent) verify(ctx context.Context, p *Plan, before, after *fm.Firewall, visits *visitBudget) error {
	_, _, err := (Planner{Engine: p.engine}).proveMigration(ctx, i.source, before, after, i.input, visits)
	return err
}

// MigrationSource returns the immutable source snapshot bound into approval.
// Deployment verifies the target independently; refreshing the source requires
// constructing and approving a new plan.
func (p *Plan) MigrationSource() *fm.Firewall {
	if i, ok := p.intent.(migrationIntent); ok {
		return i.source
	}
	return nil
}
func (p *Plan) MigrationInput() (MigrationInput, bool) {
	i, ok := p.intent.(migrationIntent)
	if !ok {
		return MigrationInput{}, false
	}
	return cloneMigrationInput(i.input), true
}

func (c MigrationContext) request(at time.Time, traffic flow.Traffic) policy.Request {
	return policy.Request{Scope: c.Chain.Scope, RuleSet: c.Chain.RuleSet, FromZone: c.FromZone, ToZone: c.ToZone, At: at, Traffic: traffic}
}
func (c MigrationContext) matches(q policy.Request) bool {
	return c.Chain == q.Chain() && (c.FromZone == "" || c.FromZone == q.FromZone) && (c.ToZone == "" || c.ToZone == q.ToZone)
}
func migrationSelected(input MigrationInput, rule *fm.Rule) bool {
	return !rule.Builtin() && (len(input.Rules) == 0 || slices.Contains(input.Rules, rule.ID()))
}

// Migrate proves the selected source behavior and preservation of every target
// decision outside that behavior. The source graph, resolved mappings and both
// captures participate in approval and replay.
func (p Planner) Migrate(ctx context.Context, source, before *fm.Firewall, input MigrationInput) (*Plan, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if source == nil || before == nil || len(input.Contexts) == 0 || len(input.Contexts) > 100 {
		return nil, ErrInvalid
	}
	if !source.Complete() || !before.Complete() {
		return nil, migrationFailure("", "incomplete-snapshot", "source and target must retain complete evidence")
	}
	limits := p.Engine.Limits.WithDefaults()
	visits := visitBudget(limits.MaxVisits)
	if err := visits.nativeCounts(ctx, source.DeclarationSize(), before.DeclarationSize(), len(input.Contexts), len(input.Rules), len(input.StaticNATs), len(input.DynamicNATs), len(input.Interfaces), len(input.VRFs)); err != nil {
		return nil, err
	}
	input = cloneMigrationInput(input)
	if err := validateMigrationInput(ctx, source, before, input, &visits); err != nil {
		return nil, err
	}
	var err error
	input, err = p.resolveMigrationNAT(ctx, source, before, input, &visits)
	if err != nil {
		return nil, err
	}
	origins := make(map[fm.ID][]fm.ID)
	after, changes, native, err := p.compileMigrationPolicy(ctx, source, before, input, &visits, origins)
	if err != nil {
		return nil, err
	}
	if len(input.StaticNATs)+len(input.DynamicNATs) > 0 {
		compiler, ok := p.Renderer.(MigrationNATCompiler)
		if !ok {
			return nil, migrationFailure("", "nat-compilation", "target driver has no native migration compiler")
		}
		var mappings []MigrationRuleMapping
		for _, id := range slices.Sorted(maps.Keys(origins)) {
			mappings = append(mappings, MigrationRuleMapping{Source: id, Targets: slices.Clone(origins[id])})
		}
		native, err = compiler.CompileMigrationNAT(ctx, source, before, NativeMigrationDraft{Input: cloneMigrationInput(input), Changes: cloneNativeChanges(native), Rules: mappings, Limits: limits})
		if err != nil {
			return nil, err
		}
		if err := visits.nativeAdditions(ctx, native.Additions); err != nil {
			return nil, err
		}
		if err := visits.take(ctx, len(native.Rules)); err != nil {
			return nil, err
		}
		if len(native.Additions.StaticNATs)+len(native.Additions.DynamicNATs) == 0 {
			return nil, migrationFailure("", "missing-translation", "compiler omitted selected NAT declarations")
		}
		data := before.Export()
		for i := range data.Rules {
			data.Rules[i].Position += len(native.Additions.Rules)
		}
		nativeAppend(&data, native.Additions)
		after, err = fm.Seal(data)
		if err != nil {
			return nil, err
		}
		if err := ValidateNativeChanges(ctx, before, after, native); err != nil {
			return nil, err
		}
		changes = native.Rules
	}
	proof, natProof, err := p.proveMigration(ctx, source, before, after, input, &visits)
	if err != nil {
		return nil, err
	}
	if err := p.preflightReadback(ctx, before, after); err != nil {
		return nil, err
	}
	var commands []string
	if len(native.Additions.Schedules)+len(native.Additions.StaticNATs)+len(native.Additions.DynamicNATs) > 0 {
		renderer := p.NativeRenderer
		if renderer == nil {
			renderer, _ = p.Renderer.(NativeRenderer)
		}
		if renderer == nil {
			return nil, migrationFailure("", "schedule-rendering", "target has no native schedule renderer")
		}
		commands, err = renderer.RenderNative(ctx, before, after, native)
	} else {
		commands, err = p.renderChanges(ctx, before, after, changes)
	}
	if err != nil {
		return nil, err
	}
	if len(commands) == 0 {
		return nil, migrationFailure("", "empty-selection", "selection has no executable effect")
	}
	result := &Plan{before: before, after: after, changes: changes, commands: commands, nativeChanges: native, natProof: natProof, proof: proof, engine: p.Engine,
		intent: migrationIntent{source: source, input: input, options: NativeOptions{MaxCandidates: p.effectiveOptions().MaxCandidates, Limits: limits}},
		cost:   Cost{NewRules: len(changes), NewObjects: len(native.Additions.Addresses) + len(native.Additions.Services) + len(native.Additions.Schedules)}}
	if err := result.seal(); err != nil {
		return nil, err
	}
	return result, nil
}

func validateMigrationInput(ctx context.Context, source, target *fm.Firewall, input MigrationInput, visits *visitBudget) error {
	seen := make(map[MigrationContext]bool)
	for _, mapping := range input.Contexts {
		if err := visits.take(ctx, 1); err != nil {
			return err
		}
		a, b := mapping.Source, mapping.Target
		if seen[a] || a.Chain.RuleSet == "" || b.Chain.RuleSet == "" || a.FromZone == "" || a.ToZone == "" || b.FromZone == "" || source.Zone(a.FromZone) == nil || source.Zone(a.ToZone) == nil || target.Zone(b.FromZone) == nil || b.ToZone != "" && target.Zone(b.ToZone) == nil {
			return ErrInvalid
		}
		seen[a] = true
	}
	selected := make(map[fm.ID]bool)
	for _, id := range input.Rules {
		if err := visits.take(ctx, 1); err != nil {
			return err
		}
		r := source.Rule(id)
		if selected[id] || r == nil || r.Builtin() {
			return ErrInvalid
		}
		selected[id] = true
	}
	interfaces := make(map[fm.ID]bool)
	for _, mapping := range input.Interfaces {
		if err := visits.take(ctx, 1); err != nil {
			return err
		}
		if source.Interface(mapping.Source) == nil || target.Interface(mapping.Target) == nil || interfaces[mapping.Source] {
			return ErrInvalid
		}
		interfaces[mapping.Source] = true
	}
	vrfs := make(map[string]bool)
	for _, mapping := range input.VRFs {
		if err := visits.take(ctx, 1); err != nil {
			return err
		}
		if vrfs[mapping.Source] {
			return ErrInvalid
		}
		vrfs[mapping.Source] = true
	}
	return nil
}

func (p Planner) compileMigrationPolicy(ctx context.Context, source, before *fm.Firewall, input MigrationInput, visits *visitBudget, origins map[fm.ID][]fm.ID) (*fm.Firewall, []Change, NativeChanges, error) {
	d := before.Export()
	addressCount, serviceCount := len(d.Addresses), len(d.Services)
	catalog, err := newObjectCatalog(ctx, before, &d, p.Engine.Limits.WithDefaults(), visits)
	if err != nil {
		return nil, nil, NativeChanges{}, err
	}
	all, err := flow.AllTraffic(p.Engine.Limits.WithDefaults().MaxRegions)
	if err != nil {
		return nil, nil, NativeChanges{}, err
	}
	// Timeless chains use effective regions, removing hidden declarations.
	// Scheduled chains retain native order; the source proof rejects any selected
	// subset whose omitted predecessors change future effective behavior.
	timed := make(map[fm.PolicyChain]bool)
	for rule := range source.DeclaredRules() {
		if rule.Schedule() != nil {
			timed[rule.Chain()] = true
		}
	}
	var rules []fm.RuleRecord
	var changes []Change
	schedules := make(map[fm.ID]fm.ID)
	for _, mapping := range input.Contexts {
		q := mapping.Source.request(input.From, all)
		effective := make(map[fm.ID]flow.Traffic)
		if !timed[q.Chain()] {
			result, err := p.Engine.Query(ctx, source, q)
			if err != nil {
				return nil, nil, NativeChanges{}, err
			}
			if !result.Complete || !result.Unknown.Empty() {
				return nil, nil, NativeChanges{}, migrationFailure("", "unknown-source", "source policy contains unresolved conditions")
			}
			for _, decision := range result.Decisions {
				effective[decision.Rule] = decision.Traffic
			}
		}
		for rule := range source.OrderedRules() {
			if err := visits.take(ctx, 1); err != nil {
				return nil, nil, NativeChanges{}, err
			}
			if !migrationSelected(input, rule) || rule.Chain() != q.Chain() {
				continue
			}
			r := rule.Record()
			if r.Disabled {
				return nil, nil, NativeChanges{}, migrationFailure(r.ID, "disabled-rule", "disabled selected declarations have no established migration intent")
			}
			if r.Log == fm.Unknown || r.LogStart == fm.Unknown || r.LogEnd == fm.Unknown {
				return nil, nil, NativeChanges{}, migrationFailure(r.ID, "unknown-logging", "selected logging behavior is unknown")
			}
			if source.Metadata().Vendor != before.Metadata().Vendor && (r.Action == fm.Deny || r.Action == fm.Reject) {
				return nil, nil, NativeChanges{}, migrationFailure(r.ID, "native-action", "generic deny/reject effects are vendor-specific")
			}
			traffic := effective[r.ID]
			if timed[q.Chain()] {
				match := r.Match
				match.Schedule = ""
				var known bool
				traffic, known, err = p.Engine.Match(ctx, source, match, q, all)
				if err != nil {
					return nil, nil, NativeChanges{}, err
				}
				if !known {
					return nil, nil, NativeChanges{}, migrationFailure(r.ID, "unknown-match", "selected match cannot be represented exactly")
				}
			}
			if traffic.Empty() {
				continue
			}
			schedule := fm.ID("")
			if r.Match.Schedule != "" {
				if input.Clock == nil || input.Clock.Validate(before.Metadata()) != nil {
					return nil, nil, NativeChanges{}, migrationFailure(r.ID, "target-clock", "schedule migration needs target capture-bound clock evidence")
				}
				schedule = schedules[r.Match.Schedule]
				if schedule == "" {
					s := source.Schedule(r.Match.Schedule).Record()
					if source.Schedule(r.Match.Schedule).HasRecurrence() && s.Timezone != input.Clock.Timezone {
						return nil, nil, NativeChanges{}, migrationFailure(r.ID, "recurring-timezone", "recurring source and target clocks need the same civil timezone")
					}
					s.ID = generatedID("fm-time-", struct {
						Source string
						ID     fm.ID
					}{source.SemanticDigest(), s.ID})
					// Schedule catalogs belong to the selected capture domain; rule
					// chain scopes are not native schedule namespaces.
					s.Name, s.Scope = string(s.ID), ""
					s.Spans = nil
					s.Timezone = input.Clock.Timezone
					if before.Schedule(s.ID) != nil {
						return nil, nil, NativeChanges{}, migrationFailure(r.ID, "schedule-collision", "target schedule identity already exists")
					}
					d.Schedules = append(d.Schedules, s)
					schedule = s.ID
					schedules[r.Match.Schedule] = schedule
				}
			}
			for _, box := range traffic.Regions() {
				if err := visits.take(ctx, 1); err != nil {
					return nil, nil, NativeChanges{}, err
				}
				if len(rules) >= p.Engine.Limits.WithDefaults().MaxRegions {
					return nil, nil, NativeChanges{}, policy.ErrBudget
				}
				match, err := catalog.match(ctx, box, mapping.Target.request(input.From, traffic))
				if err != nil {
					return nil, nil, NativeChanges{}, err
				}
				match.Schedule = schedule
				id := generatedID("fm-migrate-", struct {
					Source  fm.ID
					Context MigrationContext
					Box     flow.TrafficRegion
				}{r.ID, mapping.Target, box})
				n := fm.RuleRecord{Object: fm.Object{ID: id, Name: string(id), Scope: mapping.Target.Chain.Scope}, RuleSet: mapping.Target.Chain.RuleSet, Position: len(rules), Match: match, Action: r.Action, Log: r.Log, LogStart: r.LogStart, LogEnd: r.LogEnd}
				id, err = catalog.names.rule(ctx, id, n)
				if err != nil {
					return nil, nil, NativeChanges{}, err
				}
				n.ID, n.Name = id, string(id)
				origins[r.ID] = append(origins[r.ID], id)
				rules = append(rules, n)
				changes = append(changes, Change{Kind: CreateRule, Rule: id, Sources: match.Sources, Destinations: match.Destinations, Services: match.Services})
			}
		}
	}
	if len(rules) == 0 {
		return nil, nil, NativeChanges{}, migrationFailure("", "empty-selection", "selection has no effective user rule")
	}
	// Keep native baseline order while placing the new explicit partitions first.
	old := make([]fm.RuleRecord, 0, before.RuleCount())
	for rule := range before.OrderedRules() {
		r := rule.Record()
		r.Position = len(rules) + len(old)
		old = append(old, r)
	}
	d.Rules = append(slices.Clone(rules), old...)
	after, err := fm.Seal(d)
	if err != nil {
		return nil, nil, NativeChanges{}, err
	}
	native := NativeChanges{Rules: changes, Clock: input.Clock, Additions: NativeAdditions{Rules: rules, Addresses: d.Addresses[addressCount:], Services: d.Services[serviceCount:], Schedules: d.Schedules[before.ScheduleCount():]}}
	return after, changes, native, nil
}

type migrationEffect struct {
	Action          fm.Action
	Log, Start, End fm.Status
}

func migrationEffects(result policy.Result, fw *fm.Firewall, selected func(*fm.Rule) bool, limit int) (map[migrationEffect]flow.Traffic, flow.Traffic, error) {
	out := make(map[migrationEffect]flow.Traffic)
	var domain flow.Traffic
	if !result.Complete || !result.Unknown.Empty() {
		return nil, domain, ErrUnsafe
	}
	for _, decision := range result.Decisions {
		rule := fw.Rule(decision.Rule)
		if rule == nil || !decision.Known {
			return nil, domain, ErrUnsafe
		}
		if selected != nil && !selected(rule) {
			continue
		}
		r := rule.Record()
		key := migrationEffect{r.Action, r.Log, r.LogStart, r.LogEnd}
		var err error
		out[key], err = out[key].Union(decision.Traffic, limit)
		if err != nil {
			return nil, domain, err
		}
		domain, err = domain.Union(decision.Traffic, limit)
		if err != nil {
			return nil, domain, err
		}
	}
	return out, domain, nil
}

func (p Planner) proveMigration(ctx context.Context, source, before, after *fm.Firewall, input MigrationInput, visits *visitBudget) (Proof, *policy.NATProof, error) {
	var natProof *policy.NATProof
	if source.StaticNATCount()+source.DynamicNATCount()+before.StaticNATCount()+before.DynamicNATCount()+after.StaticNATCount()+after.DynamicNATCount() > 0 {
		proof, err := p.proveMigrationNAT(ctx, source, before, after, input, visits)
		if err != nil {
			return Proof{}, nil, err
		}
		natProof = &proof
	} else if err := p.Engine.PreserveNAT(ctx, before, after, input.From); err != nil {
		return Proof{}, nil, err
	}
	contexts, err := p.Engine.Contexts(ctx, input.From, source, before, after)
	if err != nil {
		return Proof{}, nil, err
	}
	limit := p.Engine.Limits.WithDefaults().MaxRegions
	times := make(map[time.Time]bool)
	for _, q := range contexts {
		times[q.At] = true
	}
	type domainKey struct {
		Context MigrationContext
		At      time.Time
	}
	domains := make(map[domainKey]flow.Traffic)
	allPermit := true
	for at := range times {
		for _, mapping := range input.Contexts {
			if err := visits.take(ctx, source.RuleCount()+after.RuleCount()); err != nil {
				return Proof{}, nil, err
			}
			all, err := flow.AllTraffic(limit)
			if err != nil {
				return Proof{}, nil, err
			}
			prior, err := p.Engine.Query(ctx, source, mapping.Source.request(at, all))
			if err != nil {
				return Proof{}, nil, err
			}
			want, domain, err := migrationEffects(prior, source, func(r *fm.Rule) bool { return migrationSelected(input, r) }, limit)
			if err != nil {
				return Proof{}, nil, err
			}
			key := domainKey{mapping.Target, at}
			if hit, err := domains[key].Intersection(domain, limit); err != nil {
				return Proof{}, nil, err
			} else if !hit.Empty() {
				return Proof{}, nil, migrationFailure("", "overlapping-contexts", "source contexts overlap one target selection")
			}
			domains[key], err = domains[key].Union(domain, limit)
			if err != nil {
				return Proof{}, nil, err
			}
			if domain.Empty() {
				continue
			}
			next, err := p.Engine.Query(ctx, after, mapping.Target.request(at, domain))
			if err != nil {
				return Proof{}, nil, err
			}
			got, covered, err := migrationEffects(next, after, nil, limit)
			if err != nil {
				return Proof{}, nil, err
			}
			if same, err := covered.Equal(domain, limit); err != nil {
				return Proof{}, nil, err
			} else if !same {
				return Proof{}, nil, migrationFailure("", "source-behavior", "target leaves selected source traffic unmatched")
			}
			if len(want) != len(got) {
				return Proof{}, nil, migrationFailure("", "source-behavior", "target action or logging differs from the source")
			}
			for effect, traffic := range want {
				allPermit = allPermit && effect.Action == fm.Permit
				if same, err := traffic.Equal(got[effect], limit); err != nil {
					return Proof{}, nil, err
				} else if !same {
					return Proof{}, nil, migrationFailure("", "source-behavior", "target changes a selected action, log event or traffic partition")
				}
			}
		}
	}
	baseContexts, err := p.Engine.Contexts(ctx, input.From, before, after)
	if err != nil {
		return Proof{}, nil, err
	}
	var targetContexts []policy.Request
	seenContexts := make(map[MigrationContext]bool)
	for _, q := range baseContexts {
		key := MigrationContext{Chain: q.Chain(), FromZone: q.FromZone, ToZone: q.ToZone}
		if seenContexts[key] {
			continue
		}
		seenContexts[key] = true
		for at := range times {
			if len(targetContexts) >= p.Engine.Limits.WithDefaults().MaxCombinations {
				return Proof{}, nil, policy.ErrBudget
			}
			q.At = at
			targetContexts = append(targetContexts, q)
		}
	}
	for _, q := range targetContexts {
		if err := visits.take(ctx, before.RuleCount()+after.RuleCount()+len(input.Contexts)); err != nil {
			return Proof{}, nil, err
		}
		var domain flow.Traffic
		for _, mapping := range input.Contexts {
			if mapping.Target.matches(q) {
				domain, err = domain.Union(domains[domainKey{mapping.Target, q.At}], limit)
				if err != nil {
					return Proof{}, nil, err
				}
			}
		}
		prior, err := p.Engine.Query(ctx, before, q)
		if err != nil {
			return Proof{}, nil, err
		}
		next, err := p.Engine.Query(ctx, after, q)
		if err != nil {
			return Proof{}, nil, err
		}
		if !prior.Complete || !next.Complete || !prior.Unknown.Empty() || !next.Unknown.Empty() {
			return Proof{}, nil, migrationFailure("", "unknown-target", "target outside behavior is not established")
		}
		if err := preserveOutsideTargetOwnership(ctx, prior, next, domain, limit, visits); err != nil {
			return Proof{}, nil, fmt.Errorf("%w: target outside migration selection", err)
		}
	}
	return Proof{BaseDigest: before.SemanticDigest(), ResultDigest: after.SemanticDigest(), TargetAllowed: allPermit, TargetSatisfied: true, OutsidePreserved: true, NATUnchanged: len(input.StaticNATs)+len(input.DynamicNATs) == 0}, natProof, nil
}
