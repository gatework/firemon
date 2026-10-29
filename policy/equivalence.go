package policy

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
)

var ErrNotEquivalent = errors.New("complete policy equivalence was not established")

type Equivalence struct {
	BaseDigest, ResultDigest string
	From                     time.Time
	Contexts                 int
}

// Contexts enumerates all native zone/chain combinations and all absolute
// schedule transitions at or after from. Each time represents the entire
// half-open interval to the next transition; there is no polling approximation.
func (e Engine) Contexts(ctx context.Context, from time.Time, firewalls ...*fm.Firewall) ([]Request, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	limits := e.Limits.WithDefaults()
	remaining := limits.MaxVisits
	charge := func(count int) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if count > remaining {
			return ErrBudget
		}
		remaining -= count
		return nil
	}
	chains := make(map[fm.PolicyChain]bool)
	zones := make(map[fm.ID]bool)
	times := []time.Time{from}
	for _, fw := range firewalls {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if fw == nil {
			return nil, ErrInvalid
		}
		if !fw.Complete() {
			return nil, ErrNotEquivalent
		}
		for _, count := range []int{fw.RuleCount(), fw.ZoneCount(), fw.ScheduleCount()} {
			if err := charge(count); err != nil {
				return nil, err
			}
		}
		for rule := range fw.OrderedRules() {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			chains[rule.Chain()] = true
		}
		for _, z := range fw.Zones() {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			zones[z.ID()] = true
		}
		for _, schedule := range fw.Schedules() {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if from.IsZero() {
				return nil, ErrNotEquivalent
			}
			if schedule.HasUnsupported() || schedule.HasRecurrence() {
				return nil, ErrNotEquivalent
			}
			for w := range schedule.Windows() {
				if err := charge(1); err != nil {
					return nil, err
				}
				for _, at := range []time.Time{w.Start, w.End} {
					if at.Before(from) {
						continue
					}
					if !slices.ContainsFunc(times, func(v time.Time) bool { return v.Equal(at) }) {
						times = append(times, at)
					}
					if len(times) > limits.MaxCombinations {
						return nil, ErrBudget
					}
				}
			}
		}
	}
	if len(chains) == 0 {
		chains[fm.PolicyChain{RuleSet: "security"}] = true
	}
	if len(zones) == 0 {
		zones[""] = true
	}
	keys := make([]fm.PolicyChain, 0, len(chains))
	for k := range chains {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(a, b fm.PolicyChain) int {
		if c := strings.Compare(a.Scope, b.Scope); c != 0 {
			return c
		}
		return strings.Compare(a.RuleSet, b.RuleSet)
	})
	zoneIDs := make([]fm.ID, 0, len(zones))
	for id := range zones {
		zoneIDs = append(zoneIDs, id)
	}
	slices.Sort(zoneIDs)
	slices.SortFunc(times, time.Time.Compare)
	all, err := flow.AllTraffic(limits.MaxRegions)
	if err != nil {
		return nil, err
	}
	var out []Request
	for _, key := range keys {
		for _, src := range zoneIDs {
			for _, dst := range zoneIDs {
				for _, at := range times {
					if err := ctx.Err(); err != nil {
						return nil, err
					}
					if len(out) >= limits.MaxCombinations {
						return nil, ErrBudget
					}
					out = append(out, Request{Scope: key.Scope, RuleSet: key.RuleSet, FromZone: src, ToZone: dst, At: at, Traffic: all})
				}
			}
		}
	}
	return out, nil
}

// Equivalent proves all future policy outcomes and logging, allowing rule
// ownership changes only when their observable effects agree. Non-rule catalogs,
// including both NAT types, interfaces and bindings, must remain identical.
func (e Engine) Equivalent(ctx context.Context, before, after *fm.Firewall, from time.Time) (Equivalence, error) {
	if err := ctx.Err(); err != nil {
		return Equivalence{}, err
	}
	if before == nil || after == nil {
		return Equivalence{}, ErrInvalid
	}
	if !before.Complete() || !after.Complete() {
		return Equivalence{}, ErrNotEquivalent
	}
	limits := e.Limits.WithDefaults()
	remaining := limits.MaxVisits
	if err := chargeVisits(ctx, &remaining, before.RecordCount(), after.RecordCount()); err != nil {
		return Equivalence{}, err
	}
	if err := e.preserveNATActivation(ctx, before, after, &remaining); err != nil {
		return Equivalence{}, err
	}
	beforeCatalog, afterCatalog := before.Export(), after.Export()
	beforeCatalog.Rules, afterCatalog.Rules = nil, nil
	beforeOwners, err := natOwnerRules(ctx, beforeCatalog.DynamicNATs, &remaining)
	if err != nil {
		return Equivalence{}, err
	}
	afterOwners, err := natOwnerRules(ctx, afterCatalog.DynamicNATs, &remaining)
	if err != nil {
		return Equivalence{}, err
	}
	beforeGraph, err := fm.Seal(beforeCatalog)
	if err != nil {
		return Equivalence{}, err
	}
	afterGraph, err := fm.Seal(afterCatalog)
	if err != nil {
		return Equivalence{}, err
	}
	if beforeGraph.SemanticDigest() != afterGraph.SemanticDigest() {
		return Equivalence{}, ErrNotEquivalent
	}
	contexts, err := e.Contexts(ctx, from, before, after)
	if err != nil {
		return Equivalence{}, err
	}
	for _, q := range contexts {
		if err := chargeVisits(ctx, &remaining, before.RuleCount(), after.RuleCount()); err != nil {
			return Equivalence{}, err
		}
		a, err := e.Query(ctx, before, q)
		if err != nil {
			return Equivalence{}, err
		}
		b, err := e.Query(ctx, after, q)
		if err != nil {
			return Equivalence{}, err
		}
		if !a.Complete || !b.Complete || !a.Unknown.Empty() || !b.Unknown.Empty() {
			return Equivalence{}, ErrNotEquivalent
		}
		for _, pair := range [][2]flow.Traffic{{a.Allowed, b.Allowed}, {a.Denied, b.Denied}, {a.Unmatched, b.Unmatched}} {
			if ok, err := pair[0].Equal(pair[1], limits.MaxRegions); err != nil {
				return Equivalence{}, err
			} else if !ok {
				return Equivalence{}, ErrNotEquivalent
			}
		}
		left, err := ruleEffects(ctx, before, a, beforeOwners, limits.MaxRegions, &remaining)
		if err != nil {
			return Equivalence{}, err
		}
		right, err := ruleEffects(ctx, after, b, afterOwners, limits.MaxRegions, &remaining)
		if err != nil {
			return Equivalence{}, err
		}
		if err := equivalentPartitions(left, right, limits.MaxRegions); err != nil {
			return Equivalence{}, err
		}
	}
	return Equivalence{BaseDigest: before.SemanticDigest(), ResultDigest: after.SemanticDigest(), From: from, Contexts: len(contexts)}, nil
}

func equivalentPartitions[K comparable](left, right map[K]flow.Traffic, limit int) error {
	for key, traffic := range left {
		if same, err := traffic.Equal(right[key], limit); err != nil {
			return err
		} else if !same {
			return ErrNotEquivalent
		}
		delete(right, key)
	}
	for _, traffic := range right {
		if !traffic.Empty() {
			return ErrNotEquivalent
		}
	}
	return nil
}

type ruleEffect struct {
	action                fm.Action
	log, logStart, logEnd fm.Status
	unknownLoggingRule    fm.ID
	natOwnerRule          fm.ID
}

// natOwnerRules indexes policy-bound translation once per proof, not once per
// zone/time context. It consumes the already owned configuration records.
func natOwnerRules(ctx context.Context, translations []fm.DynamicNATRecord, remaining *int) (map[fm.ID]bool, error) {
	if err := chargeVisits(ctx, remaining, len(translations)); err != nil {
		return nil, err
	}
	owners := make(map[fm.ID]bool)
	for _, translation := range translations {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if translation.Rule != "" && !translation.Disabled {
			owners[translation.Rule] = true
		}
	}
	return owners, nil
}

func ruleEffects(ctx context.Context, fw *fm.Firewall, r Result, natOwners map[fm.ID]bool, limit int, remaining *int) (map[ruleEffect]flow.Traffic, error) {
	if err := chargeVisits(ctx, remaining, len(r.Decisions)); err != nil {
		return nil, err
	}
	out := make(map[ruleEffect]flow.Traffic)
	for _, decision := range r.Decisions {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		rule := fw.Rule(decision.Rule).Record()
		key := ruleEffect{action: rule.Action, log: rule.Log, logStart: rule.LogStart, logEnd: rule.LogEnd}
		if natOwners[rule.ID] {
			key.natOwnerRule = rule.ID
		}
		if rule.Log == fm.Unknown || rule.LogStart == fm.Unknown || rule.LogEnd == fm.Unknown {
			key.unknownLoggingRule = rule.ID
		}
		var err error
		out[key], err = out[key].Union(decision.Traffic, limit)
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}
