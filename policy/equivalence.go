package policy

import (
	"context"
	"errors"
	"maps"
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
	limits := e.Limits.defaults()
	chains := make(map[[2]string]bool)
	zones := make(map[fm.ID]bool)
	times := []time.Time{from}
	for _, fw := range firewalls {
		if fw == nil || !fw.Complete() {
			return nil, ErrNotEquivalent
		}
		for _, r := range fw.Rules() {
			record := r.Record()
			chains[[2]string{record.Scope, record.RuleSet}] = true
		}
		for _, z := range fw.Zones() {
			zones[z.Record().ID] = true
		}
		for _, schedule := range fw.Schedules() {
			if from.IsZero() {
				return nil, ErrNotEquivalent
			}
			r := schedule.Record()
			if len(r.Unsupported) > 0 || len(r.Recurring) > 0 {
				return nil, ErrNotEquivalent
			}
			for _, w := range r.Windows {
				for _, at := range []time.Time{w.Start, w.End} {
					if at.Before(from) {
						continue
					}
					if !slices.ContainsFunc(times, func(v time.Time) bool { return v.Equal(at) }) {
						times = append(times, at)
					}
					if len(times) > limits.Combinations {
						return nil, ErrBudget
					}
				}
			}
		}
	}
	if len(chains) == 0 {
		chains[[2]string{"", "security"}] = true
	}
	if len(zones) == 0 {
		zones[""] = true
	}
	keys := make([][2]string, 0, len(chains))
	for k := range chains {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(a, b [2]string) int {
		if c := strings.Compare(a[0], b[0]); c != 0 {
			return c
		}
		return strings.Compare(a[1], b[1])
	})
	zoneIDs := make([]fm.ID, 0, len(zones))
	for id := range zones {
		zoneIDs = append(zoneIDs, id)
	}
	slices.Sort(zoneIDs)
	slices.SortFunc(times, time.Time.Compare)
	all, err := allTraffic(limits.Regions)
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
					if len(out) >= limits.Combinations {
						return nil, ErrBudget
					}
					out = append(out, Request{Scope: key[0], RuleSet: key[1], FromZone: src, ToZone: dst, At: at, Traffic: all})
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
	if before == nil || after == nil || !before.Complete() || !after.Complete() {
		return Equivalence{}, ErrNotEquivalent
	}
	if before.Metadata().Vendor == "fortinet" || after.Metadata().Vendor == "fortinet" {
		budget := e.Limits.defaults().Rules
		a, err := e.fortinetActiveVIPs(ctx, before, &budget)
		if err != nil {
			return Equivalence{}, err
		}
		b, err := e.fortinetActiveVIPs(ctx, after, &budget)
		if err != nil {
			return Equivalence{}, err
		}
		if !maps.Equal(a, b) {
			return Equivalence{}, ErrNotEquivalent
		}
	}
	a, b := before.Export(), after.Export()
	a.Rules, b.Rules = nil, nil
	x, err := fm.Seal(a)
	if err != nil {
		return Equivalence{}, err
	}
	y, err := fm.Seal(b)
	if err != nil {
		return Equivalence{}, err
	}
	if x.SemanticDigest() != y.SemanticDigest() {
		return Equivalence{}, ErrNotEquivalent
	}
	contexts, err := e.Contexts(ctx, from, before, after)
	if err != nil {
		return Equivalence{}, err
	}
	limits := e.Limits.defaults()
	visits := 0
	for _, q := range contexts {
		cost := len(before.Rules()) + len(after.Rules())
		if cost > limits.Rules-visits {
			return Equivalence{}, ErrBudget
		}
		visits += cost
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
			if ok, err := equivalentTraffic(pair[0], pair[1], limits.Regions); err != nil {
				return Equivalence{}, err
			} else if !ok {
				return Equivalence{}, ErrNotEquivalent
			}
		}
		left, err := effects(before, a, limits.Regions)
		if err != nil {
			return Equivalence{}, err
		}
		right, err := effects(after, b, limits.Regions)
		if err != nil {
			return Equivalence{}, err
		}
		for k, traffic := range left {
			if ok, err := equivalentTraffic(traffic, right[k], limits.Regions); err != nil {
				return Equivalence{}, err
			} else if !ok {
				return Equivalence{}, ErrNotEquivalent
			}
			delete(right, k)
		}
		for _, traffic := range right {
			if !traffic.Empty() {
				return Equivalence{}, ErrNotEquivalent
			}
		}
	}
	return Equivalence{BaseDigest: before.SemanticDigest(), ResultDigest: after.SemanticDigest(), From: from, Contexts: len(contexts)}, nil
}

func equivalentTraffic(a, b flow.Traffic, limit int) (bool, error) {
	x, err := a.Difference(b, limit)
	if err != nil || !x.Empty() {
		return false, err
	}
	x, err = b.Difference(a, limit)
	return err == nil && x.Empty(), err
}

type effect struct {
	action          fm.Action
	log, start, end fm.Status
	uncertain       fm.ID
	natOwner        fm.ID
}

func effects(fw *fm.Firewall, r Result, limit int) (map[effect]flow.Traffic, error) {
	out := make(map[effect]flow.Traffic)
	owners := make(map[fm.ID]bool)
	for _, n := range fw.DynamicNATs() {
		if r := n.Record(); r.Rule != "" && !r.Disabled {
			owners[r.Rule] = true
		}
	}
	for _, t := range r.Trace {
		rule := fw.Rule(t.Rule).Record()
		key := effect{action: rule.Action, log: rule.Log, start: rule.LogStart, end: rule.LogEnd}
		if owners[rule.ID] {
			key.natOwner = rule.ID
		}
		if rule.Log == fm.Unknown || rule.LogStart == fm.Unknown || rule.LogEnd == fm.Unknown {
			key.uncertain = rule.ID
		}
		var err error
		out[key], err = out[key].Union(t.Traffic, limit)
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}
