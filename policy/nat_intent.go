package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
)

// NATIntent requests the ordered relation of concrete, explicitly typed native
// declarations on original traffic. The declarations supply the mapping modes,
// ports and possible allocation pools; Steps never infer a mapping from size.
// An implicit bidirectional effect must have its own intent with Reverse=true.
type NATIntent struct {
	Request Request
	Steps   []NATStep
	Window  *fm.TimeWindow `json:",omitempty"`
}

// NATProof records complete relation selection and outside preservation. Dynamic
// allocations remain possibilities; this proof never identifies a live session.
type NATProof struct {
	BaseDigest, ResultDigest          string
	IntentSatisfied, OutsidePreserved bool
	Contexts                          int
}

// ProveNATEffects checks existing declarations/dependencies and proves every
// requested ordered relation, plus all original traffic outside the intent.
// Request and window times must support time.Time's JSON representation.
func (e Engine) ProveNATEffects(ctx context.Context, before, after *fm.Firewall, intents []NATIntent) (NATProof, error) {
	if err := ctx.Err(); err != nil {
		return NATProof{}, err
	}
	if before == nil || after == nil || !before.Complete() || !after.Complete() || len(intents) == 0 {
		return NATProof{}, ErrInvalid
	}
	limits := e.Limits.WithDefaults()
	remaining := limits.MaxVisits
	if err := chargeVisits(ctx, &remaining, before.RecordCount(), after.RecordCount(), len(intents)); err != nil {
		return NATProof{}, err
	}
	// Bound all caller-owned work before catalog export or per-step transforms.
	for _, intent := range intents {
		if err := chargeVisits(ctx, &remaining, len(intent.Steps), intent.Request.Traffic.RegionCount()); err != nil {
			return NATProof{}, err
		}
		if intent.Request.Traffic.RegionCount() > limits.MaxRegions {
			return NATProof{}, ErrBudget
		}
	}
	if len(intents) > limits.MaxCombinations {
		return NATProof{}, ErrBudget
	}
	from := intents[0].Request.At
	for _, i := range intents {
		if err := ctx.Err(); err != nil {
			return NATProof{}, err
		}
		if i.Request.Traffic.Empty() || len(i.Steps) == 0 {
			return NATProof{}, ErrInvalid
		}
		if _, err := natTimeKey(i.Request.At); err != nil {
			return NATProof{}, err
		}
		if i.Request.At.Before(from) {
			from = i.Request.At
		}
	}
	for _, i := range intents {
		if err := ctx.Err(); err != nil {
			return NATProof{}, err
		}
		if i.Window != nil {
			if i.Window.Start.IsZero() || !i.Window.Start.Before(i.Window.End) {
				return NATProof{}, ErrInvalid
			}
			for _, at := range []time.Time{i.Window.Start, i.Window.End} {
				if _, err := natTimeKey(at); err != nil {
					return NATProof{}, err
				}
			}
			from = time.Date(1, 1, 1, 0, 0, 0, 1, time.UTC)
		}
	}
	if err := existingNATCatalog(before, after); err != nil {
		return NATProof{}, err
	}
	contexts, err := e.NATContexts(ctx, from, before, after)
	if err != nil {
		return NATProof{}, err
	}
	// A caller-supplied finite intent is also a time boundary even if no
	// native schedule declares it. Include it across every native context so
	// an arbitrary active instant cannot hide permanent or wider NAT effects.
	var boundaries []time.Time
	for _, i := range intents {
		if i.Window != nil {
			boundaries = append(boundaries, i.Window.Start, i.Window.End)
		}
	}
	if len(boundaries) > 0 {
		count := len(contexts)
		seen := make(map[natContextIdentity]bool, count)
		for _, q := range contexts {
			if err := ctx.Err(); err != nil {
				return NATProof{}, err
			}
			key, err := natContextKey(q)
			if err != nil {
				return NATProof{}, err
			}
			seen[key] = true
		}
		for _, at := range boundaries {
			for j := range count {
				if err := chargeVisits(ctx, &remaining, 1); err != nil {
					return NATProof{}, err
				}
				q := contexts[j]
				q.At = at
				key, err := natContextKey(q)
				if err != nil {
					return NATProof{}, err
				}
				if seen[key] {
					continue
				}
				if len(contexts) >= limits.MaxCombinations {
					return NATProof{}, ErrBudget
				}
				seen[key] = true
				contexts = append(contexts, q)
			}
		}
	}
	if len(intents) > limits.MaxCombinations-len(contexts) {
		return NATProof{}, ErrBudget
	}
	// Explicit contexts also cover wildcard and otherwise empty native chains.
	all, err := flow.AllTraffic(limits.MaxRegions)
	if err != nil {
		return NATProof{}, err
	}
	for _, i := range intents {
		for _, step := range i.Steps {
			if err := ctx.Err(); err != nil {
				return NATProof{}, err
			}
			if _, err := transform(after, step); err != nil {
				return NATProof{}, err
			}
		}
		if err := ctx.Err(); err != nil {
			return NATProof{}, err
		}
		q := i.Request
		if i.Window != nil {
			q.At = i.Window.Start
		}
		q.Traffic = all
		contexts = append(contexts, q)
	}
	for _, q := range contexts {
		if err := chargeVisits(ctx, &remaining, before.RecordCount(), after.RecordCount(), len(intents)); err != nil {
			return NATProof{}, err
		}
		var domain flow.Traffic
		for _, intent := range intents {
			if !natIntentContext(intent.Request, q) || intent.Window != nil && (q.At.Before(intent.Window.Start) || !q.At.Before(intent.Window.End)) {
				continue
			}
			domain, err = domain.Union(intent.Request.Traffic, limits.MaxRegions)
			if err != nil {
				return NATProof{}, err
			}
			target := q
			target.Traffic = intent.Request.Traffic
			result, err := e.QueryNAT(ctx, after, target)
			if err != nil {
				return NATProof{}, err
			}
			if !result.Complete || !result.Unknown.Empty() || !result.Unmatched.Empty() {
				return NATProof{}, ErrNotEquivalent
			}
			var covered flow.Traffic
			for _, relation := range result.Relations {
				if !slices.Equal(relation.Steps, intent.Steps) {
					return NATProof{}, ErrNotEquivalent
				}
				covered, err = covered.Union(relation.Original, limits.MaxRegions)
				if err != nil {
					return NATProof{}, err
				}
			}
			same, err := covered.Equal(target.Traffic, limits.MaxRegions)
			if err != nil {
				return NATProof{}, err
			}
			if !same {
				return NATProof{}, ErrNotEquivalent
			}
		}
		q.Traffic, err = all.Difference(domain, limits.MaxRegions)
		if err != nil {
			return NATProof{}, err
		}
		prior, err := e.QueryNAT(ctx, before, q)
		if err != nil {
			return NATProof{}, err
		}
		next, err := e.QueryNAT(ctx, after, q)
		if err != nil {
			return NATProof{}, err
		}
		if !prior.Complete || !next.Complete || !prior.Unknown.Empty() || !next.Unknown.Empty() {
			return NATProof{}, ErrNotEquivalent
		}
		same, err := prior.Unmatched.Equal(next.Unmatched, limits.MaxRegions)
		if err != nil {
			return NATProof{}, err
		}
		if !same {
			return NATProof{}, ErrNotEquivalent
		}
		left, err := natPartitions(prior.Relations, limits.MaxRegions)
		if err != nil {
			return NATProof{}, err
		}
		right, err := natPartitions(next.Relations, limits.MaxRegions)
		if err != nil {
			return NATProof{}, err
		}
		if err := equivalentPartitions(left, right, limits.MaxRegions); err != nil {
			return NATProof{}, err
		}
	}
	return NATProof{before.SemanticDigest(), after.SemanticDigest(), true, true, len(contexts)}, nil
}
func natIntentContext(a, b Request) bool {
	return a.Scope == b.Scope && (a.RuleSet == b.RuleSet || a.RuleSet == "" && b.RuleSet == "security") && (a.FromZone == "" || a.FromZone == b.FromZone) && (a.ToZone == "" || a.ToZone == b.ToZone) && (a.EgressInterface == "" || a.EgressInterface == b.EgressInterface)
}

// NATContexts extends policy contexts with NAT-only scopes and every egress
// interface. A NAT scope without policy declarations is still part of safety.
// Requested and derived times must support time.Time's JSON representation.
func (e Engine) NATContexts(ctx context.Context, from time.Time, firewalls ...*fm.Firewall) ([]Request, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if _, err := natTimeKey(from); err != nil {
		return nil, err
	}
	base, err := e.Contexts(ctx, from, firewalls...)
	if err != nil {
		return nil, err
	}
	limits := e.Limits.WithDefaults()
	remaining := limits.MaxVisits
	scopes := map[string]bool{}
	egress := map[fm.ID]bool{"": true}
	for _, fw := range firewalls {
		if err := chargeVisits(ctx, &remaining, fw.RecordCount()); err != nil {
			return nil, err
		}
		scopes[fw.Metadata().Context] = true
		for _, n := range fw.NATSequence() {
			scopes[n.Scope] = true
		}
		for _, i := range fw.Interfaces() {
			egress[i.ID()] = true
		}
	}
	for _, q := range base {
		scopes[q.Scope] = true
	}
	type orderedContext struct {
		request Request
		sortKey string
	}
	var ordered []orderedContext
	keys := map[natContextIdentity]bool{}
	for _, q := range base {
		for scope := range scopes {
			domain := egress
			if len(firewalls) > 0 && firewalls[0].Metadata().Vendor == "hillstone" {
				domain = map[fm.ID]bool{}
				known := true
				for _, fw := range firewalls {
					count := 0
					for _, i := range fw.Interfaces() {
						if err := chargeVisits(ctx, &remaining, 1); err != nil {
							return nil, err
						}
						if i.Scope() != scope {
							continue
						}
						count++
						r := i.Record()
						if i.Disabled() || i.HasUnsupported() || i.Zone() == nil || i.Zone().HasUnsupported() || i.Zone().Scope() != scope || len(r.Addresses) == 0 {
							known = false
							continue
						}
						domain[i.ID()] = true
					}
					if count == 0 {
						known = false
					}
				}
				if !known || len(domain) == 0 {
					domain[""] = true
				}
			}
			if len(firewalls) > 0 && firewalls[0].Metadata().Vendor == "fortinet" && q.ToZone != "" {
				domain = map[fm.ID]bool{}
				known := true
				for _, fw := range firewalls {
					count := 0
					for _, i := range fw.Interfaces() {
						if err := chargeVisits(ctx, &remaining, 1); err != nil {
							return nil, err
						}
						if i.Scope() != scope || i.Record().Zone != q.ToZone {
							continue
						}
						count++
						if i.Disabled() || i.HasUnsupported() || i.Zone() == nil || i.Zone().HasUnsupported() || len(i.Record().Addresses) == 0 {
							known = false
							continue
						}
						domain[i.ID()] = true
					}
					if count == 0 {
						known = false
					}
				}
				if !known || len(domain) == 0 {
					domain[""] = true
				}
			}
			for iface := range domain {
				if err := chargeVisits(ctx, &remaining, 1); err != nil {
					return nil, err
				}
				q.Scope, q.EgressInterface = scope, iface
				key, err := natContextKey(q)
				if err != nil {
					return nil, err
				}
				if keys[key] {
					continue
				}
				keys[key] = true
				if len(ordered) >= limits.MaxCombinations {
					return nil, ErrBudget
				}
				// Retain the existing wire order without serializing repeatedly
				// in the sort comparator. Context count affects approval digests.
				wire := q
				wire.Traffic = flow.Traffic{}
				encoded, err := json.Marshal(wire)
				if err != nil {
					return nil, fmt.Errorf("%w: NAT context encoding: %w", ErrInvalid, err)
				}
				ordered = append(ordered, orderedContext{q, string(encoded)})
			}
		}
	}
	slices.SortFunc(ordered, func(a, b orderedContext) int { return strings.Compare(a.sortKey, b.sortKey) })
	out := make([]Request, len(ordered))
	for i, entry := range ordered {
		out[i] = entry.request
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// Raw rule-set names and legal time offsets are distinct wire identities, even
// when policy matching treats them alike. Keep that distinction in proofs.
type natContextIdentity struct {
	scope, ruleSet                    string
	fromZone, toZone, egressInterface fm.ID
	at                                string
}

func natContextKey(q Request) (natContextIdentity, error) {
	at, err := natTimeKey(q.At)
	if err != nil {
		return natContextIdentity{}, err
	}
	return natContextIdentity{q.Scope, q.RuleSet, q.FromZone, q.ToZone, q.EgressInterface, at}, nil
}

func natTimeKey(at time.Time) (string, error) {
	wire, err := at.MarshalJSON()
	if err != nil {
		return "", fmt.Errorf("%w: NAT context time: %w", ErrInvalid, err)
	}
	return string(wire), nil
}
func existingNATCatalog(before, after *fm.Firewall) error {
	a, b := before.Export(), after.Export()
	a.Rules, b.Rules = nil, nil
	b.Addresses = slices.DeleteFunc(b.Addresses, func(r fm.AddressRecord) bool { return before.Address(r.ID) == nil })
	b.Services = slices.DeleteFunc(b.Services, func(r fm.ServiceRecord) bool { return before.Service(r.ID) == nil })
	b.StaticNATs = slices.DeleteFunc(b.StaticNATs, func(r fm.StaticNATRecord) bool { return before.StaticNAT(r.ID) == nil })
	b.DynamicNATs = slices.DeleteFunc(b.DynamicNATs, func(r fm.DynamicNATRecord) bool { return before.DynamicNAT(r.ID) == nil })
	b.Schedules = slices.DeleteFunc(b.Schedules, func(r fm.ScheduleRecord) bool { return before.Schedule(r.ID) == nil })
	b.NATPools = slices.DeleteFunc(b.NATPools, func(r fm.NATPoolRecord) bool { return before.NATPool(r.ID) == nil })
	normalizeNATPositions(&a)
	normalizeNATPositions(&b)
	x, err := fm.Seal(a)
	if err != nil {
		return err
	}
	y, err := fm.Seal(b)
	if err != nil {
		return err
	}
	if x.SemanticDigest() != y.SemanticDigest() {
		return ErrNotEquivalent
	}
	return nil
}

// Existing NAT line/rank numbers can shift after insertion. Re-rank each
// surviving native chain while retaining its original execution sequence.
func normalizeNATPositions(d *fm.Data) {
	type entry struct {
		kind  fm.Kind
		index int
		order fm.NATOrder
		scope string
		id    fm.ID
	}
	var entries []entry
	for i, r := range d.StaticNATs {
		entries = append(entries, entry{fm.StaticNATObject, i, r.Order, r.Scope, r.ID})
	}
	for i, r := range d.DynamicNATs {
		entries = append(entries, entry{fm.DynamicNATObject, i, r.Order, r.Scope, r.ID})
	}
	slices.SortFunc(entries, func(a, b entry) int {
		if a.order.Position < b.order.Position {
			return -1
		}
		if a.order.Position > b.order.Position {
			return 1
		}
		return strings.Compare(string(a.id), string(b.id))
	})
	type chain struct {
		scope, section string
		stage          int
	}
	positions := map[chain]int{}
	for _, r := range entries {
		key := chain{r.scope, r.order.Section, r.order.Stage}
		if r.kind == fm.StaticNATObject {
			d.StaticNATs[r.index].Order.Position = positions[key]
		} else {
			d.DynamicNATs[r.index].Order.Position = positions[key]
		}
		positions[key]++
	}
}
