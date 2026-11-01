package analysis

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/policy"
)

type DeclarationChange struct {
	Catalog string `json:"catalog"`
	ID      fm.ID  `json:"id"`
	Change  string `json:"change"`
}
type RevisionComparison struct {
	BeforeDigest     string              `json:"before_digest"`
	AfterDigest      string              `json:"after_digest"`
	BeforeComplete   bool                `json:"before_complete"`
	AfterComplete    bool                `json:"after_complete"`
	TextChanged      bool                `json:"text_changed"`
	Declarations     []DeclarationChange `json:"declarations"`
	RuleOrderChanged bool                `json:"rule_order_changed"`
	NATChanged       bool                `json:"nat_changed"`
	// Unproven includes actual differences and incomplete/unsupported evidence.
	// It never asserts a behavior difference merely from declaration drift.
	Behavior string              `json:"behavior"`
	Proof    *policy.Equivalence `json:"proof,omitempty"`
}
type RevisionComparer struct{ Engine policy.Engine }

// Compare uses immutable graphs only. Source text, declaration values, native
// order and NAT drift are reported independently of whole-policy/NAT proof.
func (c RevisionComparer) Compare(ctx context.Context, before, after *fm.Firewall, from time.Time) (RevisionComparison, error) {
	if err := ctx.Err(); err != nil {
		return RevisionComparison{}, err
	}
	if before == nil || after == nil {
		return RevisionComparison{}, ErrInvalid
	}
	bm, am := before.Metadata(), after.Metadata()
	if bm.Device != am.Device || bm.Vendor != am.Vendor || bm.Context != am.Context {
		return RevisionComparison{}, ErrInvalid
	}
	limits := c.Engine.Limits.WithDefaults()
	budget := visitBudget(limits.MaxVisits)
	if err := budget.take(ctx, before.RecordCount()); err != nil {
		return RevisionComparison{}, err
	}
	if err := budget.take(ctx, after.RecordCount()); err != nil {
		return RevisionComparison{}, err
	}
	a, b := before.Export(), after.Export()
	out := RevisionComparison{BeforeDigest: before.SemanticDigest(), AfterDigest: after.SemanticDigest(), BeforeComplete: before.Complete(), AfterComplete: after.Complete(), TextChanged: before.Raw() != after.Raw(), Behavior: "unproven"}
	left, right := revisionRecords(a), revisionRecords(b)
	keys := make([]revisionIdentity, 0, len(left)+len(right))
	for k := range left {
		keys = append(keys, k)
	}
	for k := range right {
		if _, ok := left[k]; !ok {
			keys = append(keys, k)
		}
	}
	slices.SortFunc(keys, func(a, b revisionIdentity) int {
		if a.catalog < b.catalog {
			return -1
		}
		if a.catalog > b.catalog {
			return 1
		}
		if a.id < b.id {
			return -1
		}
		if a.id > b.id {
			return 1
		}
		return 0
	})
	for _, k := range keys {
		if err := ctx.Err(); err != nil {
			return RevisionComparison{}, err
		}
		av, aok := left[k]
		bv, bok := right[k]
		change := "modified"
		if !aok {
			change = "added"
		} else if !bok {
			change = "removed"
		} else if reflect.DeepEqual(av, bv) {
			continue
		}
		if len(out.Declarations) >= limits.MaxCombinations {
			return RevisionComparison{}, policy.ErrBudget
		}
		out.Declarations = append(out.Declarations, DeclarationChange{Catalog: k.catalog, ID: k.id, Change: change})
		if k.catalog == "static_nat" || k.catalog == "dynamic_nat" || k.catalog == "nat_pool" {
			out.NATChanged = true
		}
	}
	out.RuleOrderChanged = !reflect.DeepEqual(revisionOrder(before), revisionOrder(after))
	out.NATChanged = out.NATChanged || !reflect.DeepEqual(before.NATSequence(), after.NATSequence())
	proof, err := c.Engine.Equivalent(ctx, before, after, from)
	if err == nil {
		err = c.Engine.PreserveNAT(ctx, before, after, from)
	}
	if err == nil {
		out.Behavior = "equivalent"
		out.Proof = &proof
		return out, nil
	}
	if errors.Is(err, policy.ErrNotEquivalent) || errors.Is(err, policy.ErrNAT) {
		return out, nil
	}
	if errors.Is(err, flow.ErrBudget) || errors.Is(err, policy.ErrBudget) || ctx.Err() != nil {
		return RevisionComparison{}, err
	}
	return RevisionComparison{}, err
}

type revisionIdentity struct {
	catalog string
	id      fm.ID
}
type revisionRulePosition struct {
	ID       fm.ID
	Chain    fm.PolicyChain
	Position int
}

func revisionOrder(fw *fm.Firewall) []revisionRulePosition {
	var out []revisionRulePosition
	for r := range fw.OrderedRules() {
		out = append(out, revisionRulePosition{ID: r.ID(), Chain: r.Chain(), Position: r.Record().Position})
	}
	return out
}
func revisionRecords(d fm.Data) map[revisionIdentity]any {
	out := make(map[revisionIdentity]any)
	for _, r := range d.Zones {
		r.Spans = nil
		out[revisionIdentity{catalog: "zone", id: r.ID}] = r
	}
	for _, r := range d.Interfaces {
		r.Spans = nil
		out[revisionIdentity{catalog: "interface", id: r.ID}] = r
	}
	for _, r := range d.Routes {
		r.Spans = nil
		out[revisionIdentity{catalog: "route", id: r.ID}] = r
	}
	for _, r := range d.Addresses {
		r.Spans = nil
		out[revisionIdentity{catalog: "address", id: r.ID}] = r
	}
	for _, r := range d.AddressGroups {
		r.Spans = nil
		out[revisionIdentity{catalog: "address_group", id: r.ID}] = r
	}
	for _, r := range d.Services {
		r.Spans = nil
		out[revisionIdentity{catalog: "service", id: r.ID}] = r
	}
	for _, r := range d.ServiceGroups {
		r.Spans = nil
		out[revisionIdentity{catalog: "service_group", id: r.ID}] = r
	}
	for _, r := range d.Schedules {
		r.Spans = nil
		out[revisionIdentity{catalog: "schedule", id: r.ID}] = r
	}
	for _, r := range d.Rules {
		r.Spans = nil
		r.Position = 0
		out[revisionIdentity{catalog: "rule", id: r.ID}] = r
	}
	for _, r := range d.RuleBindings {
		r.Spans = nil
		out[revisionIdentity{catalog: "rule_binding", id: r.ID}] = r
	}
	for _, r := range d.StaticNATs {
		r.Spans = nil
		r.Order = fm.NATOrder{}
		out[revisionIdentity{catalog: "static_nat", id: r.ID}] = r
	}
	for _, r := range d.DynamicNATs {
		r.Spans = nil
		r.Order = fm.NATOrder{}
		out[revisionIdentity{catalog: "dynamic_nat", id: r.ID}] = r
	}
	for _, r := range d.NATPools {
		r.Spans = nil
		out[revisionIdentity{catalog: "nat_pool", id: r.ID}] = r
	}
	return out
}
