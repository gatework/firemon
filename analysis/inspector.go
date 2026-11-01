package analysis

import (
	"context"
	"slices"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/policy"
)

type InspectionRequest struct {
	// Exactly one selector: typed declaration identity, or an address set.
	Object    fm.AddressRef
	Addresses flow.AddressSet
	// Evaluation is an explicit native policy coordinate request. Exposures
	// describe this entire request, independently of inventory references.
	Evaluation *policy.Request
	// Aliases is a separate business-coordinate packet request with ingress.
	Aliases *AliasInspection
}
type AliasInspection struct {
	Request policy.PacketRequest
	View    policy.AliasView
}
type ObjectPath struct {
	Path     []fm.AddressRef `json:"path"`
	Relation string          `json:"relation"`
}
type RuleReference struct {
	Rule     fm.ID           `json:"rule"`
	Role     Dimension       `json:"role"`
	Path     []fm.AddressRef `json:"path,omitempty"`
	Relation string          `json:"relation"`
	Wildcard bool            `json:"wildcard"`
}
type InspectionIssue struct {
	Path []fm.AddressRef `json:"path"`
	Code string          `json:"code"`
}
type RuleExposure struct {
	Rule             fm.ID                `json:"rule"`
	Action           fm.Action            `json:"action"`
	Disabled         bool                 `json:"disabled"`
	Declared         Truth                `json:"declared"`
	Effective        Truth                `json:"effective"`
	DeclaredTraffic  []flow.TrafficRegion `json:"declared_traffic"`
	EffectiveTraffic []flow.TrafficRegion `json:"effective_traffic"`
}
type DynamicPoolRelation struct {
	NAT                fm.NATRef           `json:"nat"`
	Pool               fm.ID               `json:"pool"`
	Role               Dimension           `json:"role"`
	Disabled           bool                `json:"disabled"`
	Addresses          []flow.AddressRange `json:"addresses"`
	PossibleAllocation bool                `json:"possible_allocation"`
}
type StaticAlias struct {
	Business []flow.TrafficRegion `json:"business"`
	Wire     []flow.TrafficRegion `json:"wire"`
	Steps    []policy.NATStep     `json:"steps"`
}
type StaticAliasReport struct {
	View       policy.AliasView     `json:"view"`
	Candidates []StaticAlias        `json:"candidates"`
	Ambiguous  []flow.TrafficRegion `json:"ambiguous"`
	Unknown    []flow.TrafficRegion `json:"unknown"`
	Unmatched  []flow.TrafficRegion `json:"unmatched"`
}
type InspectionReport struct {
	GraphDigest  string                `json:"graph_digest"`
	Complete     bool                  `json:"complete"`
	Objects      []ObjectPath          `json:"objects"`
	References   []RuleReference       `json:"references"`
	Issues       []InspectionIssue     `json:"issues"`
	Exposures    []RuleExposure        `json:"exposures"`
	DynamicPools []DynamicPoolRelation `json:"dynamic_pools"`
	Aliases      *StaticAliasReport    `json:"aliases,omitempty"`
}
type Inspector struct{ Engine policy.Engine }

type inspectionWalk struct {
	fw        *fm.Firewall
	selector  InspectionRequest
	visits    visitBudget
	remaining int
	regions   int
	report    *InspectionReport
}

func (i Inspector) Inspect(ctx context.Context, fw *fm.Firewall, q InspectionRequest) (InspectionReport, error) {
	if err := ctx.Err(); err != nil {
		return InspectionReport{}, err
	}
	hasObject := q.Object != (fm.AddressRef{})
	if fw == nil || hasObject == !q.Addresses.Empty() {
		return InspectionReport{}, ErrInvalid
	}
	if hasObject && (q.Object.Kind != fm.AddressObject && q.Object.Kind != fm.AddressGroupObject || q.Object.ID == "") {
		return InspectionReport{}, ErrInvalid
	}
	if hasObject && (q.Object.Kind == fm.AddressObject && fw.Address(q.Object.ID) == nil || q.Object.Kind == fm.AddressGroupObject && fw.AddressGroup(q.Object.ID) == nil) {
		return InspectionReport{}, ErrInvalid
	}
	limits := i.Engine.Limits.WithDefaults()
	if q.Addresses.RangeCount() > limits.MaxRegions {
		return InspectionReport{}, flow.ErrBudget
	}
	out := InspectionReport{GraphDigest: fw.SemanticDigest(), Complete: fw.Complete()}
	w := inspectionWalk{fw: fw, selector: q, visits: visitBudget(limits.MaxVisits), remaining: limits.MaxCombinations, regions: limits.MaxRegions, report: &out}
	if err := w.visits.take(ctx, fw.RecordCount()); err != nil {
		return InspectionReport{}, err
	}
	emit := func(p ObjectPath) error {
		if err := w.row(ctx); err != nil {
			return err
		}
		out.Objects = append(out.Objects, p)
		return nil
	}
	for _, a := range fw.Addresses() {
		if err := w.walk(ctx, fm.AddressRef{Kind: fm.AddressObject, ID: a.ID()}, nil, emit); err != nil {
			return InspectionReport{}, err
		}
	}
	for _, g := range fw.AddressGroups() {
		if err := w.walk(ctx, fm.AddressRef{Kind: fm.AddressGroupObject, ID: g.ID()}, nil, emit); err != nil {
			return InspectionReport{}, err
		}
	}
	for rule := range fw.OrderedRules() {
		r := rule.Record()
		for _, role := range []Dimension{Source, Destination} {
			refs, any := r.Match.Sources, r.Match.AnySource
			if role == Destination {
				refs, any = r.Match.Destinations, r.Match.AnyDestination
			}
			for _, ref := range refs {
				if err := w.walk(ctx, ref, nil, func(p ObjectPath) error {
					if err := w.row(ctx); err != nil {
						return err
					}
					out.References = append(out.References, RuleReference{Rule: r.ID, Role: role, Path: p.Path, Relation: p.Relation})
					return nil
				}); err != nil {
					return InspectionReport{}, err
				}
			}
			if any && q.Evaluation != nil {
				if err := w.row(ctx); err != nil {
					return InspectionReport{}, err
				}
				out.References = append(out.References, RuleReference{Rule: r.ID, Role: role, Wildcard: true, Relation: "any"})
			}
		}
	}
	if q.Evaluation != nil {
		if err := i.exposures(ctx, fw, *q.Evaluation, &w); err != nil {
			return InspectionReport{}, err
		}
	}
	selected := q.Addresses
	if hasObject {
		var err error
		selected, err = w.selectedAddresses(ctx, q.Object, nil)
		if err != nil {
			return InspectionReport{}, err
		}
	}
	if err := w.pools(ctx, selected, limits.MaxRegions); err != nil {
		return InspectionReport{}, err
	}
	if q.Aliases != nil {
		aliases, err := i.Engine.DiscoverStaticAliases(ctx, fw, q.Aliases.Request, q.Aliases.View)
		if err != nil {
			return InspectionReport{}, err
		}
		if err := w.retain(aliases.Ambiguous.RegionCount() + aliases.Unknown.RegionCount() + aliases.Unmatched.RegionCount()); err != nil {
			return InspectionReport{}, err
		}
		report := &StaticAliasReport{View: q.Aliases.View, Ambiguous: aliases.Ambiguous.Regions(), Unknown: aliases.Unknown.Regions(), Unmatched: aliases.Unmatched.Regions()}
		for _, a := range aliases.Candidates {
			if err := w.row(ctx); err != nil {
				return InspectionReport{}, err
			}
			if err := w.retain(a.Business.RegionCount() + a.Wire.RegionCount()); err != nil {
				return InspectionReport{}, err
			}
			report.Candidates = append(report.Candidates, StaticAlias{Business: a.Business.Regions(), Wire: a.Wire.Regions(), Steps: slices.Clone(a.Steps)})
		}
		out.Aliases = report
	}
	return out, nil
}
func (w *inspectionWalk) row(ctx context.Context) error {
	if err := w.visits.take(ctx, 1); err != nil {
		return err
	}
	if w.remaining <= 0 {
		return policy.ErrBudget
	}
	w.remaining--
	return nil
}

func (w *inspectionWalk) retain(count int) error {
	if count > w.regions {
		return flow.ErrBudget
	}
	w.regions -= count
	return nil
}
