package analysis

import (
	"context"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/policy"
)

func (i Inspector) exposures(ctx context.Context, fw *fm.Firewall, q policy.Request, w *inspectionWalk) error {
	if q.Traffic.Empty() {
		return ErrInvalid
	}
	if q.RuleSet == "" {
		q.RuleSet = "security"
	}
	result, err := i.Engine.Query(ctx, fw, q)
	if err != nil {
		return err
	}
	effective := make(map[fm.ID]flow.Traffic)
	for _, d := range result.Decisions {
		effective[d.Rule], err = effective[d.Rule].Union(d.Traffic, i.Engine.Limits.WithDefaults().MaxRegions)
		if err != nil {
			return err
		}
	}
	for rule := range fw.OrderedRules() {
		if rule.Chain() != q.Chain() {
			continue
		}
		if err := w.row(ctx); err != nil {
			return err
		}
		r := rule.Record()
		row := RuleExposure{Rule: r.ID, Action: r.Action, Disabled: r.Disabled}
		traffic, known, err := i.Engine.Match(ctx, fw, r.Match, q, q.Traffic)
		if err != nil {
			return err
		}
		if known && !rule.HasUnsupported() {
			row.Declared = False
			if err := w.retain(traffic.RegionCount()); err != nil {
				return err
			}
			row.DeclaredTraffic = traffic.Regions()
			if !traffic.Empty() {
				row.Declared = True
			}
		}
		if result.Complete && result.Unknown.Empty() {
			row.Effective = False
			if err := w.retain(effective[r.ID].RegionCount()); err != nil {
				return err
			}
			row.EffectiveTraffic = effective[r.ID].Regions()
			if !effective[r.ID].Empty() {
				row.Effective = True
			}
		}
		w.report.Exposures = append(w.report.Exposures, row)
	}
	return nil
}
