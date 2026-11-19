package migrate

import (
	"slices"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/traffic"
)

// verify compares every translated rule with its source rule: the same
// action, the same zones (through the mapping) unless a rule-type was
// split into pairs, and the same match space. A rule that differs is
// downgraded to approximate with the reason.
func (tr *translator) verify(res *Result) {
	out, err := firemon.Compile(tr.out)
	if err != nil {
		return
	}
	for i := range res.Items {
		it := &res.Items[i]
		ids, ok := tr.ruleMap[it.Source]
		if it.Kind != ItemKindRule || !ok || it.Fidelity == FidelityUntranslatable || len(ids) == 0 {
			continue
		}
		src, _ := tr.fw.Rule(it.Source)
		if why := tr.compare(src, out, ids); why != "" {
			it.Fidelity = max(it.Fidelity, FidelityApproximate)
			it.Reason = joinNotes(slices.DeleteFunc([]string{it.Reason, why}, func(s string) bool { return s == "" }))
		}
	}
}

func (tr *translator) compare(src *firemon.Rule, out *firemon.Firewall, ids []string) string {
	var union traffic.Region
	for _, id := range ids {
		r, ok := out.Rule(id)
		if !ok {
			return "translated rule " + id + " is missing"
		}
		if r.Action() != src.Action() {
			return "action differs"
		}
		if !r.Decidable() && src.Decidable() {
			return "the translated rule cannot be evaluated exactly"
		}
		union = union.Add(r.Match())
	}
	if len(ids) == 1 && src.Spec().Scope == firemon.ZoneScopeAny {
		r, _ := out.Rule(ids[0])
		sf, st := src.Zones()
		rf, rt := r.Zones()
		if !slices.Equal(tr.zones(sf), rf) || !slices.Equal(tr.zones(st), rt) {
			return "zones differ"
		}
	}
	if !src.Decidable() {
		return "the source rule cannot be evaluated exactly, so the translation cannot be verified"
	}
	want := traffic.NewRegion(src.Match())
	if !want.SubtractRegion(union).IsEmpty() || !union.SubtractRegion(want).IsEmpty() {
		return "match differs after translation"
	}
	return ""
}
