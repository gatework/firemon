package converge

import (
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/design"
	"github.com/gatework/firemon/traffic"
)

// mergeable finds groups of rules that become one by extending the first
// in the one dimension where they differ. Rules merge only when they agree
// on everything else that decides or labels traffic (zones, rule-type,
// action, applications, logging, group), and only when moving the later
// rules' traffic up to the first rule's position changes no decision: no
// rule in between with another action, or that cannot be evaluated, may
// match it.
func mergeable(fw *firemon.Firewall, flagged map[string]bool, at time.Time, budget int) []Finding {
	rules := fw.Rules()
	buckets := map[string][]*firemon.Rule{}
	var keys []string
	for _, r := range rules {
		if !mergeEligible(r, flagged, at) {
			continue
		}
		k := mergeKey(r)
		if _, ok := buckets[k]; !ok {
			keys = append(keys, k)
		}
		buckets[k] = append(buckets[k], r)
	}
	var out []Finding
	for _, k := range keys {
		out = append(out, mergeBucket(rules, buckets[k], budget)...)
	}
	return out
}

func mergeEligible(r *firemon.Rule, flagged map[string]bool, at time.Time) bool {
	spec := r.Spec()
	return !r.Ignored() && r.Decidable() && !r.Scheduled() && !r.ExpiredAt(at) && !flagged[r.ID()] &&
		(r.Action() == firemon.ActionPermit || r.Action() == firemon.ActionDeny) &&
		!spec.NegateSource && !spec.NegateDestination && !r.Match().IsEmpty()
}

// mergeKey holds what must be equal for two rules to merge.
func mergeKey(r *firemon.Rule) string {
	spec := r.Spec()
	sorted := func(s []string) string { return strings.Join(slices.Sorted(slices.Values(s)), ",") }
	return strings.Join([]string{
		sorted(spec.From), sorted(spec.To), spec.Scope.String(), spec.Action.String(), sorted(r.Applications()),
		strconv.FormatBool(spec.ApplicationDefault), strconv.FormatBool(spec.Log), spec.Group,
	}, "|")
}

// mergeBucket groups the rules of one bucket, each with the earliest rule
// it can join.
func mergeBucket(all, bucket []*firemon.Rule, budget int) []Finding {
	used := map[string]bool{}
	var out []Finding
	for i, first := range bucket {
		if used[first.ID()] {
			continue
		}
		var field design.Field
		var later []string
		for _, l := range bucket[i+1:] {
			if used[l.ID()] {
				continue
			}
			d, ok := differing(first.Match(), l.Match())
			if !ok || (field != design.FieldUnset && d != field) {
				continue
			}
			if !orderSafe(all, first, l, budget) {
				continue
			}
			field = d
			later = append(later, l.ID())
			used[l.ID()] = true
		}
		if len(later) == 0 {
			continue
		}
		out = append(out, Finding{
			ID: CategoryMergeable.String() + ":" + first.ID(), Category: CategoryMergeable, Tier: TierSafe, Evidence: EvidenceStatic,
			Rules: append([]string{first.ID()}, later...), Merge: &Merge{Keep: first.ID(), Remove: later, Field: field},
		})
	}
	return out
}

// differing returns the one dimension in which two matches differ; false
// when they differ in none (a redundant rule, reported as such) or in more.
func differing(a, b traffic.Space) (design.Field, bool) {
	src, dst, svc := a.Src.Equal(b.Src), a.Dst.Equal(b.Dst), a.Service.Equal(b.Service)
	switch {
	case !src && dst && svc:
		return design.FieldSource, true
	case src && !dst && svc:
		return design.FieldDestination, true
	case src && dst && !svc:
		return design.FieldService, true
	default:
		return design.FieldUnset, false
	}
}

// orderSafe reports whether the traffic of later can be decided at the
// position of first: every rule in between that may match it decides it
// the same way.
func orderSafe(all []*firemon.Rule, first, later *firemon.Rule, budget int) bool {
	m := later.Match()
	checked := 0
	for _, x := range all[first.Position()+1 : later.Position()] {
		if x.Ignored() || !zonesMeet(x, later) || !x.Bound().Overlaps(m) {
			continue
		}
		if checked++; checked > budget {
			return false
		}
		if x.Action() != later.Action() || !x.Decidable() || x.Scheduled() {
			return false
		}
	}
	return true
}

// zonesMeet reports whether two rules can apply to a common zone pair.
func zonesMeet(a, b *firemon.Rule) bool {
	af, at := a.Zones()
	bf, bt := b.Zones()
	meet := func(x, y []string) bool {
		return len(x) == 0 || len(y) == 0 || slices.ContainsFunc(x, func(z string) bool { return slices.Contains(y, z) })
	}
	return meet(af, bf) && meet(at, bt)
}
