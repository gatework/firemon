package analysis

import (
	"slices"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/policy"
)

// RiskEvidence keeps the evaluated context and unresolved evidence next to the
// result. NativePolicyView means the supplied ACL coordinates, not wire traffic
// or a possible NAT allocation. Packet traversal establishes those other views.
type RiskEvidence struct {
	At               time.Time
	Chain            fm.PolicyChain
	FromZone, ToZone fm.ID
	View             RiskView
	Schedule         fm.ID
	Timezone         string
	ScheduleActive   Truth
	Disabled         bool
	Spans            []fm.Span
	Reasons          []string
}
type RiskView string

const NativePolicyView RiskView = "native-policy"

func riskEvidence(fw *fm.Firewall, rule *fm.Rule, q policy.Request, mode RiskMode, diagnostics map[fm.ID][]string) RiskEvidence {
	r := rule.Record()
	e := RiskEvidence{At: q.At, Chain: q.Chain(), FromZone: q.FromZone, ToZone: q.ToZone, View: NativePolicyView, Schedule: r.Match.Schedule, ScheduleActive: True, Disabled: r.Disabled, Spans: slices.Clone(r.Spans)}
	if !fw.Complete() {
		e.Reasons = append(e.Reasons, "incomplete-snapshot")
	}
	if len(r.Unsupported) > 0 {
		e.Reasons = append(e.Reasons, "unsupported-rule")
	}
	if r.Disabled && mode == Effective {
		e.Reasons = append(e.Reasons, "disabled-rule")
	}
	if schedule := rule.Schedule(); schedule != nil {
		e.Timezone = schedule.Record().Timezone
		active, known := schedule.ActiveAt(q.At)
		switch {
		case !known:
			e.ScheduleActive = Unknown
			e.Reasons = append(e.Reasons, "schedule-unknown")
		case !active:
			e.ScheduleActive = False
			e.Reasons = append(e.Reasons, "schedule-inactive")
		}
	}
	keys := []fm.ID{"", r.ID}
	if r.Match.Schedule != "" {
		keys = append(keys, r.Match.Schedule)
	}
	for _, key := range keys {
		for _, reason := range diagnostics[key] {
			if !slices.Contains(e.Reasons, reason) {
				e.Reasons = append(e.Reasons, reason)
			}
		}
	}
	return e
}
