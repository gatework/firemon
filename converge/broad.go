package converge

import (
	"slices"
	"time"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/hits"
	"github.com/gatework/firemon/traffic"
)

// Breadth thresholds: a /16 or wider subnet is wide, a /8 very wide.
const (
	wideBits     = 16
	veryWideBits = 8
)

// broad reviews enabled permits: two dimensions any, any service with a
// wide or any address side, or a /8. Counters, when present, say whether
// the rule is used at all; narrowing a used rule needs traffic logs.
func broad(fw *firemon.Firewall, flagged map[string]bool, counters *hits.Snapshot, minWindow time.Duration) []Finding {
	var out []Finding
	for _, r := range fw.Rules() {
		if r.Action() != firemon.ActionPermit || r.Ignored() || !r.Decidable() || flagged[r.ID()] {
			continue
		}
		reasons := breadth(r)
		if !isBroad(reasons) {
			continue
		}
		f := Finding{
			ID: CategoryBroad.String() + ":" + r.ID(), Category: CategoryBroad, Tier: TierReview, Evidence: EvidenceStatic,
			Rules: []string{r.ID()}, Reasons: reasons,
		}
		if counters != nil {
			switch counters.Judge(r.ID(), minWindow) {
			case hits.VerdictUnused:
				f.Reasons, f.Evidence = append(f.Reasons, ReasonNoHits), EvidenceBoth
				flagged[r.ID()] = true // not reported again as zero-hit
			case hits.VerdictUsed:
				f.Reasons, f.Evidence = append(f.Reasons, ReasonHits), EvidenceBoth
			case hits.VerdictUnknown:
				if _, ok := counters.Counter(r.ID()); ok {
					f.Reasons = append(f.Reasons, ReasonCountersReset)
				}
			case hits.VerdictUnset:
			}
		}
		out = append(out, f)
	}
	return out
}

func breadth(r *firemon.Rule) []Reason {
	m := r.Match()
	var out []Reason
	srcAny, dstAny := allOf(m.Src), allOf(m.Dst)
	if srcAny {
		out = append(out, ReasonSourceAny)
	}
	if dstAny {
		out = append(out, ReasonDestinationAny)
	}
	if m.Service.IsAny() {
		out = append(out, ReasonServiceAny)
	}
	if from, to := r.Zones(); len(from) == 0 && len(to) == 0 {
		out = append(out, ReasonZoneAny)
	}
	sb, db := widest(m.Src), widest(m.Dst)
	if !srcAny && sb <= wideBits {
		out = append(out, ReasonWideSource)
	}
	if !dstAny && db <= wideBits {
		out = append(out, ReasonWideDestination)
	}
	if (!srcAny && sb <= veryWideBits) || (!dstAny && db <= veryWideBits) {
		out = append(out, ReasonVeryWide)
	}
	return out
}

// isBroad applies the review thresholds.
func isBroad(reasons []Reason) bool {
	has := func(r Reason) bool { return slices.Contains(reasons, r) }
	anyCount := 0
	for _, r := range []Reason{ReasonSourceAny, ReasonDestinationAny, ReasonServiceAny} {
		if has(r) {
			anyCount++
		}
	}
	wide := has(ReasonWideSource) || has(ReasonWideDestination)
	return anyCount >= 2 || has(ReasonVeryWide) || (has(ReasonServiceAny) && (wide || anyCount >= 1))
}

// allOf reports whether s holds every address of a family.
func allOf(s traffic.AddressSet) bool {
	return s.ContainsSet(traffic.AnyIPv4()) || s.ContainsSet(traffic.AnyIPv6())
}

// widest returns the shortest IPv4-equivalent prefix length of s, 33 when
// empty. IPv6 lengths are scaled by 32/128, a /64 counting as a /16.
func widest(s traffic.AddressSet) int {
	best := 33
	for _, p := range s.Prefixes() {
		bits := p.Bits()
		if p.Addr().Is6() && !p.Addr().Is4In6() {
			bits = bits / 4
		}
		best = min(best, bits)
	}
	return best
}

// zeroHits reports enabled rules the counters saw unused over the window.
func zeroHits(fw *firemon.Firewall, flagged map[string]bool, counters *hits.Snapshot, minWindow time.Duration) []Finding {
	if counters == nil {
		return nil
	}
	var out []Finding
	for _, r := range fw.Rules() {
		if r.Ignored() || flagged[r.ID()] || counters.Judge(r.ID(), minWindow) != hits.VerdictUnused {
			continue
		}
		out = append(out, Finding{
			ID: CategoryZeroHit.String() + ":" + r.ID(), Category: CategoryZeroHit, Tier: TierReview, Evidence: EvidenceHits,
			Rules: []string{r.ID()}, Reasons: []Reason{ReasonNoHits},
		})
	}
	return out
}
