// Package health scores the policy of a firewall from its convergence
// review: how much of the rulebase takes no effect, how much permits
// broadly or blindly, how much of the object store is dead weight, and how
// much the model could not read. The score is a sum of stated deductions,
// so an operator can see why a firewall scores what it does.
package health

import (
	"cmp"
	"math"
	"slices"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/converge"
)

// Counts are what a score is computed from.
type Counts struct {
	Rules       int `json:"rules"`
	Permits     int `json:"permits"`
	Objects     int `json:"objects"`
	Ineffective int `json:"ineffective"` // rules that never take effect
	Redundant   int `json:"redundant"`
	Shadowed    int `json:"shadowed"`
	Disabled    int `json:"disabled"`
	Expired     int `json:"expired"`
	Incomplete  int `json:"incomplete"`
	NeverMatch  int `json:"never_matches"`
	Unused      int `json:"unused_objects"`
	Empty       int `json:"empty_objects"`
	Duplicate   int `json:"duplicate_objects"`
	Mergeable   int `json:"mergeable"`
	Broad       int `json:"broad"`
	NoLog       int `json:"no_log"`
	ZeroHit     int `json:"zero_hit"`
	// Unreadable are the configuration lines the parser could not read and
	// the rules no premise settles (ADR 0017).
	Unreadable int `json:"unreadable"`
	// Safe counts the findings a verified cleanup can remove.
	Safe int `json:"safe"`
}

// CountsOf counts a firewall's review.
func CountsOf(fw *firemon.Firewall, rep converge.Report) Counts {
	cfg := fw.Config()
	c := Counts{
		Rules:      len(cfg.Rules),
		Objects:    len(cfg.Addresses) + len(cfg.AddressGroups) + len(cfg.Services) + len(cfg.ServiceGroups) + len(cfg.Schedules),
		Redundant:  rep.Count(converge.CategoryRedundant),
		Shadowed:   rep.Count(converge.CategoryShadowed),
		Disabled:   rep.Count(converge.CategoryDisabled),
		Expired:    rep.Count(converge.CategoryExpired),
		Incomplete: rep.Count(converge.CategoryIncomplete),
		NeverMatch: rep.Count(converge.CategoryNeverMatches),
		Unused:     rep.Count(converge.CategoryUnusedObject),
		Empty:      rep.Count(converge.CategoryEmptyObject),
		Duplicate:  rep.Count(converge.CategoryDuplicateObject),
		Mergeable:  rep.Count(converge.CategoryMergeable),
		Broad:      rep.Count(converge.CategoryBroad),
		NoLog:      rep.Count(converge.CategoryNoLog),
		ZeroHit:    rep.Count(converge.CategoryZeroHit),
		Unreadable: len(cfg.Diagnostics),
	}
	c.Ineffective = c.Redundant + c.Shadowed + c.Disabled + c.Expired + c.Incomplete + c.NeverMatch
	for _, r := range fw.Rules() {
		if r.Action() == firemon.ActionPermit && !r.Ignored() {
			c.Permits++
		}
		if !r.Ignored() && !r.Decidable() && !r.Conditional() {
			c.Unreadable++
		}
	}
	for _, f := range rep.Findings {
		if f.Tier == converge.TierSafe {
			c.Safe++
		}
	}
	return c
}

// Deduction is one stated part of a score.
type Deduction struct {
	// Factor names what is measured.
	Factor string `json:"factor"`
	// Ratio is the measured share, from 0 to 1; Weight the most it can
	// cost; Points what it costs, Ratio times Weight.
	Ratio  float64 `json:"ratio"`
	Weight int     `json:"weight"`
	Points float64 `json:"points"`
}

// Factors of a score.
const (
	FactorIneffective = "ineffective-rules" // share of rules that never take effect
	FactorBroad       = "broad-permits"     // share of permits that are broad
	FactorNoLog       = "unlogged-permits"  // share of permits that log nothing
	FactorUnused      = "unused-objects"    // share of objects nothing uses
	FactorUnreadable  = "unreadable"        // lines and rules the model cannot read, against the rules
)

// Score is a firewall's health, 100 for a rulebase without findings.
type Score struct {
	Value      int         `json:"value"`
	Deductions []Deduction `json:"deductions"`
}

// Assess scores counts: 100 less the deductions, each the measured share
// times its weight (ineffective rules 40, broad permits 30, unlogged
// permits 10, unused objects 10, unreadable 10).
func Assess(c Counts) Score {
	ds := []Deduction{
		deduct(FactorIneffective, c.Ineffective, c.Rules, 40),
		deduct(FactorBroad, c.Broad, c.Permits, 30),
		deduct(FactorNoLog, c.NoLog, c.Permits, 10),
		deduct(FactorUnused, c.Unused+c.Empty, c.Objects, 10),
		deduct(FactorUnreadable, c.Unreadable, c.Rules, 10),
	}
	total := 0.0
	for _, d := range ds {
		total += d.Points
	}
	return Score{Value: int(math.Round(math.Max(0, 100-total))), Deductions: ds}
}

func deduct(factor string, n, of, weight int) Deduction {
	ratio := 0.0
	if of > 0 {
		ratio = math.Min(1, float64(n)/float64(of))
	}
	return Deduction{Factor: factor, Ratio: ratio, Weight: weight, Points: ratio * float64(weight)}
}

// Device is one firewall's health in a fleet.
type Device struct {
	Cluster string `json:"cluster"`
	Counts  Counts `json:"counts"`
	Score   Score  `json:"score"`
}

// Priority is a firewall's most pressing deduction: what to fix first.
type Priority struct {
	Cluster string    `json:"cluster"`
	Score   int       `json:"score"`
	Worst   Deduction `json:"worst"`
	// Affected is how many rules or objects the deduction is about;
	// Impact ranks priorities: the points weighted by the logarithm of
	// Affected, so that a share of a large rulebase outranks the same share
	// of a handful of rules.
	Affected int     `json:"affected"`
	Impact   float64 `json:"impact"`
}

// affected is how many items a factor counts on a firewall.
func affected(c Counts, factor string) int {
	switch factor {
	case FactorIneffective:
		return c.Ineffective
	case FactorBroad:
		return c.Broad
	case FactorNoLog:
		return c.NoLog
	case FactorUnused:
		return c.Unused + c.Empty
	default:
		return c.Unreadable
	}
}

// Priorities ranks the fleet's deductions by impact, one per firewall
// (its highest-impact factor), at most n.
func Priorities(devices []Device, n int) []Priority {
	var out []Priority
	for _, d := range devices {
		var best Priority
		for _, ded := range d.Score.Deductions {
			k := affected(d.Counts, ded.Factor)
			impact := ded.Points * math.Log10(1+float64(k))
			if impact > best.Impact {
				best = Priority{Cluster: d.Cluster, Score: d.Score.Value, Worst: ded, Affected: k, Impact: impact}
			}
		}
		if best.Impact > 0 {
			out = append(out, best)
		}
	}
	slices.SortStableFunc(out, func(a, b Priority) int {
		return cmp.Or(cmp.Compare(b.Impact, a.Impact), cmp.Compare(a.Score, b.Score))
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}
