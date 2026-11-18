package converge

import (
	"cmp"
	"slices"
	"time"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/audit"
	"github.com/gatework/firemon/hits"
)

// DefaultMinWindow is how long counters must have observed a rule before
// zero hits count as unused.
const DefaultMinWindow = 30 * 24 * time.Hour

// Options configures Analyze. The zero value analyses at time.Now without
// hit counters.
type Options struct {
	Now func() time.Time
	// Hits are the rule hit counters, merged over HA members; nil analyses
	// the configuration alone.
	Hits *hits.Snapshot
	// MinWindow is the observation needed to call a rule unused; zero is
	// DefaultMinWindow.
	MinWindow time.Duration
	// MaxSpaces bounds region work per rule, as in audit.
	MaxSpaces int
}

// Report is the review of one firewall, findings in category order and then
// rule position.
type Report struct {
	Findings []Finding `json:"findings"`
	// Incomplete names rules whose analysis hit the budget.
	Incomplete []string `json:"incomplete,omitempty"`
	// HitsTaken is when the counters were read; zero without counters.
	HitsTaken time.Time `json:"hits_taken,omitzero"`
}

// Count returns the number of findings of a category.
func (r Report) Count(c Category) int {
	n := 0
	for _, f := range r.Findings {
		if f.Category == c {
			n++
		}
	}
	return n
}

// Find returns the finding with an ID.
func (r Report) Find(id string) (Finding, bool) {
	i := slices.IndexFunc(r.Findings, func(f Finding) bool { return f.ID == id })
	if i < 0 {
		return Finding{}, false
	}
	return r.Findings[i], true
}

// Analyze reviews fw.
func Analyze(fw *firemon.Firewall, opts Options) Report {
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	minWindow := cmp.Or(opts.MinWindow, DefaultMinWindow)
	a := audit.Run(fw, audit.Options{Now: now, MaxSpaces: opts.MaxSpaces})
	r := Report{Incomplete: a.Incomplete}
	if opts.Hits != nil {
		r.HitsTaken = opts.Hits.Taken
	}
	flagged := map[string]bool{} // rules already found ineffective
	for _, f := range a.Findings {
		if g, ok := fromAudit(f); ok {
			r.Findings = append(r.Findings, g)
			for _, id := range g.Rules {
				flagged[id] = true
			}
		}
	}
	demoteUnrestorable(fw.Config(), r.Findings)
	at := now()
	r.Findings = append(r.Findings, mergeable(fw, flagged, at, opts.MaxSpaces)...)
	r.Findings = append(r.Findings, broad(fw, flagged, opts.Hits, minWindow)...)
	r.Findings = append(r.Findings, zeroHits(fw, flagged, opts.Hits, minWindow)...)
	position := map[string]int{}
	for _, rule := range fw.Rules() {
		position[rule.ID()] = rule.Position()
	}
	slices.SortStableFunc(r.Findings, func(x, y Finding) int {
		return cmp.Or(cmp.Compare(x.Category, y.Category), cmp.Compare(firstPosition(x, position), firstPosition(y, position)))
	})
	return r
}

func firstPosition(f Finding, position map[string]int) int {
	if len(f.Rules) == 0 {
		return -1
	}
	return position[f.Rules[0]]
}

// fromAudit turns an audit finding into a review finding; undecidable and
// permit-any findings are covered elsewhere.
func fromAudit(f audit.Finding) (Finding, bool) {
	g := Finding{Evidence: EvidenceStatic, Detail: f.Detail, By: f.By}
	switch f.Kind {
	case audit.KindUnusedAddress, audit.KindUnusedService, audit.KindUnusedSchedule:
		g.Category, g.Tier = CategoryUnusedObject, TierSafe
	case audit.KindEmptyObject:
		g.Category, g.Tier = CategoryEmptyObject, TierReview
	case audit.KindNeverMatches:
		g.Category, g.Tier = CategoryNeverMatches, TierSafe
	case audit.KindIncomplete:
		g.Category, g.Tier = CategoryIncomplete, TierSafe
	case audit.KindDisabled:
		g.Category, g.Tier = CategoryDisabled, TierSafe
	case audit.KindExpired:
		g.Category, g.Tier = CategoryExpired, TierSafe
	case audit.KindRedundant:
		g.Category, g.Tier = CategoryRedundant, TierSafe
	case audit.KindShadowed:
		g.Category, g.Tier = CategoryShadowed, TierReview
	case audit.KindUnset, audit.KindUndecidable, audit.KindPermitAny:
		return Finding{}, false
	default:
		return Finding{}, false
	}
	if f.Object != "" {
		g.Objects = []firemon.ObjectRef{{Kind: f.ObjectKind, Name: f.Object}}
		g.ID = g.Category.String() + ":" + f.ObjectKind.String() + ":" + f.Object
	} else {
		g.Rules = []string{f.Rule}
		g.ID = g.Category.String() + ":" + f.Rule
	}
	return g, true
}

// demoteUnrestorable moves unused objects whose definition the model does
// not hold completely (unparsed entries, unsupported periods) to review: a
// rollback could not recreate them exactly.
func demoteUnrestorable(cfg *firemon.Config, findings []Finding) {
	partial := map[firemon.ObjectRef]bool{}
	for _, a := range cfg.Addresses {
		partial[firemon.ObjectRef{Kind: firemon.ObjectKindAddress, Name: a.Name}] = len(a.Invalid) > 0
	}
	for _, g := range cfg.AddressGroups {
		partial[firemon.ObjectRef{Kind: firemon.ObjectKindAddressGroup, Name: g.Name}] = len(g.Invalid) > 0
	}
	for _, s := range cfg.Services {
		partial[firemon.ObjectRef{Kind: firemon.ObjectKindService, Name: s.Name}] = len(s.Invalid) > 0
	}
	for _, s := range cfg.Schedules {
		partial[firemon.ObjectRef{Kind: firemon.ObjectKindSchedule, Name: s.Name}] = s.Unsupported != ""
	}
	for i := range findings {
		f := &findings[i]
		if f.Category != CategoryUnusedObject {
			continue
		}
		for _, o := range f.Objects {
			if partial[o] {
				f.Tier = TierReview
				f.Detail = "definition not fully modelled: a rollback could not recreate it"
			}
		}
	}
}
