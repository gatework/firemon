package converge

import (
	"cmp"
	"slices"
	"strings"
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
	// Baseline is the fingerprint of the configuration reviewed; Plan
	// refuses a report of another configuration.
	Baseline string `json:"baseline"`
	// DuplicateRuleIDs are IDs several rules share; rules cannot be
	// planned by ID while they do.
	DuplicateRuleIDs []string `json:"duplicate_rule_ids,omitempty"`
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
	budget := cmp.Or(opts.MaxSpaces, audit.DefaultMaxSpaces)
	a := audit.Run(fw, audit.Options{Now: now, MaxSpaces: budget})
	r := Report{Incomplete: a.Incomplete, Baseline: fw.Fingerprint(), DuplicateRuleIDs: duplicateIDs(fw)}
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
	cfg := fw.Config()
	demoteUnrestorable(cfg, r.Findings)
	at := now()
	merges, cut := mergeable(fw, flagged, at, budget)
	r.Findings = append(r.Findings, merges...)
	r.Incomplete = append(r.Incomplete, cut...)
	var counters *hits.Index
	if opts.Hits != nil {
		x := opts.Hits.Indexed()
		counters = &x
	}
	r.Findings = append(r.Findings, broad(fw, flagged, counters, minWindow)...)
	r.Findings = append(r.Findings, zeroHits(fw, flagged, counters, minWindow)...)
	r.Findings = append(r.Findings, duplicateObjects(fw, cfg)...)
	r.Findings = append(r.Findings, noLog(fw, flagged)...)
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
	unread := unreadNames(cfg)
	partialRule := map[string]bool{}
	for _, r := range cfg.Rules {
		partialRule[r.ID] = len(r.Unsupported) > 0
	}
	for i := range findings {
		f := &findings[i]
		switch f.Category {
		case CategoryUnusedObject:
			for _, o := range f.Objects {
				switch {
				case partial[o]:
					f.Tier = TierReview
					f.Detail = "definition not fully modelled: a rollback could not recreate it"
				case unread[o.Name]:
					// A line the parser could not read names it: something
					// the model does not see may use it.
					f.Tier = TierReview
					f.Detail = "named in a configuration line that was not parsed: it may be in use"
				}
			}
		case CategoryNeverMatches, CategoryIncomplete, CategoryDisabled, CategoryExpired, CategoryRedundant:
			for _, id := range f.Rules {
				if partialRule[id] {
					// Users, URL categories or unread lines: deleting is
					// fine, but a rollback could not restore the rule.
					f.Tier = TierReview
					f.Detail = "the rule has criteria the model does not hold: a rollback could not restore it exactly"
				}
			}
		case CategoryUnset, CategoryEmptyObject, CategoryShadowed, CategoryMergeable, CategoryBroad, CategoryZeroHit, CategoryDuplicateObject, CategoryNoLog:
		}
	}
}

// duplicateObjects groups live objects of one namespace whose resolved
// contents are equal: rules could share one of them. Merging them changes
// every reference, so it is advice.
func duplicateObjects(fw *firemon.Firewall, cfg *firemon.Config) []Finding {
	refs := fw.References()
	kindOf := map[string]firemon.ObjectKind{}
	for _, a := range cfg.Addresses {
		if !a.Predefined {
			kindOf["a:"+a.Name] = firemon.ObjectKindAddress
		}
	}
	for _, g := range cfg.AddressGroups {
		if !g.Predefined {
			kindOf["a:"+g.Name] = firemon.ObjectKindAddressGroup
		}
	}
	for _, s := range cfg.Services {
		if !s.Predefined {
			kindOf["s:"+s.Name] = firemon.ObjectKindService
		}
	}
	for _, g := range cfg.ServiceGroups {
		if !g.Predefined {
			kindOf["s:"+g.Name] = firemon.ObjectKindServiceGroup
		}
	}
	groups := map[string][]firemon.ObjectRef{}
	var keys []string
	add := func(key string, o firemon.ObjectRef) {
		if !refs.Live(o) {
			return // unused objects are reported as such
		}
		if _, ok := groups[key]; !ok {
			keys = append(keys, key)
		}
		groups[key] = append(groups[key], o)
	}
	for name, set := range fw.Addresses() {
		if k, ok := kindOf["a:"+name]; ok && !set.IsEmpty() {
			add("address "+set.String(), firemon.ObjectRef{Kind: k, Name: name})
		}
	}
	for name, set := range fw.Services() {
		if k, ok := kindOf["s:"+name]; ok && !set.IsEmpty() {
			add("service "+set.String(), firemon.ObjectRef{Kind: k, Name: name})
		}
	}
	var out []Finding
	for _, key := range keys {
		objs := groups[key]
		if len(objs) < 2 {
			continue
		}
		names := make([]string, len(objs))
		for i, o := range objs {
			names[i] = o.Name
		}
		out = append(out, Finding{
			ID: CategoryDuplicateObject.String() + ":" + objs[0].Kind.String() + ":" + objs[0].Name, Category: CategoryDuplicateObject,
			Tier: TierReview, Evidence: EvidenceStatic, Objects: objs,
			Detail: "equal contents " + strings.TrimPrefix(strings.TrimPrefix(key, "address "), "service ") + "; refer to one of " + strings.Join(names, ", "),
		})
	}
	return out
}

// duplicateIDs returns the rule IDs several rules share.
func duplicateIDs(fw *firemon.Firewall) []string {
	seen := map[string]int{}
	var out []string
	for _, r := range fw.Rules() {
		if seen[r.ID()]++; seen[r.ID()] == 2 {
			out = append(out, r.ID())
		}
	}
	return out
}

// unreadNames returns the words of the configuration lines the parser did
// not read, quotes and list brackets removed.
func unreadNames(cfg *firemon.Config) map[string]bool {
	out := map[string]bool{}
	for _, d := range cfg.Diagnostics {
		for _, w := range strings.FieldsFunc(d.Text, func(r rune) bool { return r == ' ' || r == '[' || r == ']' || r == '\t' }) {
			out[strings.Trim(w, `"'`)] = true
		}
		for _, q := range strings.Split(d.Text, `"`)[1:] {
			out[q] = true // quoted names with spaces
		}
	}
	return out
}

// noLog lists the effective permit rules that log nothing: reviewing them
// is the operator's call, nothing is changed.
func noLog(fw *firemon.Firewall, flagged map[string]bool) []Finding {
	var out []Finding
	for _, r := range fw.Rules() {
		if r.Ignored() || flagged[r.ID()] || r.Action() != firemon.ActionPermit || r.Spec().Log.Enabled() {
			continue
		}
		out = append(out, Finding{
			ID: CategoryNoLog.String() + ":" + r.ID(), Category: CategoryNoLog, Tier: TierReview, Evidence: EvidenceStatic,
			Rules: []string{r.ID()},
		})
	}
	return out
}
