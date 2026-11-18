package converge

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/design"
	"github.com/gatework/firemon/query"
	"github.com/gatework/firemon/traffic"
)

// Errors of Plan.
var (
	// ErrNotSafe reports a selected finding that is not in the Safe tier.
	ErrNotSafe = errors.New("converge: finding needs review, not a change")
	// ErrUnknownFinding reports a selected ID the report does not hold.
	ErrUnknownFinding = errors.New("converge: unknown finding")
	// ErrPolicyChanged reports a cleanup that would change a decision.
	ErrPolicyChanged = errors.New("converge: cleanup changes the effective policy")
)

// Selection picks findings to plan; empty selects every Safe finding.
type Selection struct {
	IDs        []string
	Categories []Category
}

// PlanOptions configure Plan.
type PlanOptions struct {
	Now    func() time.Time
	Naming design.Naming
}

// Plan designs the changes that resolve the selected Safe findings and
// verifies that the effective policy stays the same: every decision of
// every zone pair, for the traffic of the changed rules, is equal before
// and after. Merges extend the first rule and delete the others; rules
// that never take effect are deleted; unused objects are deleted groups
// first. Deleting rules can leave more objects unused: review again after
// applying.
func Plan(fw *firemon.Firewall, rep Report, sel Selection, opts PlanOptions) (*design.Plan, error) {
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	chosen, err := selectFindings(rep, sel)
	if err != nil {
		return nil, err
	}
	b := newBuilder(fw, opts.Naming)
	for _, f := range chosen {
		for _, o := range f.Objects {
			if f.Category == CategoryUnusedObject {
				b.cat.Avoid(o.Name) // never extend a rule with an object being deleted
			}
		}
	}
	for _, f := range chosen {
		if err := b.add(f); err != nil {
			return nil, err
		}
	}
	plan := &design.Plan{Kind: design.PlanKindCleanup, Baseline: fw.Fingerprint(), Status: design.StatusChange, Changes: b.changes()}
	if len(plan.Changes) == 0 {
		plan.Status, plan.Verified = design.StatusNoChange, true
		return plan, nil
	}
	// A failed verification is a result: the plan is returned unverified
	// with the reason, never deployed.
	verr := verify(fw, plan.Changes, b.affected, b.deletedObjects, now())
	plan.Verified = verr == nil
	if verr != nil {
		plan.VerifyError = verr.Error()
	}
	return plan, nil
}

func selectFindings(rep Report, sel Selection) ([]Finding, error) {
	var out []Finding
	if len(sel.IDs) == 0 {
		for _, f := range rep.Findings {
			if f.Tier == TierSafe && (len(sel.Categories) == 0 || slices.Contains(sel.Categories, f.Category)) {
				out = append(out, f)
			}
		}
		return out, nil
	}
	for _, id := range sel.IDs {
		f, ok := rep.Find(id)
		switch {
		case !ok:
			return nil, fmt.Errorf("%w %q", ErrUnknownFinding, id)
		case f.Tier != TierSafe:
			return nil, fmt.Errorf("%w: %s", ErrNotSafe, id)
		}
		out = append(out, f)
	}
	return out, nil
}

// builder collects changes in a deployable order: new objects, rule
// extensions, rule deletions, then object deletions (groups first).
type builder struct {
	fw             *firemon.Firewall
	cfg            *firemon.Config
	cat            *design.Catalog
	extend         []design.Change
	deleteRules    map[string]bool
	deleteObjects  []design.Change
	affected       []*firemon.Rule // rules whose traffic must keep its decisions
	deletedObjects []string
}

func newBuilder(fw *firemon.Firewall, naming design.Naming) *builder {
	return &builder{fw: fw, cfg: fw.Config(), cat: design.NewCatalog(fw, naming), deleteRules: map[string]bool{}}
}

func (b *builder) add(f Finding) error {
	switch f.Category {
	case CategoryRedundant:
		for _, id := range f.Rules {
			r, _ := b.fw.Rule(id)
			b.affected = append(b.affected, r)
			b.deleteRules[id] = true
		}
	case CategoryNeverMatches, CategoryIncomplete, CategoryDisabled, CategoryExpired:
		for _, id := range f.Rules {
			b.deleteRules[id] = true // matches nothing now or ever
		}
	case CategoryMergeable:
		return b.merge(f.Merge)
	case CategoryUnusedObject:
		for _, o := range f.Objects {
			if err := b.deleteObject(o); err != nil {
				return err
			}
		}
	case CategoryUnset, CategoryEmptyObject, CategoryShadowed, CategoryBroad, CategoryZeroHit:
		return fmt.Errorf("%w: %s", ErrNotSafe, f.ID)
	}
	return nil
}

// merge extends the kept rule with the removed rules' sets and deletes them.
func (b *builder) merge(m *Merge) error {
	keep, ok := b.fw.Rule(m.Keep)
	if !ok {
		return fmt.Errorf("converge: merge into unknown rule %q", m.Keep)
	}
	var addr traffic.AddressSet
	var svc traffic.ServiceSet
	for _, id := range m.Remove {
		r, _ := b.fw.Rule(id)
		b.affected = append(b.affected, r)
		b.deleteRules[id] = true
		switch m.Field {
		case design.FieldSource:
			addr = addr.Union(r.Match().Src)
		case design.FieldDestination:
			addr = addr.Union(r.Match().Dst)
		case design.FieldService:
			svc = svc.Union(r.Match().Service)
		case design.FieldUnset:
		}
	}
	b.affected = append(b.affected, keep)
	var names []string
	switch m.Field {
	case design.FieldSource, design.FieldDestination:
		names = b.cat.AddressNames(addr.Subtract(fieldSet(keep.Match(), m.Field)))
	case design.FieldService:
		names = b.cat.ServiceNames(svc.Subtract(keep.Match().Service))
	case design.FieldUnset:
		return fmt.Errorf("converge: merge into %q without a field", m.Keep)
	}
	if len(names) > 0 {
		b.extend = append(b.extend, design.ExtendRule{RuleID: m.Keep, Field: m.Field, Names: names})
	}
	return nil
}

func fieldSet(s traffic.Space, f design.Field) traffic.AddressSet {
	if f == design.FieldSource {
		return s.Src
	}
	return s.Dst
}

// deleteObject records the deletion of an object with its definition.
func (b *builder) deleteObject(o firemon.ObjectRef) error {
	var ch design.Change
	switch o.Kind {
	case firemon.ObjectKindAddress:
		if i := slices.IndexFunc(b.cfg.Addresses, func(a firemon.Address) bool { return a.Name == o.Name }); i >= 0 {
			ch = design.DeleteAddress{Address: b.cfg.Addresses[i]}
		}
	case firemon.ObjectKindAddressGroup:
		if i := slices.IndexFunc(b.cfg.AddressGroups, func(g firemon.AddressGroup) bool { return g.Name == o.Name }); i >= 0 {
			ch = design.DeleteAddressGroup{Group: b.cfg.AddressGroups[i]}
		}
	case firemon.ObjectKindService:
		if i := slices.IndexFunc(b.cfg.Services, func(s firemon.Service) bool { return s.Name == o.Name }); i >= 0 {
			ch = design.DeleteService{Service: b.cfg.Services[i]}
		}
	case firemon.ObjectKindServiceGroup:
		if i := slices.IndexFunc(b.cfg.ServiceGroups, func(g firemon.ServiceGroup) bool { return g.Name == o.Name }); i >= 0 {
			ch = design.DeleteServiceGroup{Group: b.cfg.ServiceGroups[i]}
		}
	case firemon.ObjectKindSchedule:
		if i := slices.IndexFunc(b.cfg.Schedules, func(s firemon.Schedule) bool { return s.Name == o.Name }); i >= 0 {
			ch = design.DeleteSchedule{Schedule: b.cfg.Schedules[i]}
		}
	case firemon.ObjectKindUnset:
	}
	if ch == nil {
		return fmt.Errorf("converge: unknown object %s", o)
	}
	b.deleteObjects = append(b.deleteObjects, ch)
	b.deletedObjects = append(b.deletedObjects, o.Name)
	return nil
}

// changes returns the changes in order. Each deleted rule records the next
// rule of the original order, so that a rollback, which runs in reverse,
// puts every rule back in place.
func (b *builder) changes() []design.Change {
	out := slices.Concat(b.cat.Created(), b.extend)
	rules := b.cfg.Rules
	for i, r := range rules {
		if !b.deleteRules[r.ID] {
			continue
		}
		next := ""
		if i+1 < len(rules) {
			next = rules[i+1].ID
		}
		out = append(out, design.DeleteRule{Rule: r, Next: next})
	}
	return append(out, b.deleteObjects...)
}

// verify applies the changes and compares the decisions before and after,
// for each changed rule's traffic on every zone pair the rule applies to.
// A cleanup only moves or removes the decisions of that traffic.
func verify(fw *firemon.Firewall, changes []design.Change, affected []*firemon.Rule, deleted []string, at time.Time) error {
	cfg := fw.Config()
	if err := design.Apply(cfg, changes); err != nil {
		return err
	}
	after, err := firemon.Compile(cfg)
	if err != nil {
		return err
	}
	for _, is := range after.Issues() {
		for _, name := range deleted {
			if strings.Contains(is.Reason, `"`+name+`"`) {
				return fmt.Errorf("converge: %s still refers to deleted %q", is.Object, name)
			}
		}
	}
	before, now := query.New(fw, query.Options{}), query.New(after, query.Options{})
	zones := zoneNames(cfg)
	for _, r := range affected {
		for _, pair := range pairsOf(r, zones) {
			a, b := before.Evaluate(pair.from, pair.to, r.Match(), at), now.Evaluate(pair.from, pair.to, r.Match(), at)
			if a.Incomplete || b.Incomplete {
				return fmt.Errorf("converge: verification of rule %s exceeded the budget", r.ID())
			}
			for _, o := range []query.Outcome{query.OutcomePermit, query.OutcomeDeny, query.OutcomeDefault, query.OutcomeUnknown} {
				if !sameRegion(a.Region(o), b.Region(o)) {
					return fmt.Errorf("%w: rule %s, %s -> %s", ErrPolicyChanged, r.ID(), pair.from, pair.to)
				}
			}
		}
	}
	return nil
}

type zonePair struct{ from, to string }

// pairsOf lists the zone pairs a rule applies to; a rule for any zone is
// checked on the zones that have interfaces.
func pairsOf(r *firemon.Rule, zones []string) []zonePair {
	from, to := r.Zones()
	if len(from) == 0 {
		from = zones
	}
	if len(to) == 0 {
		to = zones
	}
	var out []zonePair
	for _, f := range from {
		for _, t := range to {
			if r.Applies(f, t) {
				out = append(out, zonePair{f, t})
			}
		}
	}
	return out
}

// zoneNames returns the zones with interfaces, or every zone when none
// has: traffic only enters and leaves through interfaces.
func zoneNames(cfg *firemon.Config) []string {
	bound := map[string]bool{}
	for _, i := range cfg.Interfaces {
		bound[i.Zone] = true
	}
	var out, all []string
	for _, z := range cfg.Zones {
		all = append(all, z.Name)
		if bound[z.Name] {
			out = append(out, z.Name)
		}
	}
	switch {
	case len(out) > 0:
		return out
	case len(all) > 0:
		return all
	default:
		return []string{""}
	}
}

func sameRegion(a, b traffic.Region) bool {
	return a.SubtractRegion(b).IsEmpty() && b.SubtractRegion(a).IsEmpty()
}
