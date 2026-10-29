package analysis

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/policy"
)

type Truth uint8

const (
	Unknown Truth = iota
	False
	True
)

type RuleIdentity struct {
	Device, Vendor, Scope, RuleSet string
	ID                             fm.ID
}

func IdentifyRule(fw *fm.Firewall, id fm.ID) (RuleIdentity, error) {
	if fw == nil || fw.Rule(id) == nil {
		return RuleIdentity{}, ErrInvalid
	}
	rule, m := fw.Rule(id), fw.Metadata()
	return RuleIdentity{Device: m.Device, Vendor: m.Vendor, Scope: rule.Scope(), RuleSet: rule.Chain().RuleSet, ID: rule.ID()}, nil
}

// RuleDigest binds the complete semantic graph as well as the rule identity.
// This deliberately invalidates evidence after changes to any shared object,
// route, NAT or ordering, rather than hashing only the rule's reference names.
func RuleDigest(fw *fm.Firewall, id fm.ID) (string, error) {
	identity, err := IdentifyRule(fw, id)
	if err != nil {
		return "", err
	}
	b, err := json.Marshal(struct {
		Identity RuleIdentity
		Graph    string
	}{identity, fw.SemanticDigest()})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

type UsageObservation struct {
	Identity                     RuleIdentity
	Revision, RuleDigest, Source string
	Start, End                   time.Time
	Hits                         uint64
	CounterReset, Complete       bool
}
type Reclamation struct {
	Rule                                 fm.ID
	RuleDigest                           string
	Disabled, Expired, Redundant, Unused Truth
	Removable                            bool
}
type Reclaimer struct {
	Planner plan.Planner
}

// ReclamationRequest supplies revision-bound evidence for one lifecycle call.
type ReclamationRequest struct {
	At                 time.Time
	Revision           string
	Window             fm.TimeWindow
	Observations       []UsageObservation
	MemberObservations []MemberUsageObservation
}

// Analyze keeps disabled, expired, shadowed and unused evidence separate. A
// zero counter never makes a rule removable; Plan proves a selected whole batch.
func (r Reclaimer) Analyze(ctx context.Context, fw *fm.Firewall, request ReclamationRequest) ([]Reclamation, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if fw == nil {
		return nil, ErrInvalid
	}
	hasWindow := !request.Window.Start.IsZero() || !request.Window.End.IsZero()
	if hasWindow && (!request.Window.Start.Before(request.Window.End) || request.At.IsZero() || request.Window.End.After(request.At) || strings.TrimSpace(request.Revision) == "") {
		return nil, ErrInvalid
	}
	if !hasWindow && len(request.Observations) > 0 {
		return nil, ErrInvalid
	}
	rules := fw.Rules()
	rows := make([]Reclamation, 0, len(rules))
	for _, rule := range rules {
		id := rule.ID()
		digest, err := RuleDigest(fw, id)
		if err != nil {
			return nil, err
		}
		rows = append(rows, Reclamation{Rule: id, RuleDigest: digest})
	}
	if !fw.Complete() {
		return rows, nil
	}
	contexts, err := r.Planner.Engine.Contexts(ctx, request.At, fw)
	if err != nil {
		return nil, err
	}
	budget := r.Planner.Engine.Limits.Rules
	if budget <= 0 {
		budget = 100000
	}
	seen := make(map[fm.ID]bool)
	for _, q := range contexts {
		if len(rules) > budget {
			return nil, policy.ErrBudget
		}
		budget -= len(rules)
		result, err := r.Planner.Engine.Query(ctx, fw, q)
		if err != nil {
			return nil, err
		}
		if !result.Complete || !result.Unknown.Empty() {
			return rows, nil
		}
		for _, trace := range result.Trace {
			if !trace.Traffic.Empty() {
				seen[trace.Rule] = true
			}
		}
	}
	for i, rule := range rules {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		row := &rows[i]
		row.Disabled, row.Expired, row.Redundant = False, False, False
		if rule.Disabled() {
			row.Disabled = True
		}
		if schedule := rule.Schedule(); schedule != nil {
			expired, known := schedule.ExpiredAt(request.At)
			row.Expired = Unknown
			if known {
				row.Expired = False
				if expired {
					row.Expired = True
				}
			}
		}
		if !rule.Disabled() && row.Expired != True && !seen[rule.ID()] {
			row.Redundant = True
		}
		row.Removable = !rule.Builtin() && (row.Disabled == True || row.Expired == True || row.Redundant == True)
		if hasWindow {
			identity, _ := IdentifyRule(fw, rule.ID())
			row.Unused = unused(request.Observations, identity, request.Revision, row.RuleDigest, request.Window)
		}
	}
	return rows, nil
}

func unused(observations []UsageObservation, id RuleIdentity, revision, digest string, window fm.TimeWindow) Truth {
	var covered []fm.TimeWindow
	uncertain := false
	for _, o := range observations {
		if o.Identity != id || o.Revision != revision || o.RuleDigest != digest || strings.TrimSpace(o.Source) == "" {
			continue
		}
		if !o.Start.Before(o.End) {
			uncertain = true
			continue
		}
		if !o.Start.Before(window.End) || !o.End.After(window.Start) {
			continue
		}
		if o.Hits > 0 {
			if !o.Start.Before(window.Start) && !o.End.After(window.End) {
				return False
			}
			uncertain = true
			continue
		}
		if !o.Complete || o.CounterReset {
			uncertain = true
			continue
		}
		covered = append(covered, fm.TimeWindow{Start: o.Start, End: o.End})
	}
	if uncertain {
		return Unknown
	}
	slices.SortFunc(covered, func(a, b fm.TimeWindow) int { return a.Start.Compare(b.Start) })
	end := window.Start
	for _, w := range covered {
		if w.Start.After(end) {
			return Unknown
		}
		if w.End.After(end) {
			end = w.End
		}
		if !end.Before(window.End) {
			return True
		}
	}
	return Unknown
}

func (r Reclaimer) Plan(ctx context.Context, fw *fm.Firewall, request ReclamationRequest, ids []fm.ID) (*plan.Plan, error) {
	if len(ids) == 0 || len(ids) > 100 {
		return nil, ErrInvalid
	}
	rows, err := r.Analyze(ctx, fw, request)
	if err != nil {
		return nil, err
	}
	removable := make(map[fm.ID]bool)
	for _, row := range rows {
		removable[row.Rule] = row.Removable
	}
	selected := make(map[fm.ID]bool)
	var changes []plan.Change
	for _, id := range ids {
		if selected[id] || !removable[id] {
			return nil, plan.ErrUnsafe
		}
		selected[id] = true
		changes = append(changes, plan.Change{Kind: plan.RemoveRule, Rule: id})
	}
	d := fw.Export()
	d.Rules = slices.DeleteFunc(d.Rules, func(v fm.RuleRecord) bool { return selected[v.ID] })
	after, err := fm.Seal(d)
	if err != nil {
		return nil, err
	}
	return r.Planner.Preserve(ctx, fw, after, changes, request.At)
}
