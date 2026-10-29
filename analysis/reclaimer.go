package analysis

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/plan"
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
	hasWindow, err := request.validate()
	if err != nil {
		return nil, err
	}
	budget := visitBudget(r.Planner.Engine.Limits.WithDefaults().MaxVisits)
	if err := budget.take(ctx, len(request.Observations)); err != nil {
		return nil, err
	}
	if err := budget.take(ctx, fw.RuleCount()); err != nil {
		return nil, err
	}
	rules := fw.Rules()
	rows := make([]Reclamation, 0, len(rules))
	for _, rule := range rules {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
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
	var evidence []usageEvidence
	if hasWindow {
		evidence = make([]usageEvidence, len(rows))
		index := make(usageIndex[RuleIdentity], len(rows))
		for i, row := range rows {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			identity, _ := IdentifyRule(fw, row.Rule)
			evidence[i].digest = row.RuleDigest
			index[identity] = &evidence[i]
		}
		for _, o := range request.Observations {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			index.observe(o.Identity, o, request)
		}
	}
	contexts, err := r.Planner.Engine.Contexts(ctx, request.At, fw)
	if err != nil {
		return nil, err
	}
	seen := make(map[fm.ID]bool)
	for _, q := range contexts {
		if err := budget.take(ctx, len(rules)); err != nil {
			return nil, err
		}
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
		if err := budget.take(ctx, 1); err != nil {
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
			row.Unused, err = evidence[i].unused(ctx, request.Window)
			if err != nil {
				return nil, err
			}
		}
	}
	return rows, nil
}

func (r Reclaimer) Plan(ctx context.Context, fw *fm.Firewall, request ReclamationRequest, ids []fm.ID) (*plan.Plan, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
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
