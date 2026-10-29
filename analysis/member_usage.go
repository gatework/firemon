package analysis

import (
	"context"
	"slices"
	"strings"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/policy"
)

// MemberIdentity distinguishes the same object used by different rules or in
// source, destination and service roles. GraphDigest binds its group paths.
type MemberIdentity struct {
	Rule RuleIdentity
	Role Dimension
	Kind fm.Kind
	ID   fm.ID
}

type MemberReference struct {
	Kind fm.Kind
	ID   fm.ID
}

// MemberUsageObservation is host-supplied evidence for exactly one member role.
// It is never inferred from the total hit count on a rule or a parent group.
type MemberUsageObservation struct {
	Identity                      MemberIdentity
	Revision, GraphDigest, Source string
	Start, End                    time.Time
	Hits                          uint64
	CounterReset, Complete        bool
}

type MemberUsage struct {
	Identity              MemberIdentity
	Revision, GraphDigest string
	// Paths run from a direct rule reference to this member, including both.
	Paths  [][]MemberReference
	Unused Truth
	// Member absence is not a proof of paired-flow equivalence or safe removal.
	Removable bool
}

// AnalyzeMembers reports references and observational usage, without performing
// device IO or authorizing edits. Independent member hits cannot prove that any
// source/destination/service combination was used; paired flows stay distinct.
func (r Reclaimer) AnalyzeMembers(ctx context.Context, fw *fm.Firewall, request ReclamationRequest) ([]MemberUsage, error) {
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
	if !hasWindow && len(request.MemberObservations) > 0 {
		return nil, ErrInvalid
	}
	budget := r.Planner.Engine.Limits.Rules
	if budget <= 0 {
		budget = 100000
	}
	if len(request.MemberObservations) > budget {
		return nil, policy.ErrBudget
	}
	budget -= len(request.MemberObservations)
	observations := make(map[MemberIdentity][]UsageObservation)
	for _, o := range request.MemberObservations {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		observations[o.Identity] = append(observations[o.Identity], UsageObservation{Identity: o.Identity.Rule, Revision: o.Revision, RuleDigest: o.GraphDigest, Source: o.Source, Start: o.Start, End: o.End, Hits: o.Hits, CounterReset: o.CounterReset, Complete: o.Complete})
	}
	var rows []MemberUsage
	index := make(map[MemberIdentity]int)
	var visit func(RuleIdentity, Dimension, MemberReference, []MemberReference) error
	visit = func(rule RuleIdentity, role Dimension, member MemberReference, path []MemberReference) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if budget <= 0 || len(path) >= 64 {
			return policy.ErrBudget
		}
		budget--
		cycle := slices.Contains(path, member)
		path = append(slices.Clone(path), member)
		identity := MemberIdentity{Rule: rule, Role: role, Kind: member.Kind, ID: member.ID}
		i, exists := index[identity]
		if !exists {
			i = len(rows)
			index[identity] = i
			rows = append(rows, MemberUsage{Identity: identity, Revision: request.Revision, GraphDigest: fw.SemanticDigest()})
		}
		if !slices.ContainsFunc(rows[i].Paths, func(p []MemberReference) bool { return slices.Equal(p, path) }) {
			rows[i].Paths = append(rows[i].Paths, path)
		}
		if cycle {
			return nil
		}
		switch member.Kind {
		case fm.AddressGroupObject:
			if group := fw.AddressGroup(member.ID); group != nil {
				for _, child := range group.Record().Members {
					if err := visit(rule, role, MemberReference{Kind: child.Kind, ID: child.ID}, path); err != nil {
						return err
					}
				}
			}
		case fm.ServiceGroupObject:
			if group := fw.ServiceGroup(member.ID); group != nil {
				for _, child := range group.Record().Members {
					if err := visit(rule, role, MemberReference{Kind: child.Kind, ID: child.ID}, path); err != nil {
						return err
					}
				}
			}
		}
		return nil
	}
	for _, rule := range fw.Rules() {
		if budget <= 0 {
			return nil, policy.ErrBudget
		}
		budget--
		record := rule.Record()
		identity, _ := IdentifyRule(fw, record.ID)
		for _, pair := range []struct {
			role Dimension
			refs []fm.AddressRef
		}{{Source, record.Match.Sources}, {Destination, record.Match.Destinations}} {
			for _, ref := range pair.refs {
				if err := visit(identity, pair.role, MemberReference{Kind: ref.Kind, ID: ref.ID}, nil); err != nil {
					return nil, err
				}
			}
		}
		for _, ref := range record.Match.Services {
			if err := visit(identity, Service, MemberReference{Kind: ref.Kind, ID: ref.ID}, nil); err != nil {
				return nil, err
			}
		}
	}
	if fw.Complete() && hasWindow {
		for i := range rows {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			row := &rows[i]
			row.Unused = unused(observations[row.Identity], row.Identity.Rule, request.Revision, row.GraphDigest, request.Window)
		}
	}
	return rows, nil
}
