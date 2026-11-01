package analysis

import (
	"context"
	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/policy"
	"github.com/gatework/firemon/vendors/asa"
	"regexp"
	"strconv"
	"strings"
)

var asaCounter = regexp.MustCompile(`^access-list\s+(\S+)\s+line\s+\d+\s+(extended\s+.+?)\s+\(hitcnt=(\d+)\)(?:\s+0x[0-9a-fA-F]+)?\s*$`)

type nativeCounter struct {
	hits  uint64
	valid bool
}

// ReadASACounters matches complete ACL declarations, never persistent line
// numbers or expanded child rows. Deltas require the same verified counter epoch.
func (u NativeUsage) ReadASACounters(ctx context.Context, fw *fm.Firewall, revision string, first, second CounterSample) (UsageReport, error) {
	u = u.defaults()
	out := UsageReport{Revision: revision, Complete: first.Complete && second.Complete, Window: fm.TimeWindow{Start: first.At, End: second.At}, Sources: []string{first.Source, second.Source}}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	if fw == nil || fw.Metadata().Vendor != "asa" {
		return out, ErrInvalid
	}
	out.GraphDigest = fw.SemanticDigest()
	if !validUsage(fw, revision, first.Revision, first.GraphDigest, first.Source) || !validUsage(fw, revision, second.Revision, second.GraphDigest, second.Source) || first.At.IsZero() || !first.At.Before(second.At) {
		u.issue(&out, 0, "unbound_revision_or_window", "")
		return out, nil
	}
	budget := visitBudget(u.Engine.Limits.WithDefaults().MaxVisits)
	if err := budget.take(ctx, fw.RuleCount()); err != nil {
		return out, err
	}
	catalog := map[fm.ID][]fm.ID{}
	for rule := range fw.OrderedRules() {
		if rule.Builtin() {
			continue
		}
		id := rule.ID()
		root := id
		for strings.HasSuffix(string(root), "-duplicate") {
			root = fm.ID(strings.TrimSuffix(string(root), "-duplicate"))
		}
		catalog[root] = append(catalog[root], id)
	}
	parse := func(sample CounterSample) (map[fm.ID]nativeCounter, error) {
		counters := map[fm.ID]nativeCounter{}
		err := u.scan(ctx, sample.Reader, func(line int, raw string) error {
			if err := budget.take(ctx, 1); err != nil {
				return err
			}
			if strings.TrimSpace(raw) == "" {
				return nil
			}
			match := asaCounter.FindStringSubmatch(strings.TrimSpace(raw))
			if match == nil {
				u.issue(&out, line, "unrecognized_counter_record", raw, sample.Source)
				return nil
			}
			native := "access-list " + match[1] + " " + match[2]
			content, e := config.NewContent(ctx, config.Source{Text: native}, config.Limits{MaxBytes: 64 << 10, MaxLines: 1})
			if e != nil {
				return e
			}
			rows, e := config.Statements(ctx, content)
			if e != nil || len(rows) != 1 {
				u.issue(&out, line, "invalid_declaration", raw, sample.Source)
				return nil
			}
			id := asa.ACLDeclarationID(rows[0].Words)
			ids := catalog[id]
			if len(ids) != 1 {
				u.issue(&out, line, "missing_or_ambiguous_declaration", raw, sample.Source)
				return nil
			}
			id = ids[0]
			count, e := strconv.ParseUint(match[3], 10, 64)
			if e != nil {
				u.issue(&out, line, "invalid_counter", raw, sample.Source)
				return nil
			}
			if _, exists := counters[id]; exists {
				counters[id] = nativeCounter{}
				u.issue(&out, line, "duplicate_counter", raw, sample.Source)
				return nil
			}
			if err := budget.take(ctx, 1); err != nil {
				return err
			}
			counters[id] = nativeCounter{count, true}
			return nil
		})
		return counters, err
	}
	a, err := parse(first)
	if err != nil {
		out.Complete = false
		return out, err
	}
	b, err := parse(second)
	if err != nil {
		out.Complete = false
		return out, err
	}
	epoch := first.Epoch != "" && first.Epoch == second.Epoch && len(first.Epoch) <= 1024
	if !epoch {
		u.issue(&out, 0, "unproven_counter_continuity", "")
	}
	for rule := range fw.OrderedRules() {
		if rule.Builtin() {
			continue
		}
		if err := budget.take(ctx, 1); err != nil {
			return UsageReport{}, err
		}
		x, xok := a[rule.ID()]
		y, yok := b[rule.ID()]
		valid := epoch && xok && yok && x.valid && y.valid && y.hits >= x.hits
		reset := xok && yok && y.hits < x.hits
		if !valid {
			u.issue(&out, 0, "unknown_counter_delta", "")
		}
		identity, _ := IdentifyRule(fw, rule.ID())
		digest, _ := RuleDigest(fw, rule.ID())
		o := UsageObservation{Identity: identity, RuleDigest: digest, Revision: revision, Source: first.Source + " -> " + second.Source, Start: first.At, End: second.At, CounterReset: reset, Complete: valid && first.Complete && second.Complete}
		if valid {
			o.Hits = y.hits - x.hits
		}
		if len(out.Observations) >= u.Engine.Limits.WithDefaults().MaxCombinations {
			return UsageReport{}, policy.ErrBudget
		}
		out.Observations = append(out.Observations, o)
	}
	return out, nil
}
