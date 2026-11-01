package analysis

import (
	"bufio"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"strings"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/internal/dependency"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/policy"
)

// NativeUsage ingests bounded offline evidence against one immutable revision.
// Source/revision/counter-epoch assertions belong to the capturing integration.
// It performs no device IO and never turns missing logs into unused evidence.
type NativeUsage struct {
	Engine                        policy.Engine
	MaxBytes, MaxLines, MaxIssues int
}
type UsageIssue struct {
	Line                  int
	Code, Excerpt, Source string
}
type UsageTuple struct {
	Identity RuleIdentity
	At       time.Time
	Traffic  flow.TrafficRegion
}
type UsageReport struct {
	Window                fm.TimeWindow
	Sources               []string
	Revision, GraphDigest string
	Complete              bool
	Observations          []UsageObservation
	Members               []MemberUsageObservation
	Tuples                []UsageTuple
	Issues                []UsageIssue
	OmittedIssues         int
}
type SessionLog struct {
	Reader                               io.Reader
	Revision, GraphDigest, Source, Scope string
	Window                               fm.TimeWindow
	Complete                             bool
}
type CounterSample struct {
	Reader                        io.Reader
	Revision, GraphDigest, Source string
	At                            time.Time
	// Epoch must identify a verified continuous native counter generation. Two
	// nondecreasing numbers alone cannot rule out an unseen reset between samples.
	Epoch    string
	Complete bool
}

func (u NativeUsage) defaults() NativeUsage {
	if u.MaxBytes <= 0 {
		u.MaxBytes = 16 << 20
	}
	if u.MaxLines <= 0 {
		u.MaxLines = 100000
	}
	if u.MaxIssues <= 0 {
		u.MaxIssues = 100
	}
	return u
}
func (u NativeUsage) issue(r *UsageReport, line int, code, raw string, sources ...string) {
	r.Complete = false
	if len(r.Issues) >= u.MaxIssues {
		r.OmittedIssues++
		return
	}
	if len(raw) > 256 {
		raw = raw[:256]
	}
	source := ""
	if len(r.Sources) > 0 {
		source = r.Sources[0]
	}
	if len(sources) > 0 {
		source = sources[0]
	}
	r.Issues = append(r.Issues, UsageIssue{Line: line, Code: code, Excerpt: raw, Source: source})
}
func validUsage(fw *fm.Firewall, revision, claimed, digest, source string) bool {
	return fw != nil && fw.Complete() && revision != "" && revision == claimed && digest == fw.SemanticDigest() && strings.TrimSpace(source) != "" && len(source) <= 1024
}
func (u NativeUsage) scan(ctx context.Context, reader io.Reader, fn func(int, string) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if dependency.Nil(reader) {
		return ErrInvalid
	}
	// The hard byte ceiling includes delimiters and bounds reader work even when
	// every line is blank. Limits cannot overflow when adding the sentinel byte.
	if u.MaxBytes > 1<<30 || u.MaxLines > 1000000 || u.MaxIssues > 10000 {
		return ErrInvalid
	}
	limited := &io.LimitedReader{R: reader, N: int64(u.MaxBytes) + 1}
	scanner := bufio.NewScanner(limited)
	scanner.Buffer(make([]byte, 4096), 64<<10)
	lines := 0
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return err
		}
		lines++
		if lines > u.MaxLines || limited.N == 0 {
			return policy.ErrBudget
		}
		if err := fn(lines, scanner.Text()); err != nil {
			return err
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if limited.N == 0 {
		return policy.ErrBudget
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("usage stream: %w", err)
	}
	return nil
}

// ReadSessions accepts timestamped native session tuples only when the captured
// rule identity and first-match policy decision agree. NAT-bearing captures need
// a separately established log coordinate contract and are refused here.
func (u NativeUsage) ReadSessions(ctx context.Context, fw *fm.Firewall, revision string, input SessionLog) (UsageReport, error) {
	u = u.defaults()
	out := UsageReport{Revision: revision, Complete: input.Complete, Window: input.Window, Sources: []string{input.Source}}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	if fw == nil {
		return out, ErrInvalid
	}
	out.GraphDigest = fw.SemanticDigest()
	if !validUsage(fw, revision, input.Revision, input.GraphDigest, input.Source) || input.Window.Start.IsZero() || !input.Window.Start.Before(input.Window.End) {
		u.issue(&out, 0, "unbound_revision_or_window", "")
		return out, nil
	}
	vendor := fw.Metadata().Vendor
	if vendor != "srx" && vendor != "netscreen" {
		return out, ErrInvalid
	}
	if fw.StaticNATCount() != 0 || fw.DynamicNATCount() != 0 {
		u.issue(&out, 0, "unknown_log_nat_coordinates", "")
		return out, nil
	}
	limits := u.Engine.Limits.WithDefaults()
	budget := visitBudget(limits.MaxVisits)
	if err := budget.take(ctx, fw.RecordCount()); err != nil {
		return out, err
	}
	index := map[string][]fm.ID{}
	for rule := range fw.OrderedRules() {
		if err := budget.take(ctx, 1); err != nil {
			return out, err
		}
		r := rule.Record()
		if r.Scope != input.Scope || r.Builtin {
			continue
		}
		if vendor == "srx" {
			if len(r.Match.FromZones) == 1 && len(r.Match.ToZones) == 1 {
				key := usageRuleKey(r.Name, string(r.Match.FromZones[0]), string(r.Match.ToZones[0]))
				index[key] = append(index[key], r.ID)
			}
		} else {
			index[string(r.ID)] = append(index[string(r.ID)], r.ID)
		}
	}
	memberRows, err := (Reclaimer{Planner: plan.Planner{Engine: u.Engine}}).AnalyzeMembers(ctx, fw, ReclamationRequest{})
	if err != nil {
		return out, err
	}
	members := map[fm.ID][]MemberUsage{}
	for _, r := range memberRows {
		if err := budget.take(ctx, 1); err != nil {
			return out, err
		}
		members[r.Identity.Rule.ID] = append(members[r.Identity.Rule.ID], r)
	}
	seen := map[[32]byte]bool{}
	err = u.scan(ctx, input.Reader, func(line int, raw string) error {
		if err := budget.take(ctx, 1); err != nil {
			return err
		}
		if strings.TrimSpace(raw) == "" {
			return nil
		}
		event, code := parseSession(vendor, raw)
		if code != "" {
			u.issue(&out, line, code, raw)
			return nil
		}
		if event.at.Before(input.Window.Start) || !event.at.Before(input.Window.End) {
			u.issue(&out, line, "outside_window", raw)
			return nil
		}
		key := event.key
		ids := index[key]
		if len(ids) != 1 {
			u.issue(&out, line, "missing_or_ambiguous_rule", raw)
			return nil
		}
		id := ids[0]
		record := fw.Rule(id).Record()
		if len(record.Match.FromZones) != 1 || len(record.Match.ToZones) != 1 || record.Disabled || record.Action != fm.Permit {
			u.issue(&out, line, "unsupported_rule", raw)
			return nil
		}
		signature := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%s\x00%v", id, event.at.Format(time.RFC3339Nano), event.traffic)))
		if seen[signature] {
			u.issue(&out, line, "duplicate_record", raw)
			return nil
		}
		if err := budget.take(ctx, fw.RuleCount()); err != nil {
			return err
		}
		traffic, e := flow.NewTraffic(limits.MaxRegions, event.traffic)
		if e != nil {
			return e
		}
		q := policy.Request{Traffic: traffic, At: event.at, Scope: record.Scope, RuleSet: record.RuleSet, FromZone: record.Match.FromZones[0], ToZone: record.Match.ToZones[0]}
		evaluated, e := u.Engine.Query(ctx, fw, q)
		if e != nil {
			return e
		}
		valid := evaluated.Complete && evaluated.Unknown.Empty() && len(evaluated.Decisions) == 1 && evaluated.Decisions[0].Rule == id && evaluated.Decisions[0].Known
		if !valid {
			u.issue(&out, line, "tuple_not_owned_by_rule", raw)
			return nil
		}
		if len(out.Tuples) >= limits.MaxRegions {
			return policy.ErrBudget
		}
		if err := budget.take(ctx, 2); err != nil {
			return err
		}
		seen[signature] = true
		identity, _ := IdentifyRule(fw, id)
		digest, _ := RuleDigest(fw, id)
		end := event.at.Add(time.Nanosecond)
		out.Tuples = append(out.Tuples, UsageTuple{identity, event.at, event.traffic})
		out.Observations = append(out.Observations, UsageObservation{Identity: identity, Revision: revision, RuleDigest: digest, Source: input.Source, Start: event.at, End: end, Hits: 1})
		for _, member := range members[id] {
			if err := budget.take(ctx, fw.RecordCount()); err != nil {
				return err
			}
			matches, e := u.memberMatches(ctx, fw, member.Identity, event.traffic)
			if e != nil {
				return e
			}
			if !matches {
				continue
			}
			if len(out.Members) >= limits.MaxCombinations {
				return policy.ErrBudget
			}
			out.Members = append(out.Members, MemberUsageObservation{Identity: member.Identity, Revision: revision, GraphDigest: fw.SemanticDigest(), Source: input.Source, Start: event.at, End: end, Hits: 1})
		}
		return nil
	})
	if err != nil {
		u.issue(&out, 0, "stream_incomplete", "")
		out.Observations = nil
		out.Tuples = nil
		out.Members = nil
	}
	return out, err
}
