package main

import (
	"context"
	"errors"
	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/analysis"
	"github.com/gatework/firemon/operations"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/policy"
	"github.com/gatework/firemon/snapshot"
	"github.com/gatework/firemon/vendors"
	"io"
	"time"
)

type reclaimDoc struct {
	Version int                         `json:"version"`
	Request analysis.ReclamationRequest `json:"request"`
	Rules   []fm.ID                     `json:"rules"`
}
type migrationDoc struct {
	Version        int                                 `json:"version"`
	TargetRevision string                              `json:"target_revision"`
	At             time.Time                           `json:"at"`
	Zones          []struct{ From, To fm.ID }          `json:"zones"`
	Chains         []struct{ From, To fm.PolicyChain } `json:"chains"`
	Pairs          []analysis.ZonePair                 `json:"pairs"`
	Rules          []fm.ID                             `json:"rules"`
	StaticNATs     []fm.ID                             `json:"static_nats"`
	DynamicNATs    []fm.ID                             `json:"dynamic_nats"`
	Interfaces     []struct{ From, To fm.ID }          `json:"interfaces"`
	VRFs           []struct{ From, To string }         `json:"vrfs"`
	VRF            string                              `json:"vrf"`
	Clock          *fm.ScheduleClock                   `json:"clock,omitempty"`
}

func lifecyclePlan(p *plan.Plan) *operations.PlanDocument {
	if p == nil {
		return nil
	}
	return &operations.PlanDocument{Digest: p.Digest(), Proof: p.Proof(), Changes: p.Changes(), Commands: p.Commands(), Cost: p.Cost()}
}
func lifecycleCommand(ctx context.Context, command string, args []string, out io.Writer) error {
	fs := flags(command, out)
	root := fs.String("store", "", "snapshot directory")
	revision := fs.String("revision", "", "explicit immutable source revision")
	file := fs.String("file", "", "version-1 lifecycle JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *root == "" || *revision == "" || *file == "" {
		return usage(analysis.ErrInvalid)
	}
	store, err := snapshot.Open(*root)
	if err != nil {
		return snapshotArgumentError(err)
	}
	fw, err := store.Load(ctx, *revision)
	if err != nil {
		return snapshotArgumentError(err)
	}
	renderer, err := vendors.Renderer(fw.Metadata().Vendor)
	if err != nil {
		return err
	}
	planner := plan.Planner{Renderer: renderer}
	var report any
	var targetRevision string
	switch command {
	case "reclamation-report", "reclamation-plan":
		var d reclaimDoc
		if err = readJSON(ctx, *file, &d); err != nil {
			return err
		}
		if d.Version != 1 || len(d.Rules) > 100 || d.Request.Revision != "" && d.Request.Revision != *revision {
			return usage(analysis.ErrInvalid)
		}
		d.Request.Revision = *revision
		reclaimer := analysis.Reclaimer{Planner: planner}
		if command == "reclamation-plan" {
			p, e := reclaimer.Plan(ctx, fw, d.Request, d.Rules)
			if e != nil {
				return e
			}
			report = lifecyclePlan(p)
		} else {
			rules, e := reclaimer.Analyze(ctx, fw, d.Request)
			if e != nil {
				return e
			}
			members, e := reclaimer.AnalyzeMembers(ctx, fw, d.Request)
			if e != nil {
				return e
			}
			report = struct {
				Rules   []analysis.Reclamation
				Members []analysis.MemberUsage
			}{rules, members}
		}
	case "migration-report", "migration-plan":
		var d migrationDoc
		if err = readJSON(ctx, *file, &d); err != nil {
			return err
		}
		if d.Version != 1 || d.TargetRevision == "" || len(d.Zones) > 100 || len(d.Chains) > 100 || len(d.Rules) > 100 || len(d.Pairs) > 100 || len(d.Interfaces) > 100 || len(d.VRFs) > 100 || len(d.StaticNATs) > 100 || len(d.DynamicNATs) > 100 {
			return usage(analysis.ErrInvalid)
		}
		target, e := store.Load(ctx, d.TargetRevision)
		if e != nil {
			return snapshotArgumentError(e)
		}
		targetRevision = d.TargetRevision
		targetRenderer, e := vendors.Renderer(target.Metadata().Vendor)
		if e != nil {
			return e
		}
		q := analysis.MigrationRequest{Zones: map[fm.ID]fm.ID{}, Chains: map[fm.PolicyChain]fm.PolicyChain{}, At: d.At, Pairs: d.Pairs, Rules: d.Rules, StaticNATs: d.StaticNATs, DynamicNATs: d.DynamicNATs, Interfaces: map[fm.ID]fm.ID{}, VRFs: map[string]string{}, VRF: d.VRF, Clock: d.Clock}
		for _, pair := range d.Interfaces {
			if _, ok := q.Interfaces[pair.From]; ok {
				return usage(analysis.ErrInvalid)
			}
			q.Interfaces[pair.From] = pair.To
		}
		for _, pair := range d.VRFs {
			if _, ok := q.VRFs[pair.From]; ok {
				return usage(analysis.ErrInvalid)
			}
			q.VRFs[pair.From] = pair.To
		}
		for _, z := range d.Zones {
			if _, ok := q.Zones[z.From]; ok {
				return usage(analysis.ErrInvalid)
			}
			q.Zones[z.From] = z.To
		}
		for _, c := range d.Chains {
			if _, ok := q.Chains[c.From]; ok {
				return usage(analysis.ErrInvalid)
			}
			q.Chains[c.From] = c.To
		}
		p, e := (analysis.Migrator{Planner: plan.Planner{Renderer: targetRenderer}}).Plan(ctx, fw, target, q)
		if e != nil {
			return e
		}
		report = struct {
			Plan   *operations.PlanDocument `json:"plan,omitempty"`
			Issues []plan.MigrationIssue    `json:"issues,omitempty"`
		}{lifecyclePlan(p.Plan), p.Issues}
	case "convergence-plan":
		var d struct {
			Version int       `json:"version"`
			At      time.Time `json:"at"`
			Rules   []fm.ID   `json:"rules"`
		}
		if err = readJSON(ctx, *file, &d); err != nil {
			return err
		}
		if d.Version != 1 || len(d.Rules) > 100 {
			return usage(analysis.ErrInvalid)
		}
		p, e := (analysis.Converger{Planner: planner}).Plan(ctx, fw, d.Rules, d.At)
		if e != nil {
			return e
		}
		report = lifecyclePlan(p)
	case "usage-report":
		report, err = readUsage(ctx, *file, *revision, fw)
		if err != nil {
			return err
		}
	default:
		return usage(analysis.ErrInvalid)
	}
	return analysisOutput(out, struct {
		Version     int    `json:"version"`
		Revision    string `json:"revision"`
		Target      string `json:"target_revision,omitempty"`
		GraphDigest string `json:"graph_digest"`
		Report      any    `json:"report"`
	}{1, *revision, targetRevision, fw.SemanticDigest(), report})
}

type counterDoc struct {
	File        string    `json:"file"`
	At          time.Time `json:"at"`
	Revision    string    `json:"revision"`
	GraphDigest string    `json:"graph_digest"`
	Source      string    `json:"source"`
	Epoch       string    `json:"epoch"`
	Complete    bool      `json:"complete"`
}

func readUsage(ctx context.Context, path, revision string, fw *fm.Firewall) (report analysis.UsageReport, err error) {
	var d struct {
		Version     int           `json:"version"`
		File        string        `json:"file"`
		Revision    string        `json:"revision"`
		GraphDigest string        `json:"graph_digest"`
		Source      string        `json:"source"`
		Scope       string        `json:"scope"`
		Window      fm.TimeWindow `json:"window"`
		Complete    bool          `json:"complete"`
		Samples     []counterDoc  `json:"samples"`
	}
	if err := readJSON(ctx, path, &d); err != nil {
		return analysis.UsageReport{}, err
	}
	if d.Version != 1 {
		return analysis.UsageReport{}, usage(analysis.ErrInvalid)
	}
	ingest := analysis.NativeUsage{Engine: policy.Engine{}}
	if fw.Metadata().Vendor == "asa" {
		if len(d.Samples) != 2 || d.File != "" {
			return analysis.UsageReport{}, usage(analysis.ErrInvalid)
		}
		var samples [2]analysis.CounterSample
		var finishes []func() error
		defer func() {
			for _, finish := range finishes {
				err = errors.Join(err, finish())
			}
		}()
		for i, s := range d.Samples {
			f, finish, err := openInput(ctx, s.File)
			if err != nil {
				return analysis.UsageReport{}, err
			}
			finishes = append(finishes, finish)
			samples[i] = analysis.CounterSample{Reader: f, At: s.At, Revision: s.Revision, GraphDigest: s.GraphDigest, Source: s.Source, Epoch: s.Epoch, Complete: s.Complete}
		}
		return ingest.ReadASACounters(ctx, fw, revision, samples[0], samples[1])
	}
	if len(d.Samples) > 0 || d.File == "" {
		return analysis.UsageReport{}, usage(analysis.ErrInvalid)
	}
	f, finish, err := openInput(ctx, d.File)
	if err != nil {
		return analysis.UsageReport{}, err
	}
	report, err = ingest.ReadSessions(ctx, fw, revision, analysis.SessionLog{Reader: f, Revision: d.Revision, GraphDigest: d.GraphDigest, Source: d.Source, Scope: d.Scope, Window: d.Window, Complete: d.Complete})
	return report, errors.Join(err, finish())
}
