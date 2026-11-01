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
	"os"
	"time"
)

type reclamationDocument struct {
	Version int                         `json:"version"`
	Request analysis.ReclamationRequest `json:"request"`
	Rules   []fm.ID                     `json:"rules"`
}
type migrationDocument struct {
	Version        int                                 `json:"version"`
	TargetRevision string                              `json:"target_revision"`
	At             time.Time                           `json:"at"`
	Zones          []struct{ From, To fm.ID }          `json:"zones"`
	Chains         []struct{ From, To fm.PolicyChain } `json:"chains"`
	Pairs          []analysis.ZonePair                 `json:"pairs"`
	Rules          []fm.ID                             `json:"rules"`
}

func lifecyclePlan(p *plan.Plan) *operations.PlanDocument {
	if p == nil {
		return nil
	}
	return &operations.PlanDocument{Digest: p.Digest(), Proof: p.Proof(), Changes: p.Changes(), Commands: p.Commands(), Cost: p.Cost()}
}
func lifecycleCommand(ctx context.Context, command string, args []string, out io.Writer) error {
	fs := flags(command)
	root := fs.String("store", "", "snapshot directory")
	revision := fs.String("revision", "", "explicit immutable source revision")
	file := fs.String("file", "", "version-1 lifecycle JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *root == "" || *revision == "" || *file == "" {
		return analysis.ErrInvalid
	}
	store, err := snapshot.Open(*root)
	if err != nil {
		return err
	}
	fw, err := store.Load(ctx, *revision)
	if err != nil {
		return err
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
		var d reclamationDocument
		if err = readAnalysisDocument(*file, &d); err != nil {
			return err
		}
		if d.Version != 1 || len(d.Rules) > 100 || d.Request.Revision != "" && d.Request.Revision != *revision {
			return analysis.ErrInvalid
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
		var d migrationDocument
		if err = readAnalysisDocument(*file, &d); err != nil {
			return err
		}
		if d.Version != 1 || d.TargetRevision == "" || len(d.Zones) > 100 || len(d.Chains) > 100 || len(d.Rules) > 100 || len(d.Pairs) > 100 {
			return analysis.ErrInvalid
		}
		target, e := store.Load(ctx, d.TargetRevision)
		if e != nil {
			return e
		}
		targetRevision = d.TargetRevision
		targetRenderer, e := vendors.Renderer(target.Metadata().Vendor)
		if e != nil {
			return e
		}
		q := analysis.MigrationRequest{Zones: map[fm.ID]fm.ID{}, Chains: map[fm.PolicyChain]fm.PolicyChain{}, At: d.At, Pairs: d.Pairs, Rules: d.Rules}
		for _, z := range d.Zones {
			if _, ok := q.Zones[z.From]; ok {
				return analysis.ErrInvalid
			}
			q.Zones[z.From] = z.To
		}
		for _, c := range d.Chains {
			if _, ok := q.Chains[c.From]; ok {
				return analysis.ErrInvalid
			}
			q.Chains[c.From] = c.To
		}
		p, e := (analysis.PolicyMigrator{Planner: plan.Planner{Renderer: targetRenderer}}).Plan(ctx, fw, target, q)
		if e != nil {
			return e
		}
		report = lifecyclePlan(p)
	case "convergence-plan":
		var d struct {
			Version int       `json:"version"`
			At      time.Time `json:"at"`
			Rules   []fm.ID   `json:"rules"`
		}
		if err = readAnalysisDocument(*file, &d); err != nil {
			return err
		}
		if d.Version != 1 || len(d.Rules) > 100 {
			return analysis.ErrInvalid
		}
		p, e := (analysis.Converger{Planner: planner}).Plan(ctx, fw, d.Rules, d.At)
		if e != nil {
			return e
		}
		report = lifecyclePlan(p)
	case "usage-report":
		report, err = readUsageDocument(ctx, *file, *revision, fw)
		if err != nil {
			return err
		}
	default:
		return analysis.ErrInvalid
	}
	return analysisOutput(out, struct {
		Version     int    `json:"version"`
		Revision    string `json:"revision"`
		Target      string `json:"target_revision,omitempty"`
		GraphDigest string `json:"graph_digest"`
		Report      any    `json:"report"`
	}{1, *revision, targetRevision, fw.SemanticDigest(), report})
}

type counterDocument struct {
	File        string    `json:"file"`
	At          time.Time `json:"at"`
	Revision    string    `json:"revision"`
	GraphDigest string    `json:"graph_digest"`
	Source      string    `json:"source"`
	Epoch       string    `json:"epoch"`
	Complete    bool      `json:"complete"`
}

func readUsageDocument(ctx context.Context, path, revision string, fw *fm.Firewall) (analysis.UsageReport, error) {
	var d struct {
		Version     int               `json:"version"`
		File        string            `json:"file"`
		Revision    string            `json:"revision"`
		GraphDigest string            `json:"graph_digest"`
		Source      string            `json:"source"`
		Scope       string            `json:"scope"`
		Window      fm.TimeWindow     `json:"window"`
		Complete    bool              `json:"complete"`
		Samples     []counterDocument `json:"samples"`
	}
	if err := readAnalysisDocument(path, &d); err != nil {
		return analysis.UsageReport{}, err
	}
	if d.Version != 1 {
		return analysis.UsageReport{}, analysis.ErrInvalid
	}
	ingest := analysis.NativeUsage{Engine: policy.Engine{}}
	if fw.Metadata().Vendor == "asa" {
		if len(d.Samples) != 2 || d.File != "" {
			return analysis.UsageReport{}, analysis.ErrInvalid
		}
		var samples [2]analysis.CounterSample
		var files []*os.File
		defer func() {
			for _, f := range files {
				_ = f.Close()
			}
		}()
		for i, s := range d.Samples {
			f, err := os.Open(s.File)
			if err != nil {
				return analysis.UsageReport{}, err
			}
			files = append(files, f)
			samples[i] = analysis.CounterSample{Reader: f, At: s.At, Revision: s.Revision, GraphDigest: s.GraphDigest, Source: s.Source, Epoch: s.Epoch, Complete: s.Complete}
		}
		return ingest.ReadASACounters(ctx, fw, revision, samples[0], samples[1])
	}
	if len(d.Samples) > 0 || d.File == "" {
		return analysis.UsageReport{}, analysis.ErrInvalid
	}
	f, err := os.Open(d.File)
	if err != nil {
		return analysis.UsageReport{}, err
	}
	report, err := ingest.ReadSessions(ctx, fw, revision, analysis.SessionLog{Reader: f, Revision: d.Revision, GraphDigest: d.GraphDigest, Source: d.Source, Scope: d.Scope, Window: d.Window, Complete: d.Complete})
	return report, errors.Join(err, f.Close())
}
