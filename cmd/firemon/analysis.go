package main

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/gatework/firemon/analysis"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/policy"
	"github.com/gatework/firemon/snapshot"
	"github.com/gatework/firemon/vendors"
)

func analysisCommand(ctx context.Context, command string, args []string, out io.Writer) error {
	fs := flags(command, out)
	root := fs.String("store", "", "snapshot directory")
	revision := fs.String("revision", "", "explicit immutable revision")
	after := fs.String("after", "", "comparison revision")
	file := fs.String("file", "", "version-1 analysis JSON")
	at := fs.String("at", "", "proof horizon, RFC3339")
	visits := fs.Int("max-visits", cliLimits.MaxVisits, "analysis visit limit")
	regions := fs.Int("max-regions", cliLimits.MaxRegions, "traffic region limit")
	combinations := fs.Int("max-combinations", cliLimits.MaxCombinations, "expression/pair/report row limit")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *root == "" || *revision == "" || *visits <= 0 || *visits > cliLimits.MaxVisits || *regions <= 0 || *regions > cliLimits.MaxRegions || *combinations <= 0 || *combinations > cliLimits.MaxCombinations {
		return usage(analysis.ErrInvalid)
	}
	requiresFile := command == "inspect-address" || command == "risk-report"
	if requiresFile != (*file != "") || (command == "compare-revisions") != (*after != "") || requiresFile && *at != "" {
		return usage(analysis.ErrInvalid)
	}
	var from time.Time
	var err error
	if *at != "" {
		from, err = time.Parse(time.RFC3339, *at)
		if err != nil {
			return usage(err)
		}
	}
	store, err := snapshot.Open(*root)
	if err != nil {
		return snapshotArgumentError(err)
	}
	fw, err := store.Load(ctx, *revision)
	if err != nil {
		return snapshotArgumentError(err)
	}
	engine := policy.Engine{Limits: policy.Limits{MaxVisits: *visits, MaxRegions: *regions, MaxCombinations: *combinations}}
	var report any
	switch command {
	case "compare-revisions":
		next, e := store.Load(ctx, *after)
		if e != nil {
			return snapshotArgumentError(e)
		}
		report, err = (analysis.RevisionComparer{Engine: engine}).Compare(ctx, fw, next, from)
	case "inspect-address":
		var d inspectionDocument
		if err = readAnalysisDocument(ctx, *file, &d); err != nil {
			return err
		}
		q, e := d.request(*regions)
		if e != nil {
			return usage(e)
		}
		report, err = (analysis.Inspector{Engine: engine}).Inspect(ctx, fw, q)
	case "risk-report":
		var d riskDocument
		if err = readAnalysisDocument(ctx, *file, &d); err != nil {
			return err
		}
		contexts, definitions, e := d.request(engine.Limits)
		if e != nil {
			return usage(e)
		}
		report, err = (analysis.RiskAnalyzer{Engine: engine}).AnalyzeBatch(ctx, fw, contexts, definitions)
	case "convergence-report":
		renderer, e := vendors.Renderer(fw.Metadata().Vendor)
		if e != nil {
			return e
		}
		report, err = (analysis.Converger{Planner: plan.Planner{Engine: engine, Renderer: renderer}, MaxComparisons: *combinations}).Candidates(ctx, fw, from)
	default:
		return errors.New("unsupported analysis command")
	}
	if err != nil {
		return err
	}
	return analysisOutput(out, struct {
		Version     int    `json:"version"`
		Revision    string `json:"revision"`
		After       string `json:"after,omitempty"`
		GraphDigest string `json:"graph_digest"`
		Complete    bool   `json:"complete"`
		Report      any    `json:"report"`
	}{1, *revision, *after, fw.SemanticDigest(), fw.Complete(), report})
}
