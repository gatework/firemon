package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/internal/jsonio"
	"github.com/gatework/firemon/vendors"
	"github.com/gatework/firemon/vendors/hillstone"
)

const maxParseSpans = 32

type parseIssue struct {
	Code  string    `json:"code"`
	Count int       `json:"count"`
	Spans []fm.Span `json:"spans,omitempty"`
}

type parseSample struct {
	ID       string         `json:"id"`
	Vendor   string         `json:"vendor"`
	Status   string         `json:"status"`
	SHA256   string         `json:"sha256,omitempty"`
	Parser   string         `json:"parser,omitempty"`
	Complete bool           `json:"complete"`
	Objects  map[string]int `json:"objects,omitempty"`
	Evidence map[string]int `json:"evidence,omitempty"`
	Issues   []parseIssue   `json:"issues,omitempty"`
}

type parseReport struct {
	ServiceBook string        `json:"service_book,omitempty"`
	Samples     []parseSample `json:"samples"`
	Failed      int           `json:"failed"`
}

func parseConfig(ctx context.Context, args []string, out io.Writer) error {
	fs := flags("parse", out)
	file := fs.String("file", "", "single configuration file")
	dir := fs.String("dir", "", "backup directory containing summary.json (schema 2)")
	complete := fs.Bool("complete", false, "single-file capture is known complete")
	services := fs.String("services", "", "observed Hillstone service-book JSON (explicit reference catalog)")
	scope := fs.String("context", "", "selected configuration context (single file)")
	var selected []string
	fs.Func("vendor", "canonical vendor; repeat to select multiple backup vendors", func(name string) error {
		if _, err := vendors.Normalize(fm.Metadata{Vendor: name}); err != nil {
			return errors.New("unsupported vendor")
		}
		if !slices.Contains(selected, name) {
			selected = append(selected, name)
		}
		return nil
	})
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || (*file == "") == (*dir == "") || len(selected) == 0 {
		return usage(errors.New("one of file or dir, and at least one vendor are required"))
	}
	var parser config.Parser = vendors.Parser{}
	bookDigest := ""
	if *services != "" {
		if len(selected) != 1 || selected[0] != "hillstone" {
			return usage(errors.New("services requires only the hillstone vendor"))
		}
		input, finish, err := openInput(ctx, *services)
		if err != nil {
			return errors.Join(errors.New("cannot open service book"), ctx.Err())
		}
		raw, readErr := jsonio.Read(ctx, input, config.DefaultMaxBytes)
		if err := errors.Join(readErr, finish()); err != nil {
			return errors.Join(errors.New("cannot read service book"), ctx.Err())
		}
		book, err := hillstone.ReadServices(ctx, strings.NewReader(string(raw)), config.DefaultMaxServiceTerms)
		if err != nil {
			return errors.Join(errors.New("invalid service book"), ctx.Err())
		}
		parser = hillstone.Parser{Services: book}
		bookDigest = fmt.Sprintf("%x", sha256.Sum256(raw))
	}
	var report parseReport
	if *file != "" {
		if len(selected) != 1 {
			return usage(errors.New("single-file parsing requires exactly one vendor"))
		}
		row := parseSample{ID: selected[0] + "-01", Vendor: selected[0]}
		input, finish, err := openInput(ctx, *file)
		if err != nil {
			return errors.Join(errors.New("cannot open configuration input"), ctx.Err())
		}
		raw, readErr := jsonio.Read(ctx, input, config.DefaultMaxBytes)
		if err := errors.Join(readErr, finish()); err != nil {
			return errors.Join(errors.New("cannot read configuration input"), ctx.Err())
		}
		row.parse(ctx, parser, config.Source{Text: string(raw), Complete: *complete}, fm.Metadata{Context: *scope})
		report.Samples = append(report.Samples, row)
	} else {
		if *complete || *scope != "" {
			return usage(errors.New("complete and context apply only to single-file parsing"))
		}
		var err error
		report, err = parseBackups(ctx, *dir, selected, parser)
		if err != nil {
			return err
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	report.ServiceBook = bookDigest
	for _, row := range report.Samples {
		if row.Status != "parsed" {
			report.Failed++
		}
	}
	if err := output(out, report); err != nil {
		return err
	}
	if report.Failed > 0 {
		return fmt.Errorf("%d configuration samples failed; see report status codes", report.Failed)
	}
	return nil
}

func (r *parseSample) parse(ctx context.Context, parser config.Parser, source config.Source, meta fm.Metadata) {
	r.SHA256 = fmt.Sprintf("%x", sha256.Sum256([]byte(source.Text)))
	meta.Device, meta.Vendor = r.ID, r.Vendor
	fw, err := parser.Parse(ctx, source, meta)
	if err != nil {
		r.Status = "parse-failed"
		return
	}
	r.Status, r.Parser, r.Complete = "parsed", fw.Metadata().ParserVersion, fw.Complete()
	d := fw.Export()
	r.Objects = map[string]int{
		"zones": len(d.Zones), "interfaces": len(d.Interfaces), "routes": len(d.Routes),
		"addresses": len(d.Addresses), "address_groups": len(d.AddressGroups),
		"services": len(d.Services), "service_groups": len(d.ServiceGroups),
		"schedules": len(d.Schedules), "rules": len(d.Rules),
		"static_nats": len(d.StaticNATs), "dynamic_nats": len(d.DynamicNATs), "nat_pools": len(d.NATPools),
	}
	r.Evidence = make(map[string]int)
	for _, e := range d.Evidence {
		switch e.State {
		case fm.Pending:
			r.Evidence["pending"]++
		case fm.Parsed:
			r.Evidence["parsed"]++
		case fm.Ignored:
			r.Evidence["ignored"]++
		}
	}
	issues := make(map[string]*parseIssue)
	for _, d := range fw.Diagnostics() {
		issue := issues[d.Code]
		if issue == nil {
			issue = &parseIssue{Code: d.Code}
			issues[d.Code] = issue
		}
		issue.Count++
		if d.Span.First > 0 && len(issue.Spans) < maxParseSpans {
			issue.Spans = append(issue.Spans, d.Span)
		}
	}
	for _, issue := range issues {
		r.Issues = append(r.Issues, *issue)
	}
	slices.SortFunc(r.Issues, func(a, b parseIssue) int { return strings.Compare(a.Code, b.Code) })
}
