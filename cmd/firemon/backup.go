package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/internal/jsonio"
)

const maxBackupFiles = 10_000

// backup is the input boundary for collector report schema 2. Unrelated
// collector fields are deliberately not part of the parser's contract.
type backup struct {
	Vendor     string    `json:"vendor"`
	Host       string    `json:"host"`
	Name       string    `json:"name"`
	Status     string    `json:"status"`
	Path       string    `json:"path"`
	Bytes      int64     `json:"bytes"`
	SHA256     string    `json:"sha256"`
	FinishedAt time.Time `json:"finished_at"`
}

func parseBackups(ctx context.Context, dir string, selected []string, parser config.Parser) (parseReport, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return parseReport{}, errors.Join(errors.New("cannot open backup directory"), ctx.Err())
	}
	defer root.Close()
	raw, err := readBackup(ctx, root, "summary.json")
	if err != nil {
		return parseReport{}, errors.Join(errors.New("cannot read backup summary"), ctx.Err())
	}
	var manifest struct {
		Version int      `json:"schema_version"`
		Devices []backup `json:"devices"`
	}
	if json.Unmarshal(raw, &manifest) != nil || manifest.Version != 2 || len(manifest.Devices) > maxBackupFiles {
		return parseReport{}, usage(errors.New("invalid or unsupported backup summary"))
	}
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return parseReport{}, errors.New("invalid backup directory")
	}
	report := parseReport{Samples: []parseSample{}}
	counts := make(map[string]int)
	files, err := backupFiles(ctx, root)
	if err != nil {
		return report, err
	}
	for _, entry := range manifest.Devices {
		if err := ctx.Err(); err != nil {
			return parseReport{}, err
		}
		vendor := entry.Vendor
		if vendor == "palo_alto" {
			vendor = "paloalto"
		}
		if !slices.Contains(selected, vendor) {
			continue
		}
		counts[vendor]++
		row := parseSample{ID: fmt.Sprintf("%s-%02d", vendor, counts[vendor]), Vendor: vendor}
		// Collector summaries retain their original absolute paths after export.
		// Rebase only through a matching, unambiguous plan entry, never by blindly
		// stripping directories from an untrusted summary path.
		if name, ok := files[[3]string{entry.Vendor, entry.Host, entry.Name}]; ok {
			if filepath.Base(entry.Path) == name {
				entry.Path = name
			}
		}
		if filepath.IsAbs(entry.Path) {
			path, err := filepath.Rel(absDir, entry.Path)
			if err != nil {
				entry.Path = ""
			} else {
				entry.Path = path
			}
		}
		row.read(ctx, root, entry, parser)
		report.Samples = append(report.Samples, row)
	}
	if len(report.Samples) == 0 {
		return report, usage(errors.New("no selected samples in backup summary"))
	}
	return report, ctx.Err()
}

func backupFiles(ctx context.Context, root *os.Root) (map[[3]string]string, error) {
	raw, err := readBackup(ctx, root, "plan.json")
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, errors.Join(errors.New("cannot read backup plan"), ctx.Err())
	}
	var plan struct {
		Selected []struct {
			Vendor string `json:"vendor"`
			Host   string `json:"host"`
			Name   string `json:"name"`
			File   string `json:"backup_filename"`
		} `json:"selected"`
	}
	if json.Unmarshal(raw, &plan) != nil || len(plan.Selected) > maxBackupFiles {
		return nil, usage(errors.New("invalid backup plan"))
	}
	files := make(map[[3]string]string)
	for _, entry := range plan.Selected {
		key := [3]string{entry.Vendor, entry.Host, entry.Name}
		if !filepath.IsLocal(entry.File) || filepath.Base(entry.File) != entry.File || entry.Host == "" || entry.Name == "" {
			return nil, usage(errors.New("invalid backup plan entry"))
		}
		if _, ok := files[key]; ok {
			return nil, usage(errors.New("duplicate backup plan entry"))
		}
		files[key] = entry.File
	}
	return files, ctx.Err()
}

func readBackup(ctx context.Context, root *os.Root, path string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f, err := root.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("backup input is not a regular file")
	}
	return jsonio.Read(ctx, f, config.DefaultMaxBytes)
}

func (r *parseSample) read(ctx context.Context, root *os.Root, entry backup, parser config.Parser) {
	if entry.Status != "backed_up" {
		r.Status = "capture-failed"
		return
	}
	path := entry.Path
	if !filepath.IsLocal(path) {
		r.Status = "invalid-path"
		return
	}
	raw, err := readBackup(ctx, root, path)
	if err != nil {
		r.Status = "read-failed"
		return
	}
	if int64(len(raw)) != entry.Bytes {
		r.Status = "size-mismatch"
		return
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(raw))
	if !strings.EqualFold(entry.SHA256, digest) {
		r.Status = "checksum-mismatch"
		return
	}
	// A successful backup verifies bytes, not semantic or capture completeness.
	r.parse(ctx, parser, config.Source{Text: string(raw)}, fm.Metadata{CapturedAt: entry.FinishedAt})
}
