package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseBackupsReportsFailuresWithoutPublishingOrExposingSource(t *testing.T) {
	dir := t.TempDir()
	raw := []byte("hostname confidential-host\nrule id 1\nsrc-addr any\ndst-addr any\nservice any\naction deny\nexit\n")
	if err := os.WriteFile(filepath.Join(dir, "secret.cfg"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	manifest := map[string]any{"schema_version": 2, "devices": []map[string]any{
		{"vendor": "hillstone", "status": "failed", "path": ""},
		{"vendor": "hillstone", "status": "backed_up", "path": "secret.cfg", "bytes": len(raw), "sha256": fmt.Sprintf("%x", sha256.Sum256(raw))},
		{"vendor": "palo_alto", "status": "backed_up", "path": "secret.cfg", "bytes": len(raw), "sha256": strings.Repeat("0", 64)},
	}}
	b, _ := json.Marshal(manifest)
	if err := os.WriteFile(filepath.Join(dir, "summary.json"), b, 0600); err != nil {
		t.Fatal(err)
	}
	var out, stderr bytes.Buffer
	code := runCLI(t.Context(), []string{"parse", "--dir", dir, "--vendor", "hillstone", "--vendor", "paloalto"}, &out, &stderr)
	if code != 1 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	var report struct {
		Samples []struct {
			Status   string
			Complete bool
			Objects  map[string]int
		}
	}
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatal(err, out.String())
	}
	if len(report.Samples) != 3 || report.Samples[0].Status != "capture-failed" || report.Samples[1].Status != "parsed" || report.Samples[2].Status != "checksum-mismatch" {
		t.Fatal(out.String())
	}
	if report.Samples[1].Complete || report.Samples[1].Objects["rules"] != 1 {
		t.Fatal("capture success became completeness", out.String())
	}
	if strings.Contains(out.String()+stderr.String(), "confidential") || strings.Contains(out.String(), "secret.cfg") {
		t.Fatal("private source exposed")
	}
	files, err := os.ReadDir(dir)
	if err != nil || len(files) != 2 {
		t.Fatal("parse published files", err)
	}
}

func TestParseBackupPathsStayInsideDirectory(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "external.cfg")
	raw := []byte("hostname secret\n")
	if err := os.WriteFile(outside, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "link.cfg")); err != nil {
		t.Fatal(err)
	}
	parent, err := filepath.Rel(dir, outside)
	if err != nil {
		t.Fatal(err)
	}
	for path, status := range map[string]string{outside: "invalid-path", parent: "invalid-path", "link.cfg": "read-failed"} {
		t.Run(path, func(t *testing.T) {
			b, _ := json.Marshal(map[string]any{"schema_version": 2, "devices": []map[string]any{{"vendor": "hillstone", "status": "backed_up", "path": path, "bytes": len(raw), "sha256": fmt.Sprintf("%x", sha256.Sum256(raw))}}})
			if err := os.WriteFile(filepath.Join(dir, "summary.json"), b, 0600); err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			if err := execute(t.Context(), []string{"parse", "--dir", dir, "--vendor", "hillstone"}, &out); err == nil {
				t.Fatal("escaped backup path accepted")
			}
			if strings.Contains(out.String(), "secret") {
				t.Fatal("external contents exposed")
			}
			var report parseReport
			if err := json.Unmarshal(out.Bytes(), &report); err != nil || len(report.Samples) != 1 || report.Samples[0].Status != status {
				t.Fatal("wrong containment failure", out.String(), err)
			}
		})
	}
}

func TestParseRelocatedBackupUsesMatchingPlanAndCatalog(t *testing.T) {
	dir := t.TempDir()
	raw := []byte("servgroup probes\nservice PING\nexit\n")
	book := []byte(`{"predefined_services":{"PING":[{"protocol":"icmp","source_port":"0","destination_port":"8"}]}}`)
	manifest := map[string]any{"schema_version": 2, "devices": []map[string]any{{
		"vendor": "hillstone", "host": "lab", "name": "lab", "status": "backed_up",
		"path": "/original/collector/sample.cfg", "bytes": len(raw), "sha256": fmt.Sprintf("%x", sha256.Sum256(raw)),
	}}}
	plan := map[string]any{"selected": []map[string]string{{
		"vendor": "hillstone", "host": "lab", "name": "lab", "backup_filename": "sample.cfg",
	}}}
	summary, _ := json.Marshal(manifest)
	planned, _ := json.Marshal(plan)
	for name, data := range map[string][]byte{"sample.cfg": raw, "services.json": book, "summary.json": summary, "plan.json": planned} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	args := []string{"parse", "--dir", dir, "--vendor", "hillstone", "--services", filepath.Join(dir, "services.json")}
	var out bytes.Buffer
	if err := execute(t.Context(), args, &out); err != nil {
		t.Fatal(err)
	}
	var report parseReport
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.ServiceBook != fmt.Sprintf("%x", sha256.Sum256(book)) || report.Samples[0].Objects["services"] != 1 {
		t.Fatal("catalog or provenance missing", out.String())
	}
	// An unrelated plan must not authorize rebasing the summary's external path.
	plan["selected"] = []map[string]string{{"vendor": "hillstone", "host": "other", "name": "lab", "backup_filename": "sample.cfg"}}
	planned, _ = json.Marshal(plan)
	if err := os.WriteFile(filepath.Join(dir, "plan.json"), planned, 0600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := execute(t.Context(), args, &out); err == nil || !strings.Contains(out.String(), `"invalid-path"`) {
		t.Fatal("unrelated plan authorized relocation", err, out.String())
	}
}

func TestParseCancellationKeepsErrorIdentity(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for _, args := range [][]string{
		{"--file", "missing", "--vendor", "hillstone"},
		{"--dir", "missing", "--vendor", "hillstone"},
		{"--file", "missing", "--vendor", "hillstone", "--services", "missing"},
	} {
		var out bytes.Buffer
		if err := parseConfig(ctx, args, &out); !errors.Is(err, context.Canceled) {
			t.Fatal("cancellation replaced by generic failure", err)
		}
	}
}
