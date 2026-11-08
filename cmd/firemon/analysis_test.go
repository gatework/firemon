package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/analysis"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/policy"
	"github.com/gatework/firemon/snapshot"
	"github.com/gatework/firemon/vendors"
)

func TestOfflineAnalysisReportsBoundRevisionsAndTrafficJSON(t *testing.T) {
	root := t.TempDir()
	store, err := snapshot.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	raw := "address src\n ip 192.0.2.1/32\nexit\naddress dst\n ip 198.51.100.1/32\nexit\npolicy-global\nrule id 1\n action permit\n src-addr src\n dst-addr dst\n service any\nexit\nexit\n"
	fw, err := (vendors.Parser{}).Parse(context.Background(), config.Source{Text: raw, Complete: true}, fm.Metadata{Device: "fw", Vendor: "hillstone"})
	if err != nil || !fw.Complete() {
		t.Fatal(fw, err)
	}
	rev, err := store.Archive(context.Background(), fw)
	if err != nil {
		t.Fatal(err)
	}
	q, err := requestTraffic("192.0.2.1/32", "198.51.100.1/32", "tcp/443")
	if err != nil {
		t.Fatal(err)
	}
	contextDoc := map[string]any{"traffic": q.Regions()}
	for _, command := range []string{"inspect-address", "risk-report", "convergence-report", "compare-revisions"} {
		var doc any
		args := []string{command, "--store", root, "--revision", rev}
		switch command {
		case "inspect-address":
			doc = map[string]any{"version": 1, "object": map[string]any{"Kind": fm.AddressObject, "ID": "src"}, "evaluation": contextDoc}
		case "risk-report":
			doc = map[string]any{"version": 1, "contexts": []any{contextDoc}, "definitions": []any{map[string]any{"id": "risk", "version": "1", "mode": 1, "relation": 1, "traffic": q.Regions()}}}
		case "compare-revisions":
			args = append(args, "--after", rev)
		}
		if doc != nil {
			data, _ := json.Marshal(doc)
			file := filepath.Join(root, command+".json")
			if err := os.WriteFile(file, data, 0600); err != nil {
				t.Fatal(err)
			}
			args = append(args, "--file", file)
		}
		var out bytes.Buffer
		if err := run(args, &out); err != nil {
			t.Fatalf("%s: %v", command, err)
		}
		var report map[string]json.RawMessage
		if err := json.Unmarshal(out.Bytes(), &report); err != nil {
			t.Fatal(err)
		}
		if string(report["revision"]) != `"`+rev+`"` {
			t.Fatal("unbound report", out.String())
		}
		if command == "risk-report" && (!strings.Contains(out.String(), `"traffic": [`) || !strings.Contains(out.String(), "192.0.2.1")) {
			t.Fatal("traffic silently serialized as empty object", out.String())
		}
		if command == "compare-revisions" && !strings.Contains(out.String(), `"behavior": "equivalent"`) {
			t.Fatal(out.String())
		}
	}
	var out bytes.Buffer
	file := filepath.Join(root, "bad.json")
	if err := os.WriteFile(file, []byte(`{"version":1,"typo":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"inspect-address", "--store", root, "--revision", rev, "--file", file}, &out); err == nil || out.Len() != 0 {
		t.Fatal("accepted unknown fields", err, out.String())
	}
}

func TestAnalysisDocumentRejectsTrailingAndOversizedInput(t *testing.T) {
	for _, raw := range []string{`{"version":1} {"version":1}`, strings.Repeat(" ", maxAnalysisInput+1)} {
		file := filepath.Join(t.TempDir(), "input.json")
		if err := os.WriteFile(file, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		var d inspectionDocument
		if err := readAnalysisDocument(t.Context(), file, &d); err == nil {
			t.Fatal("unbounded or trailing document accepted")
		}
	}
	var out bytes.Buffer
	if err := analysisOutput(&out, strings.Repeat("x", maxAnalysisOutput+1)); err == nil || out.Len() != 0 {
		t.Fatal("oversized output partially emitted", err, out.Len())
	}
}

func TestOfflineRiskCompoundDocumentPreservesFalseOR(t *testing.T) {
	traffic, err := requestTraffic("192.0.2.1/32", "198.51.100.1/32", "tcp/443")
	if err != nil {
		t.Fatal(err)
	}
	raw := `{"version":1,"contexts":[],"definitions":[{"id":"compound","version":"1","mode":1,"expression":{"any":[{"predicate":{"dimension":2,"relation":1,"addresses":[{"First":"203.0.113.1","Last":"203.0.113.1"}]}}]}}]}`
	var d riskDocument
	if err := json.Unmarshal([]byte(raw), &d); err != nil {
		t.Fatal(err)
	}
	d.Contexts = []analysisContextDocument{{Traffic: traffic.Regions()}}
	contexts, definitions, err := d.request(policy.Limits{}.WithDefaults())
	if err != nil {
		t.Fatal(err)
	}
	fw, err := fm.Seal(fm.Data{Metadata: fm.Metadata{Device: "fw", Vendor: "hillstone"}, Rules: []fm.RuleRecord{{Object: fm.Object{ID: "one"}, RuleSet: "security", Action: fm.Permit, Match: fm.Match{AnySource: true, AnyDestination: true, AnyService: true, AnyFromZone: true, AnyToZone: true}}}})
	if err != nil {
		t.Fatal(err)
	}
	rows, err := (analysis.RiskAnalyzer{}).AnalyzeBatch(context.Background(), fw, contexts, definitions)
	if err != nil || len(rows) != 1 || len(rows[0].Findings) != 1 || rows[0].Findings[0].Value != analysis.False {
		t.Fatal(rows, err)
	}
}

func TestOfflineLifecycleCommandsAndUsage(t *testing.T) {
	root := t.TempDir()
	store, err := snapshot.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	raw := "zone inside\nexit\nzone outside\nexit\naddress src\nip 192.0.2.1/32\nexit\naddress dst\nip 198.51.100.1/32\nexit\nservice web\ntcp dst-port 443\nexit\npolicy from inside to outside\nrule id 1\nsrc-addr src\ndst-addr dst\nservice web\naction permit\ndisable\nexit\nexit\n"
	fw, err := (vendors.Parser{}).Parse(t.Context(), config.Source{Text: raw, Complete: true}, fm.Metadata{Device: "fw", Vendor: "hillstone"})
	if err != nil || !fw.Complete() {
		t.Fatal(fw, err)
	}
	rev, err := store.Archive(t.Context(), fw)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(root, "lifecycle.json")
	if err = os.WriteFile(file, []byte(`{"version":1,"request":{},"rules":["1"]}`), 0600); err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{"reclamation-report", "reclamation-plan"} {
		var out bytes.Buffer
		if err = run([]string{command, "--store", root, "--revision", rev, "--file", file}, &out); err != nil {
			t.Fatal(command, err)
		}
		if !strings.Contains(out.String(), rev) || command == "reclamation-plan" && !strings.Contains(out.String(), "no rule id 1") {
			t.Fatal(out.String())
		}
	}
	// An enabled zero-hit rule is never selected for removal merely from usage.
	enabled := strings.Replace(raw, "disable\n", "", 1)
	fw, err = (vendors.Parser{}).Parse(t.Context(), config.Source{Text: enabled, Complete: true}, fm.Metadata{Device: "fw", Vendor: "hillstone"})
	if err != nil {
		t.Fatal(err)
	}
	live, err := store.Archive(t.Context(), fw)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err = run([]string{"reclamation-plan", "--store", root, "--revision", live, "--file", file}, &out); err == nil || out.Len() != 0 {
		t.Fatal("unproven removal emitted", err, out.String())
	}
	if err = os.WriteFile(file, []byte(`{"version":1,"target_revision":"`+rev+`","zones":[{"from":"inside","to":"inside"},{"from":"outside","to":"outside"}],"pairs":[{"From":"inside","To":"outside"}],"rules":["1"]}`), 0600); err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{"migration-report", "migration-plan"} {
		out.Reset()
		if err = run([]string{command, "--store", root, "--revision", live, "--file", file}, &out); err != nil {
			t.Fatal(command, err)
		}
		if !strings.Contains(out.String(), "digest") {
			t.Fatal(out.String())
		}
	}
}

func TestUsageCLIReadsExplicitRevisionAndPairedLog(t *testing.T) {
	root := t.TempDir()
	store, err := snapshot.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	native, err := os.ReadFile("../../vendors/testdata/perl/srx.cfg")
	if err != nil {
		t.Fatal(err)
	}
	fw, err := (vendors.Parser{}).Parse(t.Context(), config.Source{Text: string(native), Complete: true}, fm.Metadata{Device: "fw", Vendor: "srx"})
	if err != nil {
		t.Fatal(err)
	}
	rev, err := store.Archive(t.Context(), fw)
	if err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(root, "session.log")
	if err = os.WriteFile(log, []byte("2026-11-01T01:00:00Z fw RT_FLOW: session created 192.0.2.10/12345->192.0.2.10/443 a b c d 6 allow inside inside\n"), 0600); err != nil {
		t.Fatal(err)
	}
	doc := map[string]any{"version": 1, "file": log, "revision": rev, "graph_digest": fw.SemanticDigest(), "source": "synthetic", "window": map[string]string{"Start": "2026-11-01T00:00:00Z", "End": "2026-11-01T02:00:00Z"}}
	data, _ := json.Marshal(doc)
	file := filepath.Join(root, "usage.json")
	if err = os.WriteFile(file, data, 0600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err = run([]string{"usage-report", "--store", root, "--revision", rev, "--file", file}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"Tuples": [`) || !strings.Contains(out.String(), `"Hits": 1`) {
		t.Fatal(out.String())
	}
}
