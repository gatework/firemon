package policy_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/policy"
	"github.com/gatework/firemon/vendors"
)

// Change-safety proofs treat a Complete result as fully established. Every
// vendor's query must therefore clear Complete whenever any traffic is Unknown,
// including graphs with unsupported rules or unparsed top-level evidence.
func TestCompleteResultsNeverCarryUnknownTraffic(t *testing.T) {
	var fixtures []string
	for _, pattern := range []string{"../vendors/*/testdata/*", "../vendors/testdata/*/*"} {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatal(err)
		}
		fixtures = append(fixtures, matches...)
	}
	names := []string{"paloalto", "srx", "huawei", "hillstone", "fortinet", "netscreen", "asa"}
	engine := policy.Engine{}
	all, err := flow.AllTraffic(engine.Limits.WithDefaults().MaxRegions)
	if err != nil {
		t.Fatal(err)
	}
	var complete, unknown int
	for _, path := range fixtures {
		switch filepath.Ext(path) {
		case ".cfg", ".conf", ".set":
		default:
			continue
		}
		vendor := ""
		for _, name := range names {
			if strings.Contains(path, name) {
				vendor = name
			}
		}
		if vendor == "" {
			continue
		}
		text, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		metadata := fm.Metadata{Device: "synthetic", Vendor: vendor, Software: "7.4.0"}
		fw, err := (vendors.Parser{}).Parse(t.Context(), config.Source{Text: string(text), Complete: true}, metadata)
		if err != nil || !fw.Complete() || fw.RuleCount() == 0 {
			continue
		}
		requests, err := engine.Contexts(t.Context(), time.Time{}, fw)
		if err != nil {
			t.Fatalf("%s: contexts: %v", path, err)
		}
		requests = requests[:min(len(requests), 32)]
		for name, variant := range resultContractVariants(t, fw) {
			for _, request := range requests {
				request.Traffic = all
				result, err := engine.Query(t.Context(), variant, request)
				if err != nil {
					t.Fatalf("%s %s: query: %v", path, name, err)
				}
				if result.Complete && !result.Unknown.Empty() {
					t.Fatalf("%s %s: complete result carries unknown traffic in %s/%s %s->%s",
						path, name, request.Scope, request.RuleSet, request.FromZone, request.ToZone)
				}
				if result.Complete {
					complete++
				}
				if !result.Unknown.Empty() {
					unknown++
				}
			}
		}
	}
	if complete == 0 || unknown == 0 {
		t.Fatalf("vacuous contract: %d complete and %d unknown results", complete, unknown)
	}
	t.Logf("%d complete and %d unknown results", complete, unknown)
}

// resultContractVariants keeps the parsed graph and adds incomplete forms that
// reach the per-rule and whole-graph unknown paths.
func resultContractVariants(t *testing.T, fw *fm.Firewall) map[string]*fm.Firewall {
	t.Helper()
	unsupported := fw.Export()
	for i := range unsupported.Rules {
		unsupported.Rules[i].Unsupported = []string{"synthetic unsupported rule"}
	}
	unparsed := fw.Export()
	unparsed.Diagnostics = append(unparsed.Diagnostics, fm.Diagnostic{Code: "unparsed", Message: "synthetic unparsed line"})
	variants := map[string]*fm.Firewall{"parsed": fw}
	for name, data := range map[string]fm.Data{"unsupported-rules": unsupported, "unparsed-top-level": unparsed} {
		sealed, err := fm.Seal(data)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		variants[name] = sealed
	}
	return variants
}
