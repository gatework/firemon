package paloalto_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/vendors/paloalto"
)

// TestCorpus parses every PAN-OS set-format configuration in the private
// directory named by FIREMON_CORPUS and prints aggregate counts only (TST-3).
func TestCorpus(t *testing.T) {
	t.Parallel()
	dir := os.Getenv("FIREMON_CORPUS")
	if dir == "" {
		t.Skip("FIREMON_CORPUS not set")
	}
	paths, err := filepath.Glob(filepath.Join(dir, "*.txt"))
	if err != nil {
		t.Fatal(err)
	}
	parsed := 0
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		text := string(raw)
		if !strings.Contains(text, "\nset rulebase security rules ") {
			continue
		}
		parsed++
		t.Run(filepath.Base(path), func(t *testing.T) {
			t.Parallel()
			cfg, err := paloalto.New(paloalto.Options{}).Parse(text)
			if err != nil {
				t.Fatal(err)
			}
			if want := distinctRules(text); len(cfg.Rules) != want {
				t.Errorf("rules: got %d, want %d", len(cfg.Rules), want)
			}
			fw, err := firemon.Compile(cfg)
			if err != nil {
				t.Fatal(err)
			}
			undecidable := 0
			for _, r := range fw.Rules() {
				if !r.Decidable() {
					undecidable++
				}
			}
			t.Logf("rules=%d undecidable=%d addresses=%d groups=%d services=%d routes=%d interfaces=%d nat=%d static=%d diagnostics=%d issues=%d",
				len(cfg.Rules), undecidable, len(cfg.Addresses), len(cfg.AddressGroups), len(cfg.Services), len(cfg.Routes),
				len(cfg.Interfaces), len(cfg.DynamicNATs), len(cfg.StaticNATs), len(cfg.Diagnostics), len(fw.Issues()))
		})
	}
	if parsed == 0 {
		t.Skip("no PAN-OS configuration in corpus")
	}
}

// distinctRules counts security rule names independently of the parser.
func distinctRules(text string) int {
	seen := map[string]bool{}
	for line := range strings.Lines(text) {
		rest, ok := strings.CutPrefix(line, "set rulebase security rules ")
		if !ok {
			continue
		}
		name := strings.Fields(rest)[0]
		if strings.HasPrefix(rest, `"`) {
			name, _, _ = strings.Cut(rest[1:], `"`)
		}
		seen[name] = true
	}
	return len(seen)
}
