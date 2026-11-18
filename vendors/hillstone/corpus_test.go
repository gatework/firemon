package hillstone_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/vendors/hillstone"
)

// TestCorpus parses every StoneOS configuration in the private directory
// named by FIREMON_CORPUS and prints aggregate counts only (TST-3).
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
		if !strings.Contains(text[:min(len(text), 4096)], "\nVersion 5.") {
			continue
		}
		parsed++
		t.Run(filepath.Base(path), func(t *testing.T) {
			t.Parallel()
			cfg, err := hillstone.New(hillstone.Options{}).Parse(text)
			if err != nil {
				t.Fatal(err)
			}
			if want := strings.Count(text, "\nrule id ") - strings.Count(text, "aggregate-type"); len(cfg.Rules) != want {
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
			reasons := map[string]int{}
			for _, d := range cfg.Diagnostics {
				reasons[d.Reason]++
			}
			t.Logf("rules=%d undecidable=%d addresses=%d groups=%d services=%d routes=%d snat=%d diagnostics=%v issues=%d",
				len(cfg.Rules), undecidable, len(cfg.Addresses), len(cfg.AddressGroups), len(cfg.Services), len(cfg.Routes),
				len(cfg.DynamicNATs), reasons, len(fw.Issues()))
		})
	}
	if parsed == 0 {
		t.Skip("no StoneOS configuration in corpus")
	}
}
