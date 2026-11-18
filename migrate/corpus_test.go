package migrate_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/migrate"
)

// TestCorpus translates every configuration under FIREMON_CORPUS to the
// other vendor, renders it, reads it back, and checks every rule reported
// exact against its source rule.
func TestCorpus(t *testing.T) {
	dir := os.Getenv("FIREMON_CORPUS")
	if dir == "" {
		t.Skip("FIREMON_CORPUS not set")
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*.txt"))
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		text := string(raw)
		from, to := firemon.VendorHillstone, firemon.VendorPaloAlto
		switch {
		case strings.Contains(text, "set rulebase security"):
			from, to = firemon.VendorPaloAlto, firemon.VendorHillstone
		case !strings.Contains(text, "Version 5.5"):
			continue
		}
		t.Run(filepath.Base(f), func(t *testing.T) {
			res, src, back := translate(t, from, to, text, migrate.Mapping{})
			exact := 0
			for _, it := range res.Items {
				if it.Kind == migrate.ItemKindRule && it.Fidelity == migrate.FidelityExact && len(it.Target) > 0 {
					sameMatch(t, src, back, it)
					exact++
				}
			}
			t.Logf("%d exact rules verified; items exact %d, approximate %d, untranslatable %d",
				exact, res.Count(migrate.FidelityExact), res.Count(migrate.FidelityApproximate), res.Count(migrate.FidelityUntranslatable))
		})
	}
}
