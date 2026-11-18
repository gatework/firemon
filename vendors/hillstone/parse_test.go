package hillstone_test

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/vendors/hillstone"
)

var update = flag.Bool("update", false, "rewrite golden files")

func parseFixture(t *testing.T, name string) *firemon.Config {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := hillstone.New(hillstone.Options{Location: time.UTC}).Parse(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestParse_Golden(t *testing.T) {
	t.Parallel()
	cfg := parseFixture(t, "basic.conf")
	got, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	golden := filepath.Join("testdata", "basic.golden.json")
	if *update {
		if err := os.WriteFile(golden, append(got, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(string(want), string(got)+"\n"); diff != "" {
		t.Fatalf("golden mismatch (-want +got), rerun with -update:\n%s", diff)
	}
}

func TestParse_Semantics(t *testing.T) {
	t.Parallel()
	fw, err := firemon.Compile(parseFixture(t, "basic.conf"))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		id, match string
		decidable bool
	}{
		{"3", "any -> 10.0.0.0-10.0.8.255,10.0.10.0-10.0.255.255 any", true},
		{"1", "any -> 172.16.0.10,172.16.0.20-172.16.0.29 tcp/80,tcp/443,tcp/8080", true},
		{"7", "10.0.1.0/24,10.0.2.5-10.0.2.9 -> none tcp/443", false},
		{"8", "10.0.0.0-10.0.8.255,10.0.10.0-10.0.255.255 -> any tcp/22", true},
		{"9", "10.0.0.0-10.0.8.255,10.0.10.0-10.0.255.255 -> any any", false},
	}
	for _, tt := range tests {
		r, ok := fw.Rule(tt.id)
		if !ok {
			t.Fatalf("rule %s missing", tt.id)
		}
		if got := r.Match().String(); got != tt.match || r.Decidable() != tt.decidable {
			t.Errorf("rule %s: got %q decidable=%v %v", tt.id, got, r.Decidable(), r.Issues())
		}
	}
	if r, _ := fw.Rule("3"); r.Spec().Group != "ops" {
		t.Errorf("aggregate group: got %q", r.Spec().Group)
	}
	if got := len(fw.Rules()); got != 5 {
		t.Errorf("rules: got %d, want 5 (aggregate header excluded)", got)
	}
	if r, _ := fw.Rule("8"); !r.ActiveAt(time.Date(2026, 11, 17, 10, 0, 0, 0, time.UTC)) || r.ActiveAt(time.Date(2026, 11, 17, 20, 0, 0, 0, time.UTC)) {
		t.Error("rule 8 schedule not honoured")
	}
	if z, _ := fw.Zone("l2-trust"); z.Mode != firemon.ZoneModeLayer2 {
		t.Errorf("l2 zone mode: %s", z.Mode)
	}
	if len(fw.NATRules(firemon.NATKindSource)) != 2 || len(fw.NATRules(firemon.NATKindDestination)) != 1 || len(fw.StaticNATs()) != 1 {
		t.Error("NAT rules missing")
	}
}

func FuzzParse(f *testing.F) {
	raw, err := os.ReadFile(filepath.Join("testdata", "basic.conf"))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(string(raw))
	f.Add("rule id 1\n  src-ip \"\nexit\n")
	f.Fuzz(func(t *testing.T, text string) {
		cfg, err := hillstone.New(hillstone.Options{}).Parse(text)
		if err != nil {
			return
		}
		if _, err := firemon.Compile(cfg); err != nil {
			t.Fatal(err)
		}
	})
}
