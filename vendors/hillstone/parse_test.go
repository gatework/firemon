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
	if r, _ := fw.Rule("3"); r.Spec().Group != "10" || fw.Config().RuleGroups[0] != (firemon.RuleGroup{ID: "10", Name: "ops"}) {
		t.Errorf("aggregate group: got %q, groups %v", r.Spec().Group, fw.Config().RuleGroups)
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
	if len(fw.NATRulesFor(firemon.NATKindSource)) != 2 || len(fw.NATRulesFor(firemon.NATKindDestination)) != 1 || len(fw.StaticNATs()) != 1 {
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

// TestParse_GoldenRoundTrip checks that the stored JSON form compiles to
// the same firewall as the parsed configuration, so snapshots never need
// re-parsing.
func TestParse_GoldenRoundTrip(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(filepath.Join("testdata", "basic.golden.json"))
	if err != nil {
		t.Fatal(err)
	}
	var stored firemon.Config
	if err := json.Unmarshal(raw, &stored); err != nil {
		t.Fatal(err)
	}
	want, err := firemon.Compile(parseFixture(t, "basic.conf"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := firemon.Compile(&stored)
	if err != nil {
		t.Fatal(err)
	}
	if got.Fingerprint() != want.Fingerprint() {
		t.Fatal("stored configuration compiles differently")
	}
}

func TestParse_ServiceBookOverride(t *testing.T) {
	t.Parallel()
	text := "rule id 1\n  action permit\n  src-addr \"Any\"\n  dst-addr \"Any\"\n  service \"HTTP-EXT\"\n  service \"HTTP\"\nexit\n"
	fw, err := firemon.Compile(mustParse(t, hillstone.Options{}, text))
	if err != nil {
		t.Fatal(err)
	}
	if r, _ := fw.Rule("1"); r.Decidable() {
		t.Fatal("HTTP-EXT is not in the default book; the rule must be undecidable")
	}
	book, err := firemon.ParseServiceBook([]byte(`{"HTTP-EXT":["tcp/8080"],"HTTP":["tcp/80","tcp/8000"]}`))
	if err != nil {
		t.Fatal(err)
	}
	fw, err = firemon.Compile(mustParse(t, hillstone.Options{Services: book}, text))
	if err != nil {
		t.Fatal(err)
	}
	r, _ := fw.Rule("1")
	if !r.Decidable() || r.Match().Service.String() != "tcp/80,tcp/8000,tcp/8080" {
		t.Fatalf("with device book: %s %v", r.Match().Service, r.Issues())
	}
	if got, _ := fw.Service("SSH"); got.String() != "tcp/22" {
		t.Fatalf("defaults kept for other names: %s", got)
	}
}

func TestParse_DeclaredServiceWinsOverBook(t *testing.T) {
	t.Parallel()
	text := "service \"HTTP\"\n  tcp dst-port 8888\nexit\n"
	fw, err := firemon.Compile(mustParse(t, hillstone.Options{}, text))
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := fw.Service("HTTP"); got.String() != "tcp/8888" {
		t.Fatalf("declared HTTP: %s", got)
	}
}

func mustParse(t *testing.T, opts hillstone.Options, text string) *firemon.Config {
	t.Helper()
	cfg, err := hillstone.New(opts).Parse(text)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}
