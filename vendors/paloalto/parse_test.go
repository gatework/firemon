package paloalto_test

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/vendors/paloalto"
)

var update = flag.Bool("update", false, "rewrite golden files")

func parseFixture(t *testing.T) *firemon.Config {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "basic.conf"))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := paloalto.New(paloalto.Options{Location: time.UTC}).Parse(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestParse_Golden(t *testing.T) {
	t.Parallel()
	got, err := json.MarshalIndent(parseFixture(t), "", "  ")
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
	cfg := parseFixture(t)
	fw, err := firemon.Compile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		id, match string
		decidable bool
	}{
		{"block-bad", "192.0.2.0/24 -> any any", true},
		{"web-in", "any -> 198.51.100.80 tcp/80,tcp/443,tcp/8080", true},
		{"Allow updates", "10.0.0.0/16 -> none tcp/443", false},
		{"apps", "10.0.0.0/16 -> any any", false},
		{"not-lan", "0.0.0.0-9.255.255.255,10.1.0.0-255.255.255.255,::/0 -> any udp/53", true},
	}
	for _, tt := range tests {
		r, ok := fw.Rule(tt.id)
		if !ok {
			t.Fatalf("rule %q missing", tt.id)
		}
		if got := r.Match().String(); got != tt.match || r.Decidable() != tt.decidable {
			t.Errorf("rule %q: got %q decidable=%v %v", tt.id, got, r.Decidable(), r.Issues())
		}
	}
	if got := fw.Semantics().IntrazoneAction; got != firemon.ActionDeny {
		t.Errorf("intrazone default: %s", got)
	}
	if i, _ := fw.Interface("ethernet1/1"); len(i.Addresses) != 1 || i.Zone != "untrust" || i.VirtualRouter != "default" {
		t.Errorf("interface bound by object name: %+v", i)
	}
	if len(fw.StaticNATs()) != 1 || len(fw.NATRules(firemon.NATKindDestination)) != 1 || len(fw.NATRules(firemon.NATKindSource)) != 1 {
		t.Error("NAT rules missing")
	}
	if len(cfg.Diagnostics) != 1 {
		t.Errorf("diagnostics: %+v", cfg.Diagnostics)
	}
}

func FuzzParse(f *testing.F) {
	raw, err := os.ReadFile(filepath.Join("testdata", "basic.conf"))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(string(raw))
	f.Add("set rulebase nat rules x source-translation static-ip bi-directional yes\n")
	f.Fuzz(func(t *testing.T, text string) {
		cfg, err := paloalto.New(paloalto.Options{}).Parse(text)
		if err != nil {
			return
		}
		if _, err := firemon.Compile(cfg); err != nil {
			t.Fatal(err)
		}
	})
}
