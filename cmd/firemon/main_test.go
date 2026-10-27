package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOfflineImportInspectAndQuerySurviveRemovalOfRawFile(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "input.cfg")
	store := filepath.Join(dir, "store")
	raw := "policy-global\nrule id 1\nsrc-addr any\ndst-addr any\nservice any\naction permit\nexit\nexit\n"
	if err := os.WriteFile(input, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := run([]string{"import", "--store", store, "--device", "fw", "--vendor", "hillstone", "--file", input, "--complete", "--publication", "one"}, &output); err != nil {
		t.Fatal(err, output.String())
	}
	if err := os.Remove(input); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	if err := run([]string{"inspect", "--store", store, "--device", "fw"}, &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "static_nats") || !strings.Contains(output.String(), "dynamic_nats") {
		t.Fatal("typed NAT catalogs absent", output.String())
	}
	output.Reset()
	if err := run([]string{"query", "--store", store, "--device", "fw", "--source", "192.0.2.0/24", "--destination", "198.51.100.1/32", "--service", "tcp/443"}, &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"complete": true`) || !strings.Contains(output.String(), `"allowed"`) {
		t.Fatal(output.String())
	}
}

func TestOfflinePANPlanUsesNativeRenderer(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "pan.cfg")
	if err := os.WriteFile(input, []byte("set zone inside network layer3 ethernet1/1\nset zone outside network layer3 ethernet1/2\nset network interface ethernet ethernet1/1 layer3 ip 192.0.2.1/24\nset network interface ethernet ethernet1/2 layer3 ip 198.51.100.1/24\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := run([]string{"import", "--store", dir, "--device", "pan", "--vendor", "paloalto", "--file", input, "--complete", "--publication", "one"}, &out); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := run([]string{"plan", "--store", dir, "--device", "pan", "--source", "192.0.2.10/32", "--destination", "198.51.100.10/32", "--service", "tcp/443", "--from-zone", "inside", "--to-zone", "outside"}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "set rulebase security rules") || !strings.Contains(out.String(), `"TargetAllowed": true`) {
		t.Fatal(out.String())
	}
}

func TestOfflineSRXImportNATAndPlanningUsePersistedGraph(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "srx.set")
	raw, err := os.ReadFile("../../vendors/srx/testdata/nat.set")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(input, raw, 0600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := run([]string{"import", "--store", dir, "--device", "srx", "--vendor", "srx", "--file", input, "--complete", "--publication", "one"}, &out); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(input); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := run([]string{"nat", "--store", dir, "--device", "srx", "--source", "192.0.2.130/32", "--destination", "198.51.100.50/32", "--service", "tcp/443", "--from-zone", "inside", "--to-zone", "outside"}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"Reverse": true`) || !strings.Contains(out.String(), `"198.51.100.130"`) {
		t.Fatal(out.String())
	}
	out.Reset()
	if err := run([]string{"plan", "--store", dir, "--device", "srx", "--source", "192.0.2.10/32", "--destination", "198.51.100.10/32", "--service", "tcp/443", "--from-zone", "inside", "--to-zone", "outside"}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "set security policies") || !strings.Contains(out.String(), `"TargetAllowed": true`) {
		t.Fatal(out.String())
	}
}
