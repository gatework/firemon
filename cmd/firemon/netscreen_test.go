package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOfflineScreenOSImportNATAndPlanLoadOnlyPersistedGraph(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "screenos.set")
	raw, err := os.ReadFile("../../vendors/netscreen/testdata/nat.set")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(input, raw, 0600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err = run([]string{"import", "--store", dir, "--device", "ns", "--vendor", "netscreen", "--file", input, "--complete", "--publication", "one"}, &out); err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(input); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err = run([]string{"nat", "--store", dir, "--device", "ns", "--source", "192.0.2.60/32", "--destination", "203.0.113.5/32", "--service", "tcp/443", "--from-zone", "Trust", "--to-zone", "Untrust"}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"Reverse": true`) || !strings.Contains(out.String(), `"198.51.100.60"`) {
		t.Fatal(out.String())
	}
	out.Reset()
	if err = run([]string{"plan", "--store", dir, "--device", "ns", "--source", "203.0.113.5/32", "--destination", "192.0.2.30/32", "--service", "tcp/443", "--from-zone", "Untrust", "--to-zone", "Trust"}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "set policy id") || !strings.Contains(out.String(), `"TargetAllowed": true`) {
		t.Fatal(out.String())
	}
}
