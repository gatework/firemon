package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOfflineFortinetImportRetainsVDOMAndPlansWithoutSource(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "fortios.conf")
	raw, err := os.ReadFile("../../vendors/fortinet/testdata/basic.conf")
	if err != nil {
		t.Fatal(err)
	}
	text := strings.ReplaceAll(string(raw), `set vdom "root"`, `set vdom "tenant"`)
	if err := os.WriteFile(input, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := run([]string{"import", "--store", dir, "--device", "fgt", "--vendor", "fortinet", "--vdom", "tenant", "--file", input, "--complete", "--publication", "one"}, &out); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(input); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := run([]string{"inspect", "--store", dir, "--device", "fgt"}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"context": "tenant"`) {
		t.Fatal(out.String())
	}
	out.Reset()
	if err := run([]string{"plan", "--store", dir, "--device", "fgt", "--source", "192.0.2.11/32", "--destination", "203.0.113.30/32", "--service", "tcp/443", "--from-zone", "inside", "--to-zone", "wan1"}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "move 1 before 10") || !strings.Contains(out.String(), `"TargetAllowed": true`) || !strings.Contains(out.String(), `"context": "tenant"`) {
		t.Fatal(out.String())
	}
}

func TestOfflineFortinetVIPQueryLoadsPersistedNATObjects(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "fortios.conf")
	raw, err := os.ReadFile("../../vendors/fortinet/testdata/basic.conf")
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw) + `config firewall vip
edit "public"
set extintf "wan1"
set extip 198.51.100.20
set mappedip "192.0.2.20"
next
end
config firewall policy
edit 20
set srcintf "wan1"
set dstintf "inside"
set srcaddr "all"
set dstaddr "public"
set action accept
set schedule "always"
set service "ALL"
next
end
`
	if err := os.WriteFile(input, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := run([]string{"import", "--store", dir, "--device", "fgt", "--vendor", "fortinet", "--file", input, "--complete", "--publication", "one"}, &out); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(input); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := run([]string{"nat", "--store", dir, "--device", "fgt", "--source", "203.0.113.50/32", "--destination", "198.51.100.20/32", "--service", "tcp/443", "--from-zone", "wan1", "--to-zone", "inside"}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"Complete": true`) || !strings.Contains(out.String(), `"192.0.2.20"`) || !strings.Contains(out.String(), `"vip:public"`) {
		t.Fatal(out.String())
	}
}
