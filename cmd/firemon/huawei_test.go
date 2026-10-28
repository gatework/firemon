package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOfflineHuaweiUsesSnapshotForQueryNATAndPlan(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "huawei.conf")
	raw := `interface GigabitEthernet1/0/1
 ip address 192.0.2.1 24
#
interface GigabitEthernet1/0/2
 ip address 198.51.100.1 24
#
firewall zone trust
 add interface GigabitEthernet1/0/1
#
firewall zone untrust
 add interface GigabitEthernet1/0/2
#
nat server fixed zone untrust global 198.51.100.50 inside 192.0.2.50
security-policy
 default action deny
#
`
	if err := os.WriteFile(input, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := run([]string{"import", "--store", dir, "--device", "usg", "--vendor", "huawei", "--software", "V500R005", "--file", input, "--complete", "--publication", "one"}, &out); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(input); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct{ command, source, destination, from, to, want string }{
		{"query", "192.0.2.10/32", "203.0.113.10/32", "trust", "untrust", `"complete": true`},
		{"nat", "203.0.113.10/32", "198.51.100.50/32", "untrust", "trust", `"192.0.2.50"`},
		{"plan", "192.0.2.10/32", "203.0.113.10/32", "trust", "untrust", `"TargetAllowed": true`},
	} {
		out.Reset()
		if err := run([]string{tt.command, "--store", dir, "--device", "usg", "--source", tt.source, "--destination", tt.destination, "--service", "tcp/443", "--from-zone", tt.from, "--to-zone", tt.to}, &out); err != nil {
			t.Fatal(tt.command, err)
		}
		if !strings.Contains(out.String(), tt.want) {
			t.Fatal(out.String())
		}
	}
}
