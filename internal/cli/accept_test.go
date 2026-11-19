package cli_test

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/gatework/firemon/internal/cli"
)

// TestAccept_Matrix is the CLI acceptance matrix from the functional test
// of round 9: every case fixes the exit code, a line the operator must
// see and, where it matters, a line that must not appear. Fixtures only;
// the same commands were run on the private corpus.
func TestAccept_Matrix(t *testing.T) {
	t.Parallel()
	hs := []string{"--config", hillstoneConf}
	cases := []struct {
		name  string
		args  []string
		code  int
		want  string
		never string
	}{
		// Verdicts and the exit code contract.
		{"full match", []string{"search", "--src", "203.0.113.9", "--dst", "172.16.0.10", "--service", "tcp/80"}, cli.ExitOK, "结论：完全命中", ""},
		{"deny needs a rule before it", []string{"search", "--src", "203.0.113.9", "--dst", "10.0.0.5", "--service", "tcp/80"}, cli.ExitNotAllowed, "会绕过它", ""},
		{"range source, default deny", []string{"search", "--src", "10.0.0.5-10.0.0.9", "--dst", "8.8.8.8", "--service", "tcp/80"}, cli.ExitNotAllowed, "默认拒绝", ""},
		{"undecided without design", []string{"search", "--src", "10.0.0.5", "--dst", "8.8.8.8", "--service", "tcp/443", "--no-design"}, cli.ExitUndecided, "需确认", ""},
		{"undecided settled by a plan", []string{"search", "--src", "10.0.0.5", "--dst", "8.8.8.8", "--service", "tcp/443"}, cli.ExitNotAllowed, "由已验证的方案确保放通", "结论：需确认"},
		{"time-bound hit", []string{"search", "--src", "10.0.0.5", "--dst", "8.8.8.8", "--service", "tcp/22", "--at", "2026-11-20T10:00:00+08:00", "--timezone", "Asia/Shanghai"}, cli.ExitOK, "限时策略", ""},
		{"NAT translates to the packet family", []string{"search", "--src", "10.0.0.5", "--dst", "8.8.8.8", "--service", "tcp/443"}, cli.ExitNotAllowed, "源 NAT 1", "2001:db8:1::2"},
		// Input that is not answered rather than answered in part.
		{"unknown application", []string{"search", "--src", "10.0.0.5", "--dst", "172.16.0.10", "--service", "app:nosuch"}, cli.ExitUsage, "未知应用", ""},
		{"port zero", []string{"search", "--src", "10.0.0.5", "--dst", "172.16.0.10", "--service", "tcp/0"}, cli.ExitUsage, "无法识别", "已忽略"},
		{"unreadable source", []string{"search", "--src", "bogus", "--dst", "172.16.0.10", "--service", "tcp/443"}, cli.ExitUsage, "无法识别", "已忽略"},
		{"IPv4 to IPv6", []string{"search", "--src", "10.0.0.5", "--dst", "2001:db8::1", "--service", "tcp/443"}, cli.ExitUsage, "", ""},
		// NAT both ways.
		{"published server", []string{"nat", "--ip", "172.16.0.10"}, cli.ExitOK, "公网 198.51.100.80 tcp/80 ⇒ 内部 172.16.0.10 tcp/8080", "tcp/0"},
		{"public address", []string{"nat", "--ip", "198.51.100.80"}, cli.ExitOK, "入站目的转换", ""},
		{"static mapping", []string{"nat", "--ip", "198.51.100.10"}, cli.ExitOK, "内部 172.16.0.11", ""},
		// Usage.
		{"usage relations in Chinese", []string{"usage", "--addr", "172.16.0.10"}, cli.ExitOK, "包含所查地址", "superset"},
		// Library reasons, in Chinese.
		{"parse", []string{"parse"}, cli.ExitOK, "按应用匹配", ""},
		{"audit", []string{"audit"}, cli.ExitOK, "", ""},
		{"converge", []string{"converge"}, cli.ExitOK, "", ""},
		// Errors that say what is missing.
		{"migrate without target", []string{"migrate"}, cli.ExitUsage, "", ""},
	}
	english := regexp.MustCompile(`\b[a-z]{2,} [a-z]{2,} [a-z]{2,}\b`) // a phrase left untranslated
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			code, out, errOut := run(t, "", append(c.args, hs...)...)
			all := out + errOut
			if code != c.code {
				t.Fatalf("exit %d, want %d\n%s", code, c.code, all)
			}
			if c.want != "" && !strings.Contains(all, c.want) {
				t.Fatalf("missing %q\n%s", c.want, all)
			}
			if c.never != "" && strings.Contains(all, c.never) {
				t.Fatalf("unexpected %q\n%s", c.never, all)
			}
			for line := range strings.SplitSeq(all, "\n") {
				if isCommand(line) {
					continue
				}
				if m := english.FindString(line); m != "" {
					t.Errorf("English left in %q", line)
				}
			}
		})
	}
}

// isCommand reports a device command line, which stays in the vendor's
// language.
func isCommand(line string) bool {
	trimmed := strings.TrimSpace(line)
	for _, p := range []string{"address ", "rule id", "action ", "src-", "dst-", "service ", "name ", "description ", "log ", "exit", "no ", "ip ", "set ", "delete "} {
		if strings.HasPrefix(trimmed, p) {
			return true
		}
	}
	return false
}

// TestAccept_JSONAgreesWithExit: the JSON status says what the exit code
// says, and lists are never null.
func TestAccept_JSONAgreesWithExit(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		args   []string
		code   int
		status string
	}{
		{[]string{"--src", "203.0.113.9", "--dst", "172.16.0.10", "--service", "tcp/80"}, cli.ExitOK, "full-match"},
		{[]string{"--src", "10.0.0.5", "--dst", "8.8.8.8", "--service", "tcp/443", "--no-design"}, cli.ExitUndecided, "indeterminate"},
	} {
		code, out, errOut := run(t, "", append([]string{"search", "--json", "--config", hillstoneConf}, c.args...)...)
		var rep struct {
			Status    string            `json:"status"`
			Firewalls []json.RawMessage `json:"firewalls"`
		}
		if err := json.Unmarshal([]byte(out), &rep); err != nil {
			t.Fatalf("%v: %v\n%s%s", c.args, err, out, errOut)
		}
		if code != c.code || rep.Status != c.status || rep.Firewalls == nil {
			t.Fatalf("%v: exit %d status %q firewalls %v, want %d %q", c.args, code, rep.Status, rep.Firewalls, c.code, c.status)
		}
	}
}

// TestAccept_DeviceTimezone: with no time zone chosen, a PAN-OS
// configuration is read in the zone it sets for the device; a chosen one
// still wins.
func TestAccept_DeviceTimezone(t *testing.T) {
	t.Parallel()
	path := t.TempDir() + "/pa.conf"
	if err := os.WriteFile(path, []byte("set deviceconfig system hostname pa\nset deviceconfig system timezone Asia/Tokyo\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	zone := func(args ...string) string {
		_, out, errOut := run(t, "", append([]string{"parse", "--dump", "--config", path}, args...)...)
		var cfg struct {
			TimeZone string `json:"time_zone"`
		}
		if err := json.Unmarshal([]byte(out), &cfg); err != nil {
			t.Fatalf("%v\n%s%s", err, out, errOut)
		}
		return cfg.TimeZone
	}
	if got := zone(); got != "Asia/Tokyo" {
		t.Errorf("device zone %q, want Asia/Tokyo", got)
	}
	if got := zone("--timezone", "UTC"); got != "UTC" {
		t.Errorf("chosen zone %q, want UTC", got)
	}
}
