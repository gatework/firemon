package cli_test

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gatework/firemon/internal/cli"
)

const (
	hillstoneConf = "../../vendors/hillstone/testdata/basic.conf"
	paloaltoConf  = "../../vendors/paloalto/testdata/basic.conf"
)

func run(t *testing.T, stdin string, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	return runEnv(t, nil, stdin, args...)
}

// runEnv runs with an environment; the settings file is never the user's.
func runEnv(t *testing.T, env map[string]string, stdin string, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	settings := t.TempDir() + "/none.yaml"
	var out, errw bytes.Buffer
	code = cli.Run(t.Context(), args, cli.Deps{
		Stdin: strings.NewReader(stdin), Stdout: &out, Stderr: &errw,
		Getenv: func(k string) string {
			if v, ok := env[k]; ok {
				return v
			}
			if k == "FIREMON_CONFIG" {
				return settings
			}
			return ""
		},
		Now: func() time.Time { return time.Date(2026, 11, 17, 10, 0, 0, 0, time.UTC) },
	})
	return code, out.String(), errw.String()
}

func TestRun(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		args []string
		code int
		want string
	}{
		{"parse", []string{"parse", "--vendor", "hillstone", "--config", hillstoneConf}, cli.ExitOK, "rules              5"},
		{"query allowed", []string{"query", "--vendor", "hillstone", "--config", hillstoneConf, "--timezone", "UTC",
			"--src", "198.51.100.9", "--dst", "172.16.0.10", "--service", "tcp/443"}, cli.ExitOK, "verdict: allowed"},
		{"query denied", []string{"query", "--vendor", "paloalto", "--config", paloaltoConf,
			"--src", "192.0.2.7", "--dst", "198.51.100.80", "--service", "tcp/443"}, cli.ExitNotAllowed, "block-bad"},
		{"usage", []string{"usage", "--vendor", "paloalto", "--config", paloaltoConf, "--addr", "172.16.0.10"}, cli.ExitOK, "web-01"},
		{"design", []string{"design", "--vendor", "paloalto", "--config", paloaltoConf,
			"--src", "10.0.7.0/24", "--dst", "172.16.0.40", "--service", "tcp/8443", "--from-zone", "trust", "--to-zone", "dmz", "--name", "req"},
			cli.ExitOK, "set rulebase security rules req action allow"},
		{"audit", []string{"audit", "--vendor", "hillstone", "--config", hillstoneConf}, cli.ExitOK, "unused-address"},
		{"unknown vendor", []string{"parse", "--vendor", "acme", "--config", hillstoneConf}, cli.ExitUsage, ""},
		{"deploy rejects files", []string{"deploy", "--vendor", "hillstone", "--config", hillstoneConf,
			"--src", "10.0.0.1", "--dst", "10.0.0.2", "--service", "tcp/22"}, cli.ExitUsage, ""},
		{"missing traffic", []string{"query", "--vendor", "hillstone", "--config", hillstoneConf}, cli.ExitUsage, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			code, out, errOut := run(t, "", tt.args...)
			if code != tt.code || !strings.Contains(out, tt.want) {
				t.Fatalf("code %d (want %d)\nstdout:\n%s\nstderr:\n%s", code, tt.code, out, errOut)
			}
		})
	}
}

func TestRun_QueryJSON(t *testing.T) {
	t.Parallel()
	code, out, errOut := run(t, "", "query", "--json", "--vendor", "paloalto", "--config", paloaltoConf,
		"--src", "10.0.0.5", "--dst", "8.8.8.8", "--service", "udp/53")
	var res struct {
		Verdict string `json:"verdict"`
		Paths   []struct {
			From string `json:"from"`
			To   string `json:"to"`
		} `json:"paths"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("code %d: %v\n%s%s", code, err, out, errOut)
	}
	if len(res.Paths) != 1 || res.Paths[0].From != "trust" || res.Paths[0].To != "untrust" {
		t.Fatalf("paths %+v", res.Paths)
	}
}

func TestRun_CollectThenQuerySnapshot(t *testing.T) {
	t.Parallel()
	store := t.TempDir() + "/snapshots"
	code, out, errOut := run(t, "", "collect", "--vendor", "paloalto", "--config", paloaltoConf, "--store", store, "--name", "pa1")
	if code != cli.ExitOK || !strings.Contains(out, "stored pa1") {
		t.Fatalf("collect: %d\n%s%s", code, out, errOut)
	}
	code, out, errOut = run(t, "", "collect", "--list", "--store", store)
	if code != cli.ExitOK || !strings.Contains(out, "pa1") {
		t.Fatalf("list: %d\n%s%s", code, out, errOut)
	}
	code, out, errOut = run(t, "", "query", "--snapshot", "pa1", "--store", store,
		"--src", "10.0.0.5", "--dst", "8.8.8.8", "--service", "udp/53")
	if code != cli.ExitNotAllowed || !strings.Contains(out, "trust -> untrust") {
		t.Fatalf("query snapshot: %d\n%s%s", code, out, errOut)
	}
	code, _, _ = run(t, "", "deploy", "--snapshot", "pa1", "--store", store, "--src", "10.0.0.1", "--dst", "10.0.0.2", "--service", "tcp/22")
	if code != cli.ExitUsage {
		t.Fatalf("deploy from snapshot: %d", code)
	}
}

func TestRun_Locate(t *testing.T) {
	t.Parallel()
	store := t.TempDir() + "/snapshots"
	for name, args := range map[string][]string{
		"hs1": {"--vendor", "hillstone", "--config", hillstoneConf},
		"pa1": {"--vendor", "paloalto", "--config", paloaltoConf},
	} {
		if code, out, errOut := run(t, "", append([]string{"collect", "--store", store, "--name", name}, args...)...); code != cli.ExitOK {
			t.Fatalf("collect %s: %d %s%s", name, code, out, errOut)
		}
	}
	code, out, errOut := run(t, "", "locate", "--store", store, "--design", "--src", "10.0.0.5", "--dst", "172.16.0.40", "--service", "tcp/8443", "--name", "req")
	if code != cli.ExitNotAllowed || !strings.Contains(out, "plan: change, verified true") {
		t.Fatalf("locate: %d\n%s%s", code, out, errOut)
	}
}

func TestRun_ServiceBook(t *testing.T) {
	t.Parallel()
	book := t.TempDir() + "/book.json"
	if err := os.WriteFile(book, []byte(`{"HTTPS":["tcp/443","tcp/8443"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, _ := run(t, "", "services", "--vendor", "hillstone", "--service-book", book)
	if code != cli.ExitOK || !strings.Contains(out, "tcp/443,tcp/8443") || !strings.Contains(out, "SSH") {
		t.Fatalf("services: %d\n%s", code, out)
	}
	args := []string{"query", "--vendor", "hillstone", "--config", hillstoneConf, "--timezone", "UTC",
		"--src", "198.51.100.9", "--dst", "172.16.0.10", "--service", "tcp/8443"}
	if code, _, _ := run(t, "", args...); code != cli.ExitNotAllowed {
		t.Fatalf("default book: %d", code)
	}
	if code, out, _ := run(t, "", append(args, "--service-book", book)...); code != cli.ExitOK {
		t.Fatalf("device book: %d\n%s", code, out)
	}
}

func TestRun_Check(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	store := dir + "/snapshots"
	if code, out, errOut := run(t, "", "collect", "--store", store, "--name", "pa1", "--vendor", "paloalto", "--config", paloaltoConf); code != cli.ExitOK {
		t.Fatalf("collect: %d %s%s", code, out, errOut)
	}
	inv := dir + "/firemon.yaml"
	yaml := "firewalls:\n  - name: pa1\n    protected:\n      - zone: trust\n        networks: [10.0.0.0/16]\n"
	if err := os.WriteFile(inv, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errOut := run(t, "", "check", "--store", store, "--inventory", inv,
		"--src", "10.0.5.0 255.255.255.0，172.31.0.9", "--dst", "8.8.8.8", "--service", "53/udp", "--name", "REQ-7")
	if code != cli.ExitNotAllowed {
		t.Fatalf("a verified change is ready: code %d\n%s%s", code, out, errOut)
	}
	for _, want := range []string{"结论：", "■ pa1（受保护网段", "未经过任何防火墙（已剔除）：源 172.31.0.9", "地址+掩码已转换为网段", "▶ 处置：在 pa1 上执行"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q (code %d)\n%s%s", want, code, out, errOut)
		}
	}
	code, out, _ = run(t, "", "check", "--json", "--store", store, "--inventory", inv, "--src", "10.0.5.1", "--dst", "8.8.8.8", "--service", "udp 53")
	var rep struct {
		Status    string `json:"status"`
		Firewalls []struct {
			Status string `json:"status"`
		} `json:"firewalls"`
	}
	if err := json.Unmarshal([]byte(out), &rep); err != nil || len(rep.Firewalls) != 1 || rep.Status == "" {
		t.Fatalf("json report (code %d): %v\n%s", code, err, out)
	}
}

// fleet stores the PAN-OS fixture as pa1 and writes an inventory
// protecting 10.0.0.0/16 behind trust; extra is appended to the inventory.
func fleet(t *testing.T, extra string) (store, inv string) {
	t.Helper()
	dir := t.TempDir()
	store = dir + "/snapshots"
	if code, out, errOut := run(t, "", "collect", "--store", store, "--name", "pa1", "--vendor", "paloalto", "--config", paloaltoConf); code != cli.ExitOK {
		t.Fatalf("collect: %d %s%s", code, out, errOut)
	}
	inv = dir + "/firemon.yaml"
	yaml := extra + "firewalls:\n  - name: pa1\n    protected:\n      - zone: trust\n        networks: [10.0.0.0/16]\n"
	if err := os.WriteFile(inv, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	return store, inv
}

// The everyday question needs no command name and no flags: the store and
// inventory come from the environment, or the inventory names the store.
func TestRun_CheckPositional(t *testing.T) {
	t.Parallel()
	store, inv := fleet(t, "")
	env := map[string]string{"FIREMON_STORE": store, "FIREMON_INVENTORY": inv}
	for _, args := range [][]string{
		{"check", "10.0.5.1", "8.8.8.8", "udp 53"},
		{"10.0.5.1", "8.8.8.8", "udp 53"},
	} {
		code, out, errOut := runEnv(t, env, "", args...)
		if code != cli.ExitNotAllowed || !strings.Contains(out, "▶ 处置：在 pa1 上执行") {
			t.Fatalf("%v: code %d\n%s%s", args, code, out, errOut)
		}
	}
	_, invWithStore := fleet(t, "store: snapshots\n")
	code, out, errOut := runEnv(t, map[string]string{"FIREMON_INVENTORY": invWithStore}, "", "10.0.5.1", "8.8.8.8", "udp 53", "--no-design")
	if code != cli.ExitUndecided || strings.Contains(out, "▶ 处置：在") || !strings.Contains(out, "■ pa1") {
		t.Fatalf("inventory store, no design: code %d\n%s%s", code, out, errOut)
	}
	code, out, _ = runEnv(t, env, "", "check", "--json", "10.0.5.1", "8.8.8.8", "udp 53")
	var rep struct {
		Firewalls []struct {
			Scripts []struct {
				Commands []string `json:"commands"`
				Rollback []string `json:"rollback"`
			} `json:"scripts"`
		} `json:"firewalls"`
	}
	if err := json.Unmarshal([]byte(out), &rep); err != nil || len(rep.Firewalls) != 1 || len(rep.Firewalls[0].Scripts) == 0 || len(rep.Firewalls[0].Scripts[0].Rollback) == 0 {
		t.Fatalf("json carries the commands (code %d): %v\n%s", code, err, out)
	}
}

func TestRun_UsageErrors(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{
		{"chek"},
		{"check", "10.0.0.1", "10.0.0.2", "tcp/22", "extra"},
		{"check", "10.0.0.1", "10.0.0.2"},
		{"check", "--src", "10.0.0.1", "10.0.0.1", "10.0.0.2", "tcp/22"},
	} {
		code, _, errOut := run(t, "", args...)
		if code != cli.ExitUsage || strings.Count(errOut, "firemon:") > 1 {
			t.Errorf("%v: code %d, stderr %q", args, code, errOut)
		}
	}
}
