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
		{"parse", []string{"parse", "--vendor", "hillstone", "--config", hillstoneConf}, cli.ExitOK, "策略                5"},
		{"query allowed", []string{"search", "--vendor", "hillstone", "--config", hillstoneConf, "--timezone", "UTC",
			"--src", "198.51.100.9", "--dst", "172.16.0.10", "--service", "tcp/443"}, cli.ExitOK, "结论：完全命中"},
		{"query denied", []string{"search", "--vendor", "paloalto", "--config", paloaltoConf,
			"--src", "192.0.2.7", "--dst", "10.0.0.9", "--service", "tcp/443"}, cli.ExitNotAllowed, "被策略 block-bad 拒绝"},
		{"vendor from the configuration", []string{"search", "--config", paloaltoConf,
			"--src", "192.0.2.7", "--dst", "10.0.0.9", "--service", "tcp/443"}, cli.ExitNotAllowed, "被策略 block-bad 拒绝"},
		{"same side does not cross", []string{"search", "--config", paloaltoConf,
			"--src", "10.0.0.5", "--dst", "10.0.0.9", "--service", "tcp/443"}, cli.ExitUndecided, "源和目的在防火墙同一侧"},
		{"usage", []string{"usage", "--vendor", "paloalto", "--config", paloaltoConf, "--addr", "172.16.0.10"}, cli.ExitOK, "web-01"},
		{"design", []string{"search", "--vendor", "paloalto", "--config", paloaltoConf,
			"--src", "10.0.7.0/24", "--dst", "172.16.0.40", "--service", "tcp/8443", "--from-zone", "trust", "--to-zone", "dmz", "--name", "req"},
			cli.ExitNotAllowed, "set rulebase security rules req action allow"},
		{"audit", []string{"audit", "--vendor", "hillstone", "--config", hillstoneConf}, cli.ExitOK, "未使用的地址对象"},
		{"unknown vendor", []string{"parse", "--vendor", "acme", "--config", hillstoneConf}, cli.ExitUsage, ""},
		{"deploy rejects files", []string{"deploy", "--vendor", "hillstone", "--config", hillstoneConf,
			"--src", "10.0.0.1", "--dst", "10.0.0.2", "--service", "tcp/22"}, cli.ExitUsage, ""},
		{"missing traffic", []string{"search", "--vendor", "hillstone", "--config", hillstoneConf}, cli.ExitUsage, ""},
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
	code, out, errOut := run(t, "", "search", "--json", "--vendor", "paloalto", "--config", paloaltoConf,
		"--src", "10.0.0.5", "--dst", "8.8.8.8", "--service", "udp/53")
	var res struct {
		Firewalls []struct {
			Paths []struct {
				From string `json:"from"`
				To   string `json:"to"`
			} `json:"paths"`
		} `json:"firewalls"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("code %d: %v\n%s%s", code, err, out, errOut)
	}
	if len(res.Firewalls) != 1 || len(res.Firewalls[0].Paths) != 1 || res.Firewalls[0].Paths[0].From != "trust" || res.Firewalls[0].Paths[0].To != "untrust" {
		t.Fatalf("report %+v", res)
	}
}

func TestRun_CollectThenQuerySnapshot(t *testing.T) {
	t.Parallel()
	store := t.TempDir() + "/snapshots"
	code, out, errOut := run(t, "", "collect", "--vendor", "paloalto", "--config", paloaltoConf, "--store", store, "--name", "pa1")
	if code != cli.ExitOK || !strings.Contains(out, "已保存快照 pa1") {
		t.Fatalf("collect: %d\n%s%s", code, out, errOut)
	}
	code, out, errOut = run(t, "", "collect", "--list", "--store", store)
	if code != cli.ExitOK || !strings.Contains(out, "pa1") {
		t.Fatalf("list: %d\n%s%s", code, out, errOut)
	}
	code, out, errOut = run(t, "", "search", "-v", "--snapshot", "pa1", "--store", store,
		"--src", "10.0.0.5", "--dst", "8.8.8.8", "--service", "udp/53")
	if code != cli.ExitNotAllowed || !strings.Contains(out, "路径 trust(ethernet1/2) → untrust") {
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
	code, out, errOut := run(t, "", "search", "--store", store, "--design", "--src", "10.0.0.5", "--dst", "172.16.0.40", "--service", "tcp/8443", "--name", "req")
	if code != cli.ExitNotAllowed || !strings.Contains(out, "处置：在 pa1 上执行") {
		t.Fatalf("locate: %d\n%s%s", code, out, errOut)
	}
}

func TestRun_ServiceBook(t *testing.T) {
	t.Parallel()
	book := t.TempDir() + "/book.json"
	if err := os.WriteFile(book, []byte(`{"HTTPS":["tcp/443","tcp/8443"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, _ := run(t, "", "predefined-service", "--vendor", "hillstone", "--predefined-service", book)
	if code != cli.ExitOK || !strings.Contains(out, "tcp/443,tcp/8443") || !strings.Contains(out, "SSH") {
		t.Fatalf("services: %d\n%s", code, out)
	}
	args := []string{"search", "--vendor", "hillstone", "--config", hillstoneConf, "--timezone", "UTC",
		"--src", "198.51.100.9", "--dst", "172.16.0.10", "--service", "tcp/8443"}
	if code, _, _ := run(t, "", args...); code != cli.ExitNotAllowed {
		t.Fatalf("default book: %d", code)
	}
	if code, out, _ := run(t, "", append(args, "--predefined-service", book)...); code != cli.ExitOK {
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
	code, out, errOut := run(t, "", "search", "-v", "--store", store, "--inventory", inv,
		"--src", "10.0.5.0 255.255.255.0，172.31.0.9", "--dst", "8.8.8.8", "--service", "53/udp", "--name", "REQ-7")
	if code != cli.ExitNotAllowed {
		t.Fatalf("a verified change is ready: code %d\n%s%s", code, out, errOut)
	}
	for _, want := range []string{"结论：", "■ pa1：", "不经过任何防火墙（已剔除）：源 172.31.0.9", "地址+掩码已转换为网段", "处置：在 pa1 上执行"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q (code %d)\n%s%s", want, code, out, errOut)
		}
	}
	code, out, _ = run(t, "", "search", "--json", "--store", store, "--inventory", inv, "--src", "10.0.5.1", "--dst", "8.8.8.8", "--service", "udp 53")
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

// The everyday question needs only --src, --dst and --service: the store
// and inventory come from the environment, or the inventory names the store.
func TestRun_CheckDefaults(t *testing.T) {
	t.Parallel()
	store, inv := fleet(t, "")
	env := map[string]string{"FIREMON_STORE": store, "FIREMON_INVENTORY": inv}
	code, out, errOut := runEnv(t, env, "", "search", "--src", "10.0.5.1", "--dst", "8.8.8.8", "--service", "udp 53")
	if code != cli.ExitNotAllowed || !strings.Contains(out, "处置：在 pa1 上执行") {
		t.Fatalf("code %d\n%s%s", code, out, errOut)
	}
	_, invWithStore := fleet(t, "store: snapshots\n")
	code, out, errOut = runEnv(t, map[string]string{"FIREMON_INVENTORY": invWithStore}, "", "search", "--src", "10.0.5.1", "--dst", "8.8.8.8", "--service", "udp 53", "--no-design")
	if code != cli.ExitUndecided || strings.Contains(out, "处置：在") || !strings.Contains(out, "■ pa1") {
		t.Fatalf("inventory store, no design: code %d\n%s%s", code, out, errOut)
	}
	code, out, _ = runEnv(t, env, "", "search", "--json", "--src", "10.0.5.1", "--dst", "8.8.8.8", "--service", "udp 53")
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
		{"10.0.0.1", "10.0.0.2", "tcp/22"},
		{"search", "10.0.0.1", "10.0.0.2", "tcp/22"},
		{"check", "--src", "10.0.0.1", "--dst", "10.0.0.2", "--service", "tcp/22"},
		{"query", "--src", "10.0.0.1", "--dst", "10.0.0.2", "--service", "tcp/22"},
		{"search", "--src", "10.0.0.1", "--dst", "10.0.0.2"},
	} {
		code, _, errOut := run(t, "", args...)
		if code != cli.ExitUsage || strings.Count(errOut, "firemon:") > 1 {
			t.Errorf("%v: code %d, stderr %q", args, code, errOut)
		}
	}
}

// A request a specific deny blocks needs a new rule: the design places it
// before the deny and asks to confirm bypassing it.
func TestRun_CheckBlockedDesignsBeforeTheDeny(t *testing.T) {
	t.Parallel()
	args := []string{"search", "--vendor", "paloalto", "--config", paloaltoConf, "--src", "192.0.2.7", "--dst", "10.0.0.9", "--service", "tcp/443", "--name", "REQ-9"}
	code, out, errOut := run(t, "", args...)
	for _, want := range []string{"结论：需要新增策略", "被策略 block-bad 拒绝", "拒绝  策略 block-bad（第 1 条）", "⚠ 新策略放在拒绝策略 block-bad 之前", "move rulebase security rules REQ-9 before block-bad"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q (code %d)\n%s%s", want, code, out, errOut)
		}
	}
	if code != cli.ExitNotAllowed {
		t.Fatalf("a verified change is ready: code %d", code)
	}
	// Paths and candidates are detail.
	if strings.Contains(out, "路径 ") {
		t.Fatalf("default output shows paths:\n%s", out)
	}
	_, verbose, _ := run(t, "", append(args, "-v")...)
	if !strings.Contains(verbose, "路径 untrust") {
		t.Fatalf("-v shows the paths:\n%s", verbose)
	}
}

// A fully matched request shows the rule that permits it and nothing to do.
func TestRun_CheckFullMatch(t *testing.T) {
	t.Parallel()
	code, out, errOut := run(t, "", "search", "--vendor", "hillstone", "--config", hillstoneConf, "--timezone", "UTC",
		"--src", "198.51.100.9", "--dst", "172.16.0.10", "--service", "tcp/443")
	want := "结论：完全命中\n\n■ lab-fw1：完全命中\n  已有策略：\n    放通  策略 1 web-in（第 2 条）：198.51.100.9 -> 172.16.0.10 tcp/443\n" +
		"          区域 untrust → dmz；源 任意；目的 web-servers（172.16.0.10、172.16.0.20-172.16.0.29）；服务 web（tcp/80、tcp/443、tcp/8080）；日志 会话结束\n  处置：无需变更\n"
	if code != cli.ExitOK || out != want {
		t.Fatalf("code %d\n%s%s", code, out, errOut)
	}
}

// nat looks an address up both ways and says which entries take effect.
func TestRun_NAT(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		conf, ip string
		want     []string
	}{
		{paloaltoConf, "172.16.0.10", []string{"被发布：公网 198.51.100.80 tcp/80,tcp/8080 ⇒ 内部 172.16.0.10 tcp/8080  [NAT 规则 dnat-web（第 1 条），生效]"}},
		{paloaltoConf, "198.51.100.80", []string{"入站目的转换：公网 198.51.100.80 tcp/80,tcp/8080 ⇒ 内部 172.16.0.10 tcp/8080"}},
		{paloaltoConf, "172.16.0.11", []string{"[NAT 规则 static-web（第 3 条），被前面的规则 snat-out 完全覆盖，不会生效]", "被发布：公网 198.51.100.11 ⇒ 内部 172.16.0.11  [静态 NAT static-web，生效]"}},
		{hillstoneConf, "10.1.0.5", []string{"[NAT 规则 2（第 2 条），已禁用]"}},
		{hillstoneConf, "172.16.0.10", []string{"被发布：公网 198.51.100.80 tcp/80 ⇒ 内部 172.16.0.10 tcp/8080  [NAT 规则 1（第 1 条），生效]"}},
	} {
		code, out, errOut := run(t, "", "nat", "--config", tt.conf, "--ip", tt.ip)
		for _, w := range tt.want {
			if code != cli.ExitOK || !strings.Contains(out, w) {
				t.Errorf("%s %s: missing %q (code %d)\n%s%s", tt.conf, tt.ip, w, code, out, errOut)
			}
		}
	}
	// The public address of a source translation is not "translated when
	// it goes out" by a rule for traffic from the inside.
	_, out, _ := run(t, "", "nat", "--config", paloaltoConf, "--ip", "198.51.100.80")
	if strings.Contains(out, "出访源转换") {
		t.Errorf("an inside source rule listed for a public address:\n%s", out)
	}
}
