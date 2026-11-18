package cli_test

import (
	"bytes"
	"encoding/json"
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
	var out, errw bytes.Buffer
	code = cli.Run(t.Context(), args, cli.Deps{
		Stdin: strings.NewReader(stdin), Stdout: &out, Stderr: &errw,
		Getenv: func(string) string { return "" },
		Now:    func() time.Time { return time.Date(2026, 11, 17, 10, 0, 0, 0, time.UTC) },
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
