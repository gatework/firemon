package cli_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gatework/firemon/internal/cli"
)

// Operations features of search (round 2): change risk, temporary access,
// Markdown for tickets, batch tickets designed one on the other.
func TestSearch_Operations(t *testing.T) {
	t.Parallel()
	hs := []string{"--config", hillstoneConf, "--timezone", "UTC"}
	batch := filepath.Join(t.TempDir(), "tickets.csv")
	rows := "工单号,源,目的,服务\nT-1,10.0.0.5,203.0.113.208,tcp/80\nT-2,10.0.0.6,203.0.113.208,tcp/80\n"
	if err := os.WriteFile(batch, []byte(rows), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name   string
		args   []string
		code   int
		want   []string
		absent string
	}{
		{"a rule placed before a deny carries its risk", []string{"search", "-v", "--src", "203.0.113.9", "--dst", "10.0.0.5", "--service", "tcp/80"}, cli.ExitNotAllowed, []string{"风险："}, ""},
		{"temporary access expires on the device", []string{"search", "--src", "10.0.0.5", "--dst", "203.0.113.208", "--service", "tcp/80", "--until", "2026-12-31", "-v"},
			cli.ExitNotAllowed, []string{"expire-time 12/31/2026 23:59:00", "时间：有效期 至 2026-12-31"}, ""},
		{"an end in the past is refused", []string{"search", "--src", "10.0.0.5", "--dst", "203.0.113.208", "--service", "tcp/80", "--until", "2026-01-01"}, cli.ExitUsage, []string{"已经过去"}, ""},
		{"markdown for a ticket", []string{"search", "--format", "markdown", "--src", "10.0.0.5,10.0.0.6", "--dst", "203.0.113.208", "--service", "tcp/80"},
			cli.ExitNotAllowed, []string{"**结论**", "| # | 源 | 目的 |", "```"}, "■"},
		{"batch tickets: summary, then each on the one before", []string{"search", "-v", "--file", batch},
			cli.ExitNotAllowed, []string{"批量工单汇总（2 单）", "新增策略 T-1", "修改策略 11 T-1", "修改工单 T-1 新建的策略", "结论：需要修改已有策略"}, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			code, out, errOut := run(t, "", append(c.args, hs...)...)
			all := out + errOut
			if code != c.code {
				t.Fatalf("exit %d, want %d\n%s", code, c.code, all)
			}
			for _, w := range c.want {
				if !strings.Contains(all, w) {
					t.Fatalf("missing %q\n%s", w, all)
				}
			}
			if c.absent != "" && strings.Contains(all, c.absent) {
				t.Fatalf("unexpected %q\n%s", c.absent, all)
			}
		})
	}
}

// Batch tickets on one firewall do not reuse rule IDs: the second is
// designed on the first (here to a different destination, so it cannot
// extend the first ticket's rule).
func TestSearch_BatchRuleIDs(t *testing.T) {
	t.Parallel()
	batch := filepath.Join(t.TempDir(), "tickets.csv")
	if err := os.WriteFile(batch, []byte("T-1,10.0.0.5,203.0.113.208,tcp/80\nT-2,10.0.0.6,203.0.113.210,tcp/8080\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, out, errOut := run(t, "", "search", "--json", "--file", batch, "--config", hillstoneConf, "--timezone", "UTC")
	var results []struct {
		Report struct {
			Firewalls []struct {
				Planned []struct {
					Rule struct {
						Rule string `json:"rule"`
					} `json:"rule"`
				} `json:"planned"`
			} `json:"firewalls"`
		} `json:"report"`
	}
	if err := json.Unmarshal([]byte(out), &results); err != nil || len(results) != 2 {
		t.Fatalf("%v\n%s%s", err, out, errOut)
	}
	ids := map[string]bool{}
	for _, r := range results {
		for _, f := range r.Report.Firewalls {
			for _, p := range f.Planned {
				if ids[p.Rule.Rule] {
					t.Fatalf("rule ID %s planned twice", p.Rule.Rule)
				}
				ids[p.Rule.Rule] = true
			}
		}
	}
	if len(ids) != 2 {
		t.Fatalf("planned rules %v", ids)
	}
}

// The default answer is the scripts: per firewall the existing rules
// permitting the flows as the device holds them, and the script with its
// rollback for what is still needed. -v adds the reasoning.
func TestSearch_ScriptsByDefault(t *testing.T) {
	t.Parallel()
	args := []string{"search", "--config", hillstoneConf, "--timezone", "UTC"}
	_, needed, _ := run(t, "", append(args, "--src", "203.0.113.9", "--dst", "10.0.0.5", "--service", "tcp/80")...)
	for _, want := range []string{"结论：需要变更 —— lab-fw1 1 条", "放通 203.0.113.9 → 10.0.0.5 tcp/80（原被策略 3 block-inbound 拒绝）", "    rule id ", "  回退：", "⚠ "} {
		if !strings.Contains(needed, want) {
			t.Fatalf("missing %q\n%s", want, needed)
		}
	}
	for _, reasoning := range []string{"命中依据", "未选择修改", "名称：", "流量明细"} {
		if strings.Contains(needed, reasoning) {
			t.Fatalf("default output has %q\n%s", reasoning, needed)
		}
	}
	_, allowed, _ := run(t, "", append(args, "--src", "198.51.100.9", "--dst", "172.16.0.10", "--service", "tcp/443")...)
	for _, want := range []string{"结论：无需变更 —— 已有策略放通", "已有策略 1 web-in 放通 198.51.100.9 → 172.16.0.10 tcp/443：", "    rule id 1"} {
		if !strings.Contains(allowed, want) {
			t.Fatalf("missing %q\n%s", want, allowed)
		}
	}
	_, reasoned, _ := run(t, "", append(args, "-v", "--src", "203.0.113.9", "--dst", "10.0.0.5", "--service", "tcp/80")...)
	if !strings.Contains(reasoned, "动作：") {
		t.Fatalf("-v prints the reasoning\n%s", reasoned)
	}
}

// converge and audit answer with a summary; -v lists the findings.
func TestConvergeAndAudit_SummaryByDefault(t *testing.T) {
	t.Parallel()
	for _, cmd := range []string{"converge", "audit"} {
		_, brief, errOut := run(t, "", cmd, "--config", hillstoneConf, "--timezone", "UTC")
		_, detail, _ := run(t, "", cmd, "-v", "--config", hillstoneConf, "--timezone", "UTC")
		if lines := strings.Count(brief, "\n"); lines > 15 || lines == 0 {
			t.Fatalf("%s summary has %d lines\n%s%s", cmd, lines, brief, errOut)
		}
		if strings.Count(detail, "\n") <= strings.Count(brief, "\n") {
			t.Fatalf("%s -v lists nothing more\n%s", cmd, detail)
		}
	}
}
