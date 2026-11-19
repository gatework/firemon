package cli

import (
	"github.com/spf13/cobra"

	"github.com/gatework/firemon"
)

func newParseCmd(o *options) *cobra.Command {
	var full bool
	cmd := &cobra.Command{
		Use:   "parse",
		Short: "解析并编译配置，报告对象统计、无法解析的行和无法离线判定的策略",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			loaded, _, err := o.load(cmd.Context())
			if err != nil {
				return err
			}
			if full {
				return writeJSON(cmd.OutOrStdout(), loaded.Config)
			}
			s := summarize(loaded.Config, loaded.Firewall)
			if o.json {
				return writeJSON(cmd.OutOrStdout(), s)
			}
			p := &printer{w: cmd.OutOrStdout()}
			p.f("厂商 %s  主机名 %s  版本 %s  指纹 %s\n", s.Vendor, s.Hostname, s.Version, s.Fingerprint[:16])
			p.table("对象\t数量", s.rows())
			for _, d := range s.Diagnostics {
				p.f("第 %d 行未能解析（%s）：%s\n", d.Line, zhReason(d.Reason), d.Text)
			}
			for _, i := range s.Issues {
				p.f("无法离线判定：%s\n", zhIssue(i))
			}
			return p.err
		},
	}
	cmd.Flags().BoolVar(&full, "dump", false, "以 JSON 输出完整的解析结果")
	return cmd
}

// summary is the parse report.
type summary struct {
	Vendor      firemon.Vendor       `json:"vendor"`
	Hostname    string               `json:"hostname,omitempty"`
	Version     string               `json:"version,omitempty"`
	Fingerprint string               `json:"fingerprint"`
	Counts      map[string]int       `json:"counts"`
	Diagnostics []firemon.Diagnostic `json:"diagnostics,omitempty"`
	Issues      []firemon.Issue      `json:"issues,omitempty"`
}

var countOrder = []string{"zones", "interfaces", "routes", "addresses", "address_groups", "services", "service_groups", "schedules", "rules", "undecidable_rules", "static_nats", "dynamic_nats"}

func summarize(cfg *firemon.Config, fw *firemon.Firewall) summary {
	undecidable := 0
	for _, r := range fw.Rules() {
		if !r.Decidable() {
			undecidable++
		}
	}
	return summary{
		Vendor: cfg.Vendor, Hostname: cfg.Hostname, Version: cfg.Version, Fingerprint: fw.Fingerprint(),
		Counts: map[string]int{
			"zones": len(cfg.Zones), "interfaces": len(cfg.Interfaces), "routes": len(cfg.Routes),
			"addresses": len(cfg.Addresses), "address_groups": len(cfg.AddressGroups), "services": len(cfg.Services),
			"service_groups": len(cfg.ServiceGroups), "schedules": len(cfg.Schedules), "rules": len(cfg.Rules),
			"undecidable_rules": undecidable, "static_nats": len(cfg.StaticNATs), "dynamic_nats": len(cfg.DynamicNATs),
		},
		Diagnostics: cfg.Diagnostics,
		Issues:      fw.Issues(),
	}
}

func (s summary) rows() [][]string {
	rows := make([][]string, 0, len(countOrder))
	for _, k := range countOrder {
		rows = append(rows, []string{text(countText, k, k), itoa(s.Counts[k])})
	}
	return rows
}
