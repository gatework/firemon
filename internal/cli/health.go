package cli

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/gatework/firemon/converge"
	"github.com/gatework/firemon/health"
)

// healthFlags are the inputs of the health command.
type healthFlags struct {
	clusters  []string
	verbosity int
	format    string
}

func newHealthCmd(o *options) *cobra.Command {
	var f healthFlags
	cmd := &cobra.Command{
		Use:   "health --inventory 备份目录|库存文件",
		Short: "全网策略健康：按设备统计不会生效的策略、过宽放通、未开日志、未用对象与解析问题，给出健康分和优先处理项",
		Long: "逐台（每个 HA 集群按主设备）审查策略，统计不会生效的策略（冗余、被覆盖、禁用、过期、不完整、永不命中）、\n" +
			"过宽放通、放通未开日志、未使用或为空的对象、无法解析或判定的配置，按公开的扣分规则给出健康分，\n" +
			"并列出全网最该先处理的问题和下一步命令。-v 显示每台的扣分明细。\n" +
			"  firemon health --inventory ~/Documents/2026-10-14",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if o.inventoryFile == "" {
				return &usageError{errors.New("需要 --inventory：配置备份目录，或库存文件与快照")}
			}
			return o.health(cmd, f)
		},
	}
	fl := cmd.Flags()
	fl.StringSliceVar(&f.clusters, "cluster", nil, "只评估这些集群")
	fl.CountVarP(&f.verbosity, "verbose", "v", "显示每台设备的扣分明细")
	fl.StringVar(&f.format, "format", "", "输出格式：text（默认）、markdown、json")
	return cmd
}

// healthResult is one cluster reviewed.
type healthResult struct {
	health.Device
	Label string `json:"device"`
}

func (o *options) health(cmd *cobra.Command, f healthFlags) error {
	format, err := o.outputFormat(f.format)
	if err != nil {
		return err
	}
	clusters, err := o.fleetClusters(cmd, f.clusters)
	if err != nil {
		return err
	}
	results := make([]healthResult, len(clusters))
	eachParallel(len(clusters), func(i int) {
		c := clusters[i]
		rep := converge.Analyze(c.Firewall, converge.Options{Now: o.deps.Now})
		counts := health.CountsOf(c.Firewall, rep)
		results[i] = healthResult{Device: health.Device{Cluster: c.Name, Counts: counts, Score: health.Assess(counts)}, Label: c.Label()}
	})
	devices := make([]health.Device, len(results))
	for i, r := range results {
		devices[i] = r.Device
	}
	priorities := health.Priorities(devices, 5)
	if format == formatJSON {
		return writeJSON(cmd.OutOrStdout(), struct {
			Devices    []healthResult    `json:"devices"`
			Priorities []health.Priority `json:"priorities"`
		}{results, priorities})
	}
	p := &printer{w: cmd.OutOrStdout()}
	printHealth(p, results, priorities, o.inventoryFile, format == formatMarkdown, f.verbosity > 0)
	return p.err
}

// healthHeader names the columns of the health table.
var healthHeader = []string{"设备", "策略", "不生效", "过宽放通", "未开日志", "未用对象", "可合并", "解析问题", "可安全清理", "健康分"}

func healthRow(r healthResult) []string {
	c := r.Counts
	return []string{r.Label, itoa(c.Rules), itoa(c.Ineffective), itoa(c.Broad), itoa(c.NoLog), itoa(c.Unused + c.Empty),
		itoa(c.Mergeable), itoa(c.Unreadable), itoa(c.Safe), itoa(r.Score.Value)}
}

func printHealth(p *printer, results []healthResult, priorities []health.Priority, inv string, markdown, verbose bool) {
	total, ineffective, safe := 0, 0, 0
	for _, r := range results {
		total += r.Counts.Rules
		ineffective += r.Counts.Ineffective
		safe += r.Counts.Safe
	}
	p.f("全网策略健康：%d 台（按 HA 集群的主设备评估），策略 %d 条，其中 %d 条不会生效；可安全清理 %d 项\n\n", len(results), total, ineffective, safe)
	if markdown {
		p.f("| %s |\n|%s\n", strings.Join(healthHeader, " | "), strings.Repeat("---|", len(healthHeader)))
		for _, r := range results {
			p.f("| %s |\n", strings.Join(healthRow(r), " | "))
		}
	} else {
		rows := [][]string{healthHeader}
		for _, r := range results {
			rows = append(rows, healthRow(r))
		}
		columns(p, "", rows)
	}
	if len(priorities) > 0 {
		p.f("\n优先处理：\n")
		for i, pr := range priorities {
			r := resultOf(results, pr.Cluster)
			p.f("  %d. %s（健康分 %d）：%s\n     → %s\n", i+1, r.Label, pr.Score, priorityText(pr, r.Counts), nextStep(pr, inv))
		}
	}
	if verbose {
		p.f("\n扣分明细（健康分 = 100 − 各项占比 × 权重）：\n")
		for _, r := range results {
			parts := make([]string, 0, len(r.Score.Deductions))
			for _, d := range r.Score.Deductions {
				if d.Points > 0 {
					parts = append(parts, fmt.Sprintf("%s %.0f%%×%d=%.1f", text(factorText, d.Factor, d.Factor), d.Ratio*100, d.Weight, d.Points))
				}
			}
			p.f("  %s %d：%s\n", r.Label, r.Score.Value, orDash(strings.Join(parts, "，")))
		}
	} else {
		p.f("\n（-v 查看扣分明细；--json 输出全部计数）\n")
	}
}

var factorText = map[string]string{
	health.FactorIneffective: "不生效策略", health.FactorBroad: "过宽放通", health.FactorNoLog: "未开日志",
	health.FactorUnused: "未用对象", health.FactorUnreadable: "无法解析或判定",
}

func resultOf(results []healthResult, cluster string) healthResult {
	for _, r := range results {
		if r.Cluster == cluster {
			return r
		}
	}
	return healthResult{Label: cluster}
}

// priorityText says what costs a firewall most, with the numbers.
func priorityText(pr health.Priority, c health.Counts) string {
	switch pr.Worst.Factor {
	case health.FactorIneffective:
		return fmt.Sprintf("%d 条策略不会生效（冗余 %d、被覆盖 %d、禁用 %d、过期 %d、不完整 %d），占 %.0f%%", c.Ineffective, c.Redundant, c.Shadowed, c.Disabled, c.Expired, c.Incomplete, pr.Worst.Ratio*100)
	case health.FactorBroad:
		return fmt.Sprintf("%d 条放通过宽，占放通策略 %.0f%%", c.Broad, pr.Worst.Ratio*100)
	case health.FactorNoLog:
		return fmt.Sprintf("%d 条放通未开日志，占放通策略 %.0f%%", c.NoLog, pr.Worst.Ratio*100)
	case health.FactorUnused:
		return fmt.Sprintf("%d 个对象未使用或为空，占全部对象 %.0f%%", c.Unused+c.Empty, pr.Worst.Ratio*100)
	default:
		return fmt.Sprintf("%d 处配置无法解析或判定", c.Unreadable)
	}
}

// nextStep is the command that acts on a priority.
func nextStep(pr health.Priority, inv string) string {
	base := "firemon converge --inventory " + inv + " --cluster " + pr.Cluster
	switch pr.Worst.Factor {
	case health.FactorIneffective, health.FactorUnused:
		return base + " --plan --out ./cleanup（生成已验证的清理脚本与回退）"
	case health.FactorBroad, health.FactorNoLog:
		return base + " -v（逐条评估）"
	default:
		return "firemon parse --config <该设备的配置>（查看无法解析的行）"
	}
}
