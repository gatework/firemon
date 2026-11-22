package cli

import (
	"cmp"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/gatework/firemon/adapter/filestore"
	"github.com/gatework/firemon/converge"
	"github.com/gatework/firemon/design"
	"github.com/gatework/firemon/hits"
	"github.com/gatework/firemon/internal/bootstrap"
	"github.com/gatework/firemon/inventory"
)

type convergeFlags struct {
	hitsFile  string
	minWindow time.Duration
	plan      bool
	selection []string
	clusters  []string
	out       string
	verbosity int
}

func newConvergeCmd(o *options) *cobra.Command {
	var f convergeFlags
	cmd := &cobra.Command{
		Use:   "converge",
		Short: "策略收敛：不会生效的策略、未用对象、可合并策略、过宽放通，安全项生成已验证的清理脚本与回退",
		Long: "审查策略：不会生效的策略（冗余、被覆盖、禁用、过期、不完整、永不命中），未使用、为空或重复的对象，\n" +
			"可合并的策略，以及需要人工评估的过宽放通和未开日志的放通。默认每台给出汇总，-v 逐条列出（方括号里是 --select 用的编号）。\n" +
			"--plan 把安全项（或 --select 指定的发现）设计为变更，验证每个判定都不变后给出脚本与回退；--out 目录 保存为文件。\n" +
			"--inventory 可以是配置备份目录或库存文件，--cluster 只处理指定集群：\n" +
			"  firemon converge --inventory ~/Documents/2026-10-14 --cluster SZX9-IN --plan --out ./cleanup",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return o.converge(cmd, f)
		},
	}
	fl := cmd.Flags()
	fl.StringVar(&f.hitsFile, "hits", "", "命中计数文件（JSON 或 CSV）；默认使用快照库中该快照最新的计数")
	fl.DurationVar(&f.minWindow, "min-window", converge.DefaultMinWindow, "判定零命中所需的最短观察时长")
	fl.BoolVar(&f.plan, "plan", false, "为安全项生成变更方案、命令与回退命令")
	fl.StringSliceVar(&f.selection, "select", nil, "只处理这些发现（-v 列表方括号中的编号）；默认全部安全项")
	fl.StringSliceVar(&f.clusters, "cluster", nil, "只处理这些集群（--inventory 时）")
	fl.StringVar(&f.out, "out", "", "清理脚本与回退写入此目录（每台 <设备>-cleanup.txt 与 <设备>-rollback.txt）")
	fl.CountVarP(&f.verbosity, "verbose", "v", "逐条列出发现及证据")
	return cmd
}

// review is one firewall reviewed, with its cleanup when planned.
type review struct {
	converge.Report
	Cluster string             `json:"cluster"`
	Devices []inventory.Device `json:"devices"`
	Plan    *design.Plan       `json:"plan,omitempty"`
	Script  *design.Script     `json:"script,omitempty"`
	// Files are where the script and rollback were written.
	Files []string `json:"files,omitempty"`
	err   error
}

func (o *options) converge(cmd *cobra.Command, f convergeFlags) error {
	var targets []fleetCluster
	if o.inventoryFile != "" {
		var err error
		if targets, err = o.fleetClusters(cmd, f.clusters); err != nil {
			return err
		}
		if len(targets) == 0 {
			return &usageError{fmt.Errorf("--cluster %s 不在库存中", strings.Join(f.clusters, ","))}
		}
	} else {
		loaded, platform, err := o.load(cmd.Context())
		if err != nil {
			return err
		}
		name := cmp.Or(o.snapshot, loaded.Config.Hostname, "firewall")
		targets = []fleetCluster{{Name: name, Firewall: loaded.Firewall, Platform: platform, Devices: []inventory.Device{{Name: name, Host: o.device.host, Evaluated: true}}}}
	}
	reviews := make([]review, len(targets))
	counters := make([]*hits.Snapshot, len(targets))
	for i, t := range targets {
		c, err := o.reviewCounters(cmd, f, t)
		if err != nil {
			return err
		}
		counters[i] = c
	}
	eachParallel(len(targets), func(i int) {
		reviews[i] = o.reviewOne(targets[i], counters[i], f)
	})
	for _, r := range reviews {
		if r.err != nil {
			return r.err
		}
	}
	if f.out != "" && f.plan {
		if err := writeCleanups(f.out, reviews); err != nil {
			return err
		}
	}
	if o.json {
		return writeJSON(cmd.OutOrStdout(), reviews)
	}
	p := &printer{w: cmd.OutOrStdout()}
	for _, r := range reviews {
		printReview(p, r, f)
	}
	return p.err
}

// reviewCounters are the hit counters of a firewall: a file, the snapshot
// store's latest for --snapshot, or those of every member of a cluster
// whose snapshots the store holds (a rule unused on the active member may
// carry the standby's traffic after a failover).
func (o *options) reviewCounters(cmd *cobra.Command, f convergeFlags, t fleetCluster) (*hits.Snapshot, error) {
	if o.inventoryFile == "" || f.hitsFile != "" {
		return o.counters(cmd, f.hitsFile)
	}
	if isDir(o.inventoryFile) {
		return nil, nil //nolint:nilnil // backups carry no counters
	}
	store, err := bootstrap.OpenSnapshots(o.store)
	if err != nil {
		return nil, err
	}
	var snaps []hits.Snapshot
	for _, d := range t.Devices {
		s, err := store.LatestHits(cmd.Context(), d.Name)
		if errors.Is(err, filestore.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		snaps = append(snaps, s)
	}
	if len(snaps) == 0 {
		return nil, nil //nolint:nilnil // no counters: static review only
	}
	merged := hits.Merge(t.Name, snaps...)
	return &merged, nil
}

// reviewOne analyzes a firewall and, when asked, plans its cleanup.
func (o *options) reviewOne(t fleetCluster, counters *hits.Snapshot, f convergeFlags) review {
	rep := converge.Analyze(t.Firewall, converge.Options{Now: o.deps.Now, Hits: counters, MinWindow: f.minWindow})
	r := review{Cluster: t.Name, Devices: t.Devices, Report: rep}
	if !f.plan {
		return r
	}
	plan, err := converge.Plan(t.Firewall, rep, converge.Selection{IDs: f.selection}, converge.PlanOptions{Now: o.deps.Now, Naming: t.Platform.Naming})
	if err != nil {
		r.err = &usageError{fmt.Errorf("%s：%w", t.Label(), err)}
		return r
	}
	script, err := t.Platform.Render(plan)
	if err != nil {
		r.err = err
		return r
	}
	r.Plan, r.Script = plan, scriptOrNil(plan, script)
	return r
}

// writeCleanups writes each verified cleanup as two files.
func writeCleanups(dir string, reviews []review) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("创建 %s 失败：%w", dir, err)
	}
	for i := range reviews {
		r := &reviews[i]
		if r.Script == nil || len(r.Script.Commands) == 0 {
			continue
		}
		name := r.Cluster
		if len(r.Devices) > 0 {
			name = r.Devices[0].Name
		}
		base := filepath.Join(dir, fileSafe(name))
		for suffix, lines := range map[string][]string{"-cleanup.txt": r.Script.Commands, "-rollback.txt": r.Script.Rollback} {
			path := base + suffix
			if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
				return fmt.Errorf("写入 %s 失败：%w", path, err)
			}
			r.Files = append(r.Files, path)
		}
	}
	return nil
}

func fileSafe(s string) string {
	return strings.Map(func(r rune) rune {
		if strings.ContainsRune(`/\:*?"<>|() `, r) {
			return '_'
		}
		return r
	}, s)
}

func label(devices []inventory.Device, fallback string) string {
	if len(devices) > 0 {
		return devices[0].Label()
	}
	return fallback
}

// printReview writes one firewall: the summary, the findings with -v, and
// the cleanup when planned.
func printReview(p *printer, r review, f convergeFlags) {
	p.f("\n━━ %s", label(r.Devices, r.Cluster))
	if len(r.Devices) > 1 {
		peers := make([]string, 0, len(r.Devices)-1)
		for _, d := range r.Devices[1:] {
			peers = append(peers, d.Label())
		}
		p.f("  HA 同步至 %s", strings.Join(peers, "、"))
	}
	p.f("\n")
	printReviewSummary(p, r.Report)
	if f.verbosity > 0 {
		printConverge(p, r.Report)
	}
	switch {
	case r.Plan != nil:
		printCleanupPlan(p, r, f.out != "")
	case safeCount(r.Report) > 0:
		p.f("  → 加 --plan 生成已验证的清理脚本（--out 目录 保存为文件）；-v 逐条列出\n")
	}
}

// printReviewSummary counts a review by what an operator does with it.
func printReviewSummary(p *printer, rep converge.Report) {
	n := rep.Count
	ineffective := n(converge.CategoryRedundant) + n(converge.CategoryShadowed) + n(converge.CategoryDisabled) +
		n(converge.CategoryExpired) + n(converge.CategoryIncomplete) + n(converge.CategoryNeverMatches)
	if ineffective > 0 {
		p.f("  不会生效的策略 %d 条：%s\n", ineffective, countList(rep, converge.CategoryRedundant, converge.CategoryShadowed,
			converge.CategoryDisabled, converge.CategoryExpired, converge.CategoryIncomplete, converge.CategoryNeverMatches))
	}
	if objects := countList(rep, converge.CategoryUnusedObject, converge.CategoryEmptyObject, converge.CategoryDuplicateObject); objects != "" {
		p.f("  对象：%s\n", objects)
	}
	if m := n(converge.CategoryMergeable); m > 0 {
		p.f("  可合并策略：%d 组\n", m)
	}
	if review := countList(rep, converge.CategoryBroad, converge.CategoryNoLog, converge.CategoryZeroHit); review != "" {
		p.f("  需人工评估：%s\n", review)
	}
	if !rep.HitsTaken.IsZero() {
		p.f("  命中计数采集于 %s\n", rep.HitsTaken.Format("2006-01-02 15:04"))
	}
	if len(rep.Incomplete) > 0 {
		p.f("  覆盖分析未完成的策略：%s\n", strings.Join(rep.Incomplete, ","))
	}
	if ineffective == 0 && len(rep.Findings) == 0 {
		p.f("  没有发现问题\n")
	}
	if s := safeCount(rep); s > 0 {
		p.f("  可安全清理 %d 项\n", s)
	}
}

// countList writes the categories with findings as "name N".
func countList(rep converge.Report, cats ...converge.Category) string {
	var parts []string
	for _, c := range cats {
		if k := rep.Count(c); k > 0 {
			parts = append(parts, shortCategory(c)+" "+itoa(k))
		}
	}
	return strings.Join(parts, "、")
}

func shortCategory(c converge.Category) string {
	return map[converge.Category]string{
		converge.CategoryRedundant: "冗余", converge.CategoryShadowed: "被覆盖", converge.CategoryDisabled: "禁用",
		converge.CategoryExpired: "过期", converge.CategoryIncomplete: "不完整", converge.CategoryNeverMatches: "永不匹配",
		converge.CategoryUnusedObject: "未使用", converge.CategoryEmptyObject: "空", converge.CategoryDuplicateObject: "重复",
		converge.CategoryBroad: "过宽放通", converge.CategoryNoLog: "放通未开日志", converge.CategoryZeroHit: "零命中",
	}[c]
}

func safeCount(rep converge.Report) int {
	n := 0
	for _, f := range rep.Findings {
		if f.Tier == converge.TierSafe {
			n++
		}
	}
	return n
}

// scriptOrNil returns the script of a verified plan: commands of a plan
// whose verification failed must never be handed out.
func scriptOrNil(plan *design.Plan, s design.Script) *design.Script {
	if plan == nil || !plan.Verified {
		return nil
	}
	return &s
}

// counters reads hit counters from a file or the snapshot store; none is
// not an error.
func (o *options) counters(cmd *cobra.Command, file string) (*hits.Snapshot, error) {
	if file != "" {
		snap, err := o.readHits(cmd, o.snapshot, "", file)
		return &snap, err
	}
	if o.snapshot == "" {
		return nil, nil //nolint:nilnil // no counters: static review only
	}
	store, err := bootstrap.OpenSnapshots(o.store)
	if err != nil {
		return nil, err
	}
	snap, err := store.LatestHits(cmd.Context(), o.snapshot)
	if errors.Is(err, filestore.ErrNotFound) {
		return nil, nil //nolint:nilnil // no counters collected yet
	}
	return &snap, err
}

// printConverge lists the findings by category, each with its selector.
func printConverge(p *printer, rep converge.Report) {
	last := converge.CategoryUnset
	for _, f := range rep.Findings {
		if f.Category != last {
			last = f.Category
			p.f("\n  ■ %s（%d 项）\n", text(categoryText, f.Category, f.Category.String()), rep.Count(f.Category))
		}
		p.f("    %s  [%s｜%s｜%s]\n", findingText(f), text(tierText, f.Tier, f.Tier.String()), text(evidenceText, f.Evidence, f.Evidence.String()), f.ID)
	}
	p.f("\n")
}

func findingText(f converge.Finding) string {
	var parts []string
	if len(f.Objects) > 0 {
		names := make([]string, len(f.Objects))
		for i, o := range f.Objects {
			names[i] = text(objectKindText, o.Kind, o.Kind.String()) + " " + o.Name
		}
		parts = append(parts, strings.Join(names, "，"))
	}
	if f.Merge != nil {
		parts = append(parts, fmt.Sprintf("策略 %s 的%s并入策略 %s 后删除", strings.Join(f.Merge.Remove, ","), text(fieldText2, f.Merge.Field, f.Merge.Field.String()), f.Merge.Keep))
	} else if len(f.Rules) > 0 {
		parts = append(parts, "策略 "+strings.Join(f.Rules, ","))
	}
	if len(f.By) > 0 {
		parts = append(parts, "被策略 "+strings.Join(f.By, ",")+" 覆盖")
	}
	if len(f.Reasons) > 0 {
		rs := make([]string, len(f.Reasons))
		for i, r := range f.Reasons {
			rs[i] = text(convergeReasonText, r, r.String())
		}
		parts = append(parts, strings.Join(rs, "、"))
	}
	if f.Detail != "" {
		parts = append(parts, zhReason(f.Detail))
	}
	return strings.Join(parts, "；")
}

// printCleanupPlan writes a verified cleanup: the files it went to, or the
// commands and rollback.
func printCleanupPlan(p *printer, r review, toFiles bool) {
	plan := r.Plan
	if !plan.Verified {
		// Never print commands that are not proven to keep every decision.
		p.f("  清理方案验证未通过：%s。不输出命令；请用 --select 缩小范围后重试\n", cmp.Or(plan.VerifyError, "未验证"))
		return
	}
	if r.Script == nil || len(r.Script.Commands) == 0 {
		p.f("  没有需要清理的项\n")
		return
	}
	p.f("  清理方案：%d 项变更，已验证全部判定不变；命令 %d 行\n", len(plan.Changes), len(r.Script.Commands))
	if toFiles {
		for _, path := range r.Files {
			p.f("    %s\n", path)
		}
	} else {
		p.f("  命令：\n    %s\n  回退：\n    %s\n", strings.Join(r.Script.Commands, "\n    "), strings.Join(r.Script.Rollback, "\n    "))
	}
	p.f("  删除策略后可能产生新的未使用对象，下发后请再运行一次 converge\n")
}
