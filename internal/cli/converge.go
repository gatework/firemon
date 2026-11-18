package cli

import (
	"cmp"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/gatework/firemon/adapter/filestore"
	"github.com/gatework/firemon/converge"
	"github.com/gatework/firemon/design"
	"github.com/gatework/firemon/hits"
	"github.com/gatework/firemon/internal/bootstrap"
	"github.com/gatework/firemon/internal/workflow"
)

type convergeFlags struct {
	hitsFile  string
	minWindow time.Duration
	plan      bool
	selection []string
}

func newConvergeCmd(o *options) *cobra.Command {
	var f convergeFlags
	cmd := &cobra.Command{
		Use:   "converge",
		Short: "策略收敛：未使用对象、无效策略、过宽放通、可合并策略，安全项输出变更与回退命令",
		Long: "converge reviews the policy: unused or empty objects, rules that never take effect (redundant,\n" +
			"shadowed, disabled, expired, incomplete, never matching), broad permits and rules that can merge.\n" +
			"Hit counters (stored with `firemon hits` for --snapshot, or --hits FILE) add zero-hit evidence.\n" +
			"--plan designs the Safe findings (or --select IDs) as changes verified to keep every decision.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return o.converge(cmd, f)
		},
	}
	fl := cmd.Flags()
	fl.StringVar(&f.hitsFile, "hits", "", "命中计数文件（JSON 或 CSV）；默认使用快照库中该快照最新的计数")
	fl.DurationVar(&f.minWindow, "min-window", converge.DefaultMinWindow, "判定零命中所需的最短观察时长")
	fl.BoolVar(&f.plan, "plan", false, "为安全项生成变更方案、命令与回退命令")
	fl.StringSliceVar(&f.selection, "select", nil, "只处理这些发现（ID，见报告）；默认全部安全项")
	return cmd
}

func (o *options) converge(cmd *cobra.Command, f convergeFlags) error {
	if o.inventoryFile != "" {
		return o.convergeFleet(cmd, f)
	}
	loaded, platform, err := o.load(cmd.Context())
	if err != nil {
		return err
	}
	counters, err := o.counters(cmd, f.hitsFile)
	if err != nil {
		return err
	}
	rep := converge.Analyze(loaded.Firewall, converge.Options{Now: o.deps.Now, Hits: counters, MinWindow: f.minWindow})
	var plan *design.Plan
	var script design.Script
	if f.plan {
		plan, err = converge.Plan(loaded.Firewall, rep, converge.Selection{IDs: f.selection}, converge.PlanOptions{Now: o.deps.Now, Naming: platform.Naming})
		if err != nil {
			return &usageError{err}
		}
		if script, err = platform.Render(plan); err != nil {
			return err
		}
	}
	if o.json {
		return writeJSON(cmd.OutOrStdout(), struct {
			converge.Report
			Plan   *design.Plan   `json:"plan,omitempty"`
			Script *design.Script `json:"script,omitempty"`
		}{rep, plan, scriptOrNil(plan, script)})
	}
	p := &printer{w: cmd.OutOrStdout()}
	printConverge(p, rep)
	if plan != nil {
		printCleanupPlan(p, plan, script)
	}
	return p.err
}

func scriptOrNil(plan *design.Plan, s design.Script) *design.Script {
	if plan == nil {
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
	store, err := filestore.New(o.store)
	if err != nil {
		return nil, err
	}
	snap, err := store.LatestHits(cmd.Context(), o.snapshot)
	if errors.Is(err, filestore.ErrNotFound) {
		return nil, nil //nolint:nilnil // no counters collected yet
	}
	return &snap, err
}

func printConverge(p *printer, rep converge.Report) {
	counts := map[converge.Category]int{}
	for _, f := range rep.Findings {
		counts[f.Category]++
	}
	p.f("策略收敛报告")
	if !rep.HitsTaken.IsZero() {
		p.f("（命中计数采集于 %s）", rep.HitsTaken.Format("2006-01-02 15:04"))
	}
	p.f("\n")
	last := converge.CategoryUnset
	for _, f := range rep.Findings {
		if f.Category != last {
			last = f.Category
			p.f("\n■ %s（%d 项）\n", text(categoryText, f.Category, f.Category.String()), counts[f.Category])
		}
		p.f("  [%s|%s] %s %s\n", text(tierText, f.Tier, f.Tier.String()), text(evidenceText, f.Evidence, f.Evidence.String()), f.ID, findingText(f))
	}
	if len(rep.Incomplete) > 0 {
		p.f("\n遮蔽分析超出预算的策略：%s\n", strings.Join(rep.Incomplete, ","))
	}
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
		parts = append(parts, f.Detail)
	}
	return strings.Join(parts, "；")
}

func printCleanupPlan(p *printer, plan *design.Plan, script design.Script) {
	p.f("\n变更方案（%d 项，有效策略不变已验证：%v）\n", len(plan.Changes), plan.Verified)
	if plan.VerifyError != "" {
		p.f("  验证未通过：%s（不要下发）\n", plan.VerifyError)
	}
	if len(script.Commands) == 0 {
		return
	}
	p.f("命令：\n  %s\n回退命令：\n  %s\n", strings.Join(script.Commands, "\n  "), strings.Join(script.Rollback, "\n  "))
	p.f("删除策略后可能产生新的未使用对象，下发后请再运行一次 converge。\n")
}

// convergeFleet reviews every cluster of --inventory on its active member
// (or the first by name), with the hit counters of all its members merged: a rule unused
// on the active member may carry the standby's traffic after a failover.
func (o *options) convergeFleet(cmd *cobra.Command, f convergeFlags) error {
	store, err := filestore.New(o.store)
	if err != nil {
		return err
	}
	fleet, _, err := o.fleet(cmd, store)
	if err != nil {
		return err
	}
	clusters := map[string][]fleetMember{}
	var order []string
	for _, m := range fleet {
		c := cmp.Or(m.cluster, m.name)
		if _, ok := clusters[c]; !ok {
			order = append(order, c)
		}
		clusters[c] = append(clusters[c], m)
	}
	slices.Sort(order)
	p := &printer{w: cmd.OutOrStdout()}
	for _, c := range order {
		members := clusters[c]
		// The active member first, then by name: it is the one reviewed.
		slices.SortFunc(members, func(a, b fleetMember) int {
			return cmp.Or(compareActive(a, b), strings.Compare(a.name, b.name))
		})
		snap, err := store.Load(cmd.Context(), members[0].snapshot)
		if err != nil {
			return fmt.Errorf("cluster %s: %w", c, err)
		}
		loaded, err := workflow.FromConfig(snap.Config)
		if err != nil {
			return err
		}
		platform, err := bootstrap.Lookup(snap.Vendor, snap.Config.Location, nil)
		if err != nil {
			return err
		}
		counters, err := clusterHits(cmd, store, c, members)
		if err != nil {
			return err
		}
		rep := converge.Analyze(loaded.Firewall, converge.Options{Now: o.deps.Now, Hits: counters, MinWindow: f.minWindow})
		p.f("\n══ %s（成员 %s）\n", c, memberNames(members))
		printConverge(p, rep)
		if !f.plan {
			continue
		}
		plan, err := converge.Plan(loaded.Firewall, rep, converge.Selection{IDs: f.selection}, converge.PlanOptions{Now: o.deps.Now, Naming: platform.Naming})
		if err != nil {
			return &usageError{fmt.Errorf("cluster %s: %w", c, err)}
		}
		script, err := platform.Render(plan)
		if err != nil {
			return err
		}
		printCleanupPlan(p, plan, script)
	}
	return p.err
}

// clusterHits merges the latest counters of the members that have any;
// nil when none has.
func clusterHits(cmd *cobra.Command, store *filestore.Store, cluster string, members []fleetMember) (*hits.Snapshot, error) {
	var snaps []hits.Snapshot
	for _, m := range members {
		s, err := store.LatestHits(cmd.Context(), m.snapshot)
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
	merged := hits.Merge(cluster, snaps...)
	return &merged, nil
}

func memberNames(members []fleetMember) string {
	names := make([]string, len(members))
	for i, m := range members {
		names[i] = m.name
	}
	return strings.Join(names, ",")
}

func compareActive(a, b fleetMember) int {
	switch {
	case a.active == b.active:
		return 0
	case a.active:
		return -1
	default:
		return 1
	}
}
