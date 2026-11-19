package cli

import (
	"cmp"
	"errors"
	"fmt"
	"maps"
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
		Long: "审查策略：未使用或为空的对象，不会生效的策略（冗余、被覆盖、禁用、过期、不完整、永不命中），\n" +
			"过宽的放通策略，以及可合并的策略。命中计数（用 firemon hits 为 --snapshot 保存，或 --hits 文件）\n" +
			"提供零命中证据。--plan 把安全项（或 --select 指定的发现）设计为变更，并验证每个判定都不变。",
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
		printCleanupPlan(p, plan, &script)
	}
	return p.err
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
		p.f("\n覆盖分析超出预算的策略：%s\n", strings.Join(rep.Incomplete, ","))
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
		parts = append(parts, zhReason(f.Detail))
	}
	return strings.Join(parts, "；")
}

func printCleanupPlan(p *printer, plan *design.Plan, script *design.Script) {
	p.f("\n变更方案（%d 项，已验证全部判定不变：%s）\n", len(plan.Changes), yesNo(plan.Verified))
	if !plan.Verified {
		// Never print commands that are not proven to keep every decision.
		p.f("  验证未通过：%s。不输出命令；请缩小 --select 范围后重试。\n", cmp.Or(plan.VerifyError, "未验证"))
		return
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
	clusters := groupClusters(fleet)
	p := &printer{w: cmd.OutOrStdout()}
	var out []clusterReview
	for _, c := range slices.Sorted(maps.Keys(clusters)) {
		members := clusters[c]
		snap, err := o.loadStored(cmd.Context(), store, members[0].snapshot)
		if err != nil {
			return fmt.Errorf("集群 %s：%w", c, snapshotError(err, members[0].snapshot, o.store))
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
		review := clusterReview{Cluster: c, Members: memberList(members), Report: rep}
		if f.plan {
			plan, err := converge.Plan(loaded.Firewall, rep, converge.Selection{IDs: f.selection}, converge.PlanOptions{Now: o.deps.Now, Naming: platform.Naming})
			if err != nil {
				return &usageError{fmt.Errorf("集群 %s：%w", c, err)}
			}
			script, err := platform.Render(plan)
			if err != nil {
				return err
			}
			review.Plan, review.Script = plan, scriptOrNil(plan, script)
		}
		if o.json {
			out = append(out, review)
			continue
		}
		p.f("\n══ %s（成员 %s，在 %s 上执行，备机通过 HA 同步）\n", c, memberNames(members), members[0].name)
		printConverge(p, rep)
		if review.Plan != nil {
			printCleanupPlan(p, review.Plan, cmp.Or(review.Script, &design.Script{}))
		}
	}
	if o.json {
		return writeJSON(cmd.OutOrStdout(), out)
	}
	return p.err
}

// groupClusters groups fleet members by cluster, each cluster's active
// member first, then by name: the first is the one reviewed.
func groupClusters(fleet []fleetMember) map[string][]fleetMember {
	clusters := map[string][]fleetMember{}
	for _, m := range fleet {
		c := cmp.Or(m.cluster, m.name)
		clusters[c] = append(clusters[c], m)
	}
	for _, members := range clusters {
		slices.SortFunc(members, func(a, b fleetMember) int {
			return cmp.Or(compareActive(a, b), strings.Compare(a.name, b.name))
		})
	}
	return clusters
}

// clusterReview is the JSON form of one cluster's review.
type clusterReview struct {
	converge.Report
	Cluster string `json:"cluster"`
	// Members are the cluster's members, the reviewed (active) one first.
	Members []string       `json:"members"`
	Plan    *design.Plan   `json:"plan,omitempty"`
	Script  *design.Script `json:"script,omitempty"`
}

func memberList(ms []fleetMember) []string {
	out := make([]string, len(ms))
	for i, m := range ms {
		out[i] = m.name
	}
	return out
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
