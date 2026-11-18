package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/adapter/dns"
	"github.com/gatework/firemon/design"
	"github.com/gatework/firemon/intake"
	"github.com/gatework/firemon/internal/bootstrap"
	"github.com/gatework/firemon/inventory"
	"github.com/gatework/firemon/query"
	"github.com/gatework/firemon/report"
)

// checkFlags are the inputs of the check command: free-form text the
// operator pastes, read by intake.
type checkFlags struct {
	src, dst, service       string
	fromZone, toZone        string
	name, description       string
	override, plan, resolve bool
}

func newCheckCmd(o *options) *cobra.Command {
	var f checkFlags
	cmd := &cobra.Command{
		Use:   "check",
		Short: "一键查询：定位防火墙，检查 NAT 与访问控制策略，输出命中报告与变更方案",
		Long: "check takes sources, destinations and services in any common form (see intake), locates the\n" +
			"firewalls among the snapshots (--inventory adds HA clusters and protected networks), evaluates\n" +
			"NAT and access control on each, and reports full match, partial match, need new, blocked or\n" +
			"indeterminate, with the best rules to modify. --design adds the verified change and commands.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return o.check(cmd, f)
		},
	}
	fl := cmd.Flags()
	fl.StringVar(&f.src, "src", "", "源地址：IP、网段、范围、IP+掩码，任意分隔")
	fl.StringVar(&f.dst, "dst", "", "目的地址：同上，也可以是域名")
	fl.StringVar(&f.service, "service", "", "服务：443、tcp 80、80/udp、https、ping、app:ssh …")
	fl.StringVar(&f.fromZone, "from-zone", "", "源区域（透明模式或无法按路由定位时指定）")
	fl.StringVar(&f.toZone, "to-zone", "", "目的区域")
	fl.StringVar(&f.name, "name", "", "新建策略名称，例如工单号")
	fl.StringVar(&f.description, "description", "", "新建策略描述")
	fl.BoolVar(&f.override, "override", false, "允许新策略放在具体拒绝策略之前")
	fl.BoolVar(&f.plan, "design", false, "为每台防火墙输出变更方案与命令")
	fl.BoolVar(&f.resolve, "resolve", false, "解析域名，以便按 IP 写的策略也能判定")
	return cmd
}

func (o *options) check(cmd *cobra.Command, f checkFlags) error {
	inv, platforms, fws, err := o.checkFleet(cmd)
	if err != nil {
		return err
	}
	in, err := intake.Parse(f.src, f.dst, f.service, intakeOptions(platforms))
	if err != nil {
		printNotes(&printer{w: cmd.OutOrStdout()}, in.Notes)
		return &usageError{err}
	}
	req := query.Request{
		Src: in.Src, Dst: in.Dst, DstDomains: in.DstDomains, Service: in.Service, Applications: in.Applications,
		FromZone: f.fromZone, ToZone: f.toZone,
	}
	if f.resolve && len(in.DstDomains) > 0 {
		req.Resolved = dns.Resolver{}.Resolve(cmd.Context(), in.DstDomains)
	}
	tr, err := inv.Locate(req)
	if err != nil {
		return err
	}
	var plans []inventory.ClusterPlan
	if f.plan && !in.Dst.IsEmpty() {
		intent := design.Intent{
			Src: in.Src, Dst: in.Dst, Service: in.Service, FromZone: f.fromZone, ToZone: f.toZone,
			Name: f.name, Description: f.description, Override: f.override,
		}
		if plans, err = inv.Plan(intent); err != nil {
			return err
		}
	}
	rep := report.Build(in.Notes, tr, fws, plans)
	if o.json {
		return writeJSON(cmd.OutOrStdout(), rep)
	}
	if err := printReport(cmd, rep, plans, platforms); err != nil {
		return err
	}
	if rep.Status != report.StatusFullMatch {
		return errNotAllowed
	}
	return nil
}

// checkFleet loads the inventory: one firewall from --config or --snapshot,
// or the whole snapshot store.
func (o *options) checkFleet(cmd *cobra.Command) (*inventory.Inventory, map[string]bootstrap.Platform, map[string]*firemon.Firewall, error) {
	fws := map[string]*firemon.Firewall{}
	if o.file != "" || o.snapshot != "" || o.device.host != "" {
		loaded, p, err := o.load(cmd.Context())
		if err != nil {
			return nil, nil, nil, err
		}
		name := firstNonEmpty(o.snapshot, loaded.Config.Hostname, "firewall")
		inv, err := inventory.New([]inventory.Member{{Name: name, Firewall: loaded.Firewall, Naming: p.Naming}}, inventory.Options{Now: o.deps.Now})
		fws[name] = loaded.Firewall
		return inv, map[string]bootstrap.Platform{name: p}, fws, err
	}
	inv, platforms, err := o.inventory(cmd)
	if err != nil {
		return nil, nil, nil, err
	}
	for _, name := range inv.Clusters() {
		fws[name] = inv.Firewall(name)
	}
	return inv, platforms, fws, nil
}

// intakeOptions reads service and application names with the books of
// every platform in the fleet.
func intakeOptions(platforms map[string]bootstrap.Platform) intake.Options {
	services := firemon.ServiceBook{}
	apps := firemon.ServiceBook{}
	for _, p := range platforms {
		services = services.With(p.Services)
		apps = apps.With(p.Applications)
	}
	return intake.Options{Services: services, IsApplication: func(name string) bool {
		_, ok := apps.Lookup(name)
		return ok
	}}
}

func printNotes(p *printer, notes []intake.Note) {
	for _, n := range notes {
		line := "  " + text(fieldText, n.Field, string(n.Field)) + " " + n.Input + "：" + text(noteText, n.Code, n.Code.String())
		if n.Result != "" && !n.Skipped() {
			line += " → " + n.Result
		}
		p.f("%s\n", line)
	}
}

func printReport(cmd *cobra.Command, rep report.Report, plans []inventory.ClusterPlan, platforms map[string]bootstrap.Platform) error {
	p := &printer{w: cmd.OutOrStdout()}
	p.f("结论：%s\n", text(statusText, rep.Status, rep.Status.String()))
	if len(rep.Notes) > 0 {
		p.f("\n输入说明：\n")
		printNotes(p, rep.Notes)
	}
	if rep.Excluded.Src != "" || rep.Excluded.Dst != "" {
		p.f("\n未经过任何防火墙（已剔除）：源 %s  目的 %s\n", orDash(rep.Excluded.Src), orDash(rep.Excluded.Dst))
	}
	for _, name := range rep.ZonesNeeded {
		p.f("提示：%s 有透明模式（二层）接口，经二层转发的流量无法按路由定位，请用 --from-zone/--to-zone 指定区域\n", name)
	}
	for _, a := range rep.Ambiguous {
		p.f("归属不唯一（多个防火墙同等声明，均已检查）：%s\n", a)
	}
	for _, f := range rep.Firewalls {
		printFirewall(p, f)
		printPlan(p, f, plans, platforms)
	}
	return p.err
}

func printFirewall(p *printer, f report.Firewall) {
	p.f("\n■ %s（%s，成员 %s）：%s\n", f.Cluster, text(ownershipText, f.Ownership, f.Ownership.String()),
		strings.Join(f.Members, ","), text(statusText, f.Status, f.Status.String()))
	for _, path := range f.Paths {
		printPath(p, path)
	}
	hits := func(title string, hs []report.Hit) {
		for _, h := range hs {
			p.f("  %s %s %s：%s\n", title, h.Rule, h.Name, h.Traffic)
		}
	}
	hits("放通策略", f.Permitted)
	hits("拒绝策略", f.Blocked)
	if len(f.Undecided) > 0 {
		names := make([]string, 0, len(f.Undecided))
		for _, h := range f.Undecided {
			kinds := make([]string, len(h.Reasons))
			for i, k := range h.Reasons {
				kinds[i] = text(issueKindText, k, k)
			}
			names = append(names, h.Rule+" "+h.Name+"（"+strings.Join(kinds, "、")+"）")
		}
		p.f("  待确认流量：%s\n  可能先命中的策略：%s\n", f.UndecidedTraffic, strings.Join(names, "，"))
		for _, h := range f.Otherwise {
			outcome := "放通"
			if len(h.Reasons) > 0 && h.Reasons[0] != "permit" {
				outcome = "拒绝"
			}
			p.f("  若这些策略都不命中：由 %s %s %s\n", h.Rule, h.Name, outcome)
		}
	}
	if f.Remaining != "" {
		p.f("  未放通部分：%s\n", f.Remaining)
	}
	if f.Unrouted != "" {
		p.f("  无路由（被丢弃）的目的：%s\n", f.Unrouted)
	}
	if f.Incomplete {
		p.f("  评估超出预算被截断，结论仅覆盖已评估部分，按无法判定处理\n")
	}

	for _, c := range f.Candidates {
		mark := "候选"
		if c.Recommended {
			mark = "推荐修改"
		}
		reasons := make([]string, len(c.Reasons))
		for i, r := range c.Reasons {
			reasons[i] = text(reasonText, r, string(r))
		}
		p.f("  %s %s %s：源%s 目的%s 服务%s %s\n", mark, c.Rule, c.Name, text(relationText, c.Src, c.Src.String()),
			text(relationText, c.Dst, c.Dst.String()), text(relationText, c.Service, c.Service.String()), strings.Join(reasons, "；"))
	}
}

func printPath(p *printer, path report.Path) {
	target := ""
	if path.Domain != "" {
		target += " 域名 " + path.Domain
	}
	if path.Application != "" {
		target += " 应用 " + path.Application
	}
	p.f("  路径 %s → %s%s：%s\n", zoneIface(path.From, path.Ingress), zoneIface(path.To, path.Egress), target, text(verdictText, path.Verdict, path.Verdict.String()))
	if path.PolicyRoute != "" {
		p.f("    策略路由 %s 选择出口\n", path.PolicyRoute)
	}
	for _, c := range path.Conditions {
		p.f("    前提：%s\n", conditionText(c))
	}
	for _, id := range path.NATSkipped {
		p.f("    已跳过禁用的 %s\n", id)
	}
	for _, n := range path.NAT {
		if n.Uncertain {
			p.f("    NAT %s 可能生效，无法判定\n", n.Rule)
			continue
		}
		order := ""
		if n.Position > 0 {
			order = fmt.Sprintf("（第 %d 条，按顺序首条命中）", n.Position)
		}
		p.f("    %s %s%s：%s → %s\n", text(natSideText, n.Side, n.Side.String()), n.Rule, order, orDash(n.Traffic), n.Translated)
	}
}

func printPlan(p *printer, f report.Firewall, plans []inventory.ClusterPlan, platforms map[string]bootstrap.Platform) {
	for _, cp := range plans {
		if cp.Cluster != f.Cluster || cp.Plan == nil || len(cp.Plan.Changes) == 0 {
			continue
		}
		script, err := platforms[cp.Firewall].Render(cp.Plan)
		if err != nil {
			p.f("  方案无法生成命令：%v\n", err)
			continue
		}
		p.f("  变更方案（已验证：%v）：\n", cp.Plan.Verified)
		for _, c := range script.Commands {
			p.f("    %s\n", c)
		}
		p.f("  回退命令：\n")
		for _, c := range script.Rollback {
			p.f("    %s\n", c)
		}
	}
}

// conditionText renders a path condition.
func conditionText(c query.Condition) string {
	if c.Matches {
		return "策略路由 " + c.PolicyRoute + " 命中（含无法离线判定的条件，如用户组）"
	}
	return "策略路由 " + c.PolicyRoute + " 不命中"
}

func zoneIface(zone, iface string) string {
	if iface == "" {
		return orDash(zone)
	}
	return orDash(zone) + "(" + iface + ")"
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
