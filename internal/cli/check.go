package cli

import (
	"cmp"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
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
	"github.com/gatework/firemon/traffic"
)

// checkFlags are the inputs of the check command: free-form text the
// operator pastes, read by intake.
type checkFlags struct {
	src, dst, service       string
	fromZone, toZone        string
	nat                     natFlags
	name, description       string
	override, plan, resolve bool
	noDesign                bool
}

func newCheckCmd(o *options) *cobra.Command {
	var f checkFlags
	cmd := &cobra.Command{
		Use:   "check --src SRC --dst DST --service SERVICE",
		Short: "一键查询：定位防火墙，检查 NAT 与访问控制策略，输出命中报告与变更方案",
		Long: "check takes sources, destinations and services in any common form (see intake), locates the\n" +
			"firewalls among the snapshots (--inventory adds HA clusters and protected networks), evaluates\n" +
			"NAT and access control on each, and reports full match, partial match, need new, blocked or\n" +
			"indeterminate, with the best rules to modify, and designs the verified change and commands\n" +
			"(--no-design to skip):\n" +
			"  firemon check --src 10.248.30.5 --dst 10.250.116.25 --service 9600\n" +
			"Exit status: 0 allowed, 3 a verified change is ready, 4 needs confirmation, 2 usage.",
		Args: usageArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			if f.src == "" || f.dst == "" || f.service == "" {
				return &usageError{errors.New("需要 --src 源地址、--dst 目的地址和 --service 服务")}
			}
			if f.noDesign {
				f.plan = false
			}
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
	fl.BoolVar(&f.plan, "design", true, "为每台防火墙输出变更方案与命令（默认开启）")
	fl.BoolVar(&f.noDesign, "no-design", false, "只查询，不设计变更方案")
	fl.BoolVar(&f.resolve, "resolve", false, "解析域名，以便按 IP 写的策略也能判定")
	f.nat.register(fl)
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
	nat, err := f.nat.intent()
	if err != nil {
		return &usageError{err}
	}
	if nat != nil && !f.plan {
		return &usageError{errors.New("--nat 需要设计变更方案，请去掉 --no-design")}
	}
	req := query.Request{
		Src: in.Src, Dst: in.Dst, DstDomains: in.DstDomains, Service: in.Service, Applications: in.Applications,
		FromZone: f.fromZone, ToZone: f.toZone,
	}
	if f.resolve && len(in.DstDomains) > 0 {
		req.Resolved = dns.Resolver{}.Resolve(cmd.Context(), in.DstDomains)
	}
	tr, err := locatePublished(inv, req, nat)
	if err != nil {
		return err
	}
	var plans []inventory.ClusterPlan
	if f.plan && !in.Dst.IsEmpty() {
		intent := design.Intent{
			Src: in.Src, Dst: in.Dst, Service: in.Service, FromZone: f.fromZone, ToZone: f.toZone,
			Name: f.name, Description: f.description, Override: f.override, NAT: nat,
		}
		if plans, err = inv.Plan(intent); err != nil {
			return err
		}
	}
	rep := report.Build(in.Notes, tr, fws, plans)
	if err := attachScripts(&rep, plans, platforms); err != nil {
		return err
	}
	if o.json {
		if err := writeJSON(cmd.OutOrStdout(), rep); err != nil {
			return err
		}
	} else if err := printReport(cmd, rep, plans, platforms); err != nil {
		return err
	}
	return checkExit(rep, f.plan)
}

// attachScripts renders the verified plans so that JSON carries the
// commands and their rollback.
func attachScripts(rep *report.Report, plans []inventory.ClusterPlan, platforms map[string]bootstrap.Platform) error {
	for i := range rep.Firewalls {
		f := &rep.Firewalls[i]
		for _, cp := range plans {
			if cp.Cluster != f.Cluster || cp.Plan == nil || !cp.Plan.Verified || len(cp.Plan.Changes) == 0 {
				continue
			}
			script, err := platforms[cp.Firewall].Render(cp.Plan)
			if err != nil {
				return err
			}
			f.Scripts = append(f.Scripts, script)
		}
	}
	return nil
}

// checkExit maps the result to the exit status: allowed, a verified
// change ready for every firewall that needs one, or a person needed.
func checkExit(rep report.Report, designed bool) error {
	switch rep.Status {
	case report.StatusFullMatch:
		return nil
	case report.StatusUnset:
		return errUndecided // no firewall on the way: nothing to change
	case report.StatusIndeterminate, report.StatusPartialMatch, report.StatusNeedNew, report.StatusBlocked:
	}
	if !designed {
		if rep.Status == report.StatusIndeterminate {
			return errUndecided
		}
		return errNotAllowed
	}
	// Undecided traffic is settled by a verified plan without unknown
	// parts: it permits the request whatever the undecidable rules do.
	for _, f := range rep.Firewalls {
		if f.Status == report.StatusFullMatch {
			continue
		}
		if f.Plan == nil || !f.Plan.Verified || len(f.Plan.Conflicts) > 0 || len(f.Plan.Unknown) > 0 {
			return errUndecided
		}
	}
	return errNotAllowed
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
		name := cmp.Or(o.snapshot, loaded.Config.Hostname, "firewall")
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
	// Later books win on name clashes: merge in a fixed order so that the
	// result does not depend on map iteration.
	for _, name := range slices.Sorted(maps.Keys(platforms)) {
		p := platforms[name]
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
	for _, in := range rep.Inside {
		p.f("源与目的同在 %s 的 %s 区域一侧，不经过该防火墙：%s\n", in.Cluster, in.Zone, in.Traffic)
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
			outcome := "拒绝"
			if h.Final == query.OutcomePermit {
				outcome = "放通"
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
	for _, ref := range path.NATSkipped {
		p.f("    已跳过禁用的 NAT 规则 %s\n", ref.ID())
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
	if f.Status == report.StatusFullMatch {
		p.f("  ▶ 处置：已放通，无需变更\n")
		return
	}
	designed := false
	for _, cp := range plans {
		if cp.Cluster != f.Cluster || cp.Plan == nil {
			continue
		}
		designed = true
		printNATOutcome(p, cp.Plan.NAT)
		for _, c := range cp.Plan.Conflicts {
			p.f("  设计冲突：策略 %s 拒绝 %s（%s → %s），未自动放在其前；确认后加 --override\n", c.RuleID, c.Text, c.From, c.To)
		}
		for _, u := range cp.Plan.Unknown {
			p.f("  无法设计：%s\n", planNote(u))
		}
		for _, w := range cp.Plan.Warnings {
			p.f("  注意：%s\n", planNote(w))
		}
		if len(cp.Plan.Changes) == 0 {
			continue
		}
		if !cp.Plan.Verified {
			p.f("  ▶ 处置：需确认，方案验证未通过（%s），不输出命令\n", cmp.Or(cp.Plan.VerifyError, "未验证"))
			continue
		}
		script, err := platforms[cp.Firewall].Render(cp.Plan)
		if err != nil {
			p.f("  ▶ 处置：需确认，方案无法生成命令：%v\n", err)
			continue
		}
		p.f("  ▶ 处置：在 %s 上执行以下命令%s（已验证：只放通本次请求）\n", cp.Firewall, haNote(f.Members, cp.Firewall))
		for _, c := range cp.Plan.Changes {
			p.f("    · %s\n", c)
		}
		for _, c := range script.Commands {
			p.f("    %s\n", c)
		}
		p.f("    回退命令：\n")
		for _, c := range script.Rollback {
			p.f("    %s\n", c)
		}
	}
	if !designed {
		p.f("  ▶ 处置：%s（去掉 --no-design 可生成变更方案）\n", text(statusText, f.Status, f.Status.String()))
	}
}

// haNote names the cluster members that receive the change through HA
// synchronization.
func haNote(members []string, on string) string {
	others := slices.DeleteFunc(slices.Clone(members), func(m string) bool { return m == on })
	if len(others) == 0 {
		return ""
	}
	return "，" + strings.Join(others, "、") + " 通过 HA 同步"
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

// printNATOutcome writes the NAT part of a plan.
func printNATOutcome(p *printer, n *design.NATOutcome) {
	if n == nil {
		return
	}
	line := "  NAT 设计：" + text(natStatusText, n.Status, n.Status.String())
	switch {
	case len(n.Existing) > 0 && n.Status == design.NATStatusConflict:
		line += "，NAT 规则 " + strings.Join(n.Existing, ",") + " 排在前面，已把该地址端口映射到其他服务器"
	case len(n.Existing) > 0:
		line += "，已由 NAT 规则 " + strings.Join(n.Existing, ",") + " 按顺序首条命中完成"
	case n.Rule != "":
		line += "，新增规则 " + n.Rule
		if n.Before != "" {
			line += "，放在规则 " + n.Before + " 之前（NAT 按顺序匹配，越靠前越优先）"
		} else {
			line += "，放在列表末尾"
		}
	}
	if n.Address != "" {
		line += "，地址 " + n.Address
	}
	if n.Interface != "" {
		line += "，使用 " + n.Interface + " 接口地址"
	}
	if n.Reused {
		line += "（复用已有 NAT 地址）"
	}
	if n.Reason != "" {
		line += "：" + n.Reason
	}
	p.f("%s\n", line)
}

// locatePublished locates the request as clients send it: to the published
// address when destination or static NAT already maps it, else to the
// server itself (an unpublished address ends at the firewall).
func locatePublished(inv *inventory.Inventory, req query.Request, nat *design.NATIntent) (inventory.Trace, error) {
	if nat != nil && nat.Mode != design.NATModeSource && nat.Address.IsValid() {
		pub := req
		svc, err := design.PublishedService(req.Service, nat.Port)
		if err != nil {
			return inventory.Trace{}, &usageError{err}
		}
		pub.Dst, pub.Service = traffic.NewAddressSet(netip.PrefixFrom(nat.Address, nat.Address.BitLen())), svc
		if tr, err := inv.Locate(pub); err != nil || len(tr.Crossings) > 0 {
			return tr, err
		}
	}
	return inv.Locate(req)
}
