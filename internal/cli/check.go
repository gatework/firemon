package cli

import (
	"cmp"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"time"

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
	src, dst, service      string
	fromZone, toZone       string
	nat                    natFlags
	name, description      string
	plan, resolve, verbose bool
	noDesign               bool
	vr, at, schedule       string
	override               bool
}

func newCheckCmd(o *options) *cobra.Command {
	var f checkFlags
	cmd := &cobra.Command{
		Use: "check --src SRC --dst DST --service SERVICE",
		// The former query, design and locate commands asked the same
		// question; their names still work.
		Aliases: []string{"query", "design", "locate"},
		Short:   "查询有没有策略、要不要新增：定位防火墙，给出结论、命中的策略和变更命令",
		Long: "源、目的、服务可以用常见的各种写法输入。在快照中定位经过的防火墙（--inventory 提供 HA 集群和受保护网段），\n" +
			"逐台检查 NAT 与访问控制，给出 完全命中 / 部分命中 / 需要新增策略 / 需确认，列出命中的已有策略，\n" +
			"并设计经过验证的变更与命令（--no-design 只查询；被拒绝策略挡住时新策略放在其前并提示确认）。\n" +
			"-v 显示路径、NAT、输入说明、候选策略和对象完整展开：\n" +
			"  firemon check --src 10.248.30.5 --dst 10.250.116.25 --service 9600\n" +
			"退出码：0 完全命中，3 有已验证的方案待执行，4 需确认，2 用法错误。",
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) > 0 {
				return &usageError{fmt.Errorf("不接受位置参数 %q：请用 --src 源地址 --dst 目的地址 --service 服务", args)}
			}
			return nil
		},
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
	fl.StringVar(&f.vr, "virtual-router", "", "虚拟路由器（默认使用厂商默认值）")
	fl.StringVar(&f.at, "at", "", "按该时刻（RFC 3339）判断时间计划（默认当前时间）")
	fl.StringVar(&f.schedule, "schedule", "", "新建策略使用的已有时间计划")
	fl.BoolVar(&f.override, "override", false, "已不需要：被拒绝策略挡住时新策略会放在其前并提示确认")
	_ = fl.MarkHidden("override")
	fl.StringVar(&f.name, "name", "", "新建策略名称，例如工单号")
	fl.StringVar(&f.description, "description", "", "新建策略描述")
	fl.BoolVar(&f.plan, "design", true, "为每台防火墙设计变更方案与命令")
	fl.BoolVar(&f.noDesign, "no-design", false, "只查询，不设计变更方案")
	fl.BoolVar(&f.resolve, "resolve", false, "解析域名，以便按 IP 写的策略也能判定")
	fl.BoolVarP(&f.verbose, "verbose", "v", false, "显示详情：路径与 NAT、输入说明、按端口推断、候选策略、对象完整展开")
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
		FromZone: f.fromZone, ToZone: f.toZone, VirtualRouter: f.vr,
	}
	if f.at != "" {
		if req.At, err = time.Parse(time.RFC3339, f.at); err != nil {
			return &usageError{fmt.Errorf("--at %q 不是 RFC 3339 时刻，例如 2026-11-18T09:00:00+08:00", f.at)}
		}
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
			Src: in.Src, Dst: in.Dst, Service: in.Service, FromZone: f.fromZone, ToZone: f.toZone, VirtualRouter: f.vr, Schedule: f.schedule,
			// A deny that blocks the request is passed: the new rule goes
			// before it, and the report asks to confirm that is intended.
			Name: f.name, Description: f.description, Override: true, NAT: nat,
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
	} else if err := printReport(cmd, rep, reportView{plans: plans, platforms: platforms, fws: fws, verbose: f.verbose}); err != nil {
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
		// The operator named the firewall: it answers for every address,
		// so no part of the request is set aside as not crossing it.
		everything := inventory.Protection{Firewall: name, Networks: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}}
		inv, err := inventory.New([]inventory.Member{{Name: name, Firewall: loaded.Firewall, Naming: p.Naming}},
			inventory.Options{Now: o.deps.Now, Protections: []inventory.Protection{everything}})
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
	if len(path.AppPorts) > 0 {
		var apps []string
		for _, a := range path.AppPorts {
			for _, n := range a.Applications {
				if !slices.Contains(apps, n) {
					apps = append(apps, n)
				}
			}
		}
		shown := apps[:min(len(apps), 8)]
		more := ""
		if len(apps) > len(shown) {
			more = " 等"
		}
		p.f("    按端口推断：%d 条应用识别策略（%s%s）的应用标准端口不含本次服务，按不命中处理；如该端口实际承载这些应用，请用 --service app:<应用名> 查询\n",
			len(path.AppPorts), strings.Join(shown, "、"), more)
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
