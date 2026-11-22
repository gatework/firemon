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
	src, dst, service    string
	fromZone, toZone     string
	nat                  natFlags
	name, description    string
	plan, resolve        bool
	verbosity            int
	noDesign             bool
	vr, at, schedule     string
	noLog                bool
	strict               bool
	users, urlCategories []string
	until                string
	file, format         string
}

func newCheckCmd(o *options) *cobra.Command {
	var f checkFlags
	cmd := &cobra.Command{
		Use:   "search --src SRC --dst DST --service SERVICE",
		Short: "查询有没有策略、要不要新增：定位防火墙，给出结论、命中的策略和变更命令",
		Long: "源、目的、服务可以用常见的各种写法输入。在快照中定位经过的防火墙（--inventory 提供 HA 集群和受保护网段），\n" +
			"逐台检查 NAT 与访问控制，给出 完全命中 / 部分命中 / 需要新增策略 / 需确认，列出命中的已有策略，\n" +
			"并设计经过验证的变更与命令（--no-design 只查询；被拒绝策略挡住时新策略放在其前并提示确认）。\n" +
			"默认按防火墙给出脚本：已有放通策略（设备配置写法），或需新增、修改的策略脚本与回退；-v 显示推理过程（命中依据、前提说明、风险与未选修改的原因）；\n" +
			"-vv 再显示路径、NAT、输入说明、候选策略和对象完整展开：\n" +
			"  firemon search --src 10.248.30.5 --dst 10.250.116.25 --service 9600\n" +
			"退出码：0 完全命中或无需策略，3 需新增或修改（已给出验证过的方案；--no-design 时未设计），4 需确认，2 输入、参数或文件错误，1 运行错误。",
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) > 0 {
				return &usageError{fmt.Errorf("不接受位置参数 %q：请用 --src 源地址 --dst 目的地址 --service 服务", args)}
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			if f.file == "" && (f.src == "" || f.dst == "" || f.service == "") {
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
	fl.StringVar(&f.file, "file", "", "批量工单：CSV 文件，每行 工单号,源,目的,服务[,源区域,目的区域,有效期,描述]，首行可为表头；逐单查询并设计，同一设备上的工单依次叠加")
	fl.StringVar(&f.format, "format", "", "输出格式：text（默认）、markdown（可直接贴进工单）、json")
	fl.StringVar(&f.until, "until", "", "限时开通：新建策略到该时刻失效，如 2026-12-31（当天 23:59 止）或 2026-12-31T18:00")
	fl.BoolVar(&f.noLog, "no-log", false, "新建策略不开启日志（默认记录会话开始和结束）")
	fl.StringVar(&f.name, "name", "", "新建策略名称，例如工单号（默认 P-日期-序号，如 P-20261118-001）")
	fl.StringVar(&f.description, "description", "", "新建策略描述（默认 名称-By-Firemon）")
	fl.BoolVar(&f.plan, "design", true, "为每台防火墙设计变更方案与命令")
	fl.BoolVar(&f.noDesign, "no-design", false, "只查询，不设计变更方案")
	fl.BoolVar(&f.resolve, "resolve", false, "解析域名，以便按 IP 写的策略也能判定")
	fl.BoolVar(&f.strict, "strict", false, "保守判定：按应用、用户、URL 分类匹配的策略一律视为可能命中（默认按端口识别标准应用，用户与 URL 分类未给出时视为不命中，并列为前提）")
	fl.StringSliceVar(&f.users, "user", nil, "源的用户、用户组或角色，用于判定按用户匹配的策略（可多个，逗号分隔）")
	fl.StringSliceVar(&f.urlCategories, "url-category", nil, "请求的 URL 分类，用于判定按 URL 分类匹配的策略")
	fl.CountVarP(&f.verbosity, "verbose", "v", "推理过程：-v 命中策略详情、前提说明、风险与未选修改的原因、完整策略定义；-vv 再加路径、NAT、输入说明、候选策略、对象展开，列表不截断")
	f.nat.register(fl)
	return cmd
}

func (o *options) check(cmd *cobra.Command, f checkFlags) error {
	format, err := o.outputFormat(f.format)
	if err != nil {
		return err
	}
	inv, platforms, fws, err := o.checkFleet(cmd)
	if err != nil {
		return err
	}
	if f.file != "" {
		return o.batch(cmd, f, format, inv, platforms)
	}
	a, err := o.answer(cmd, f, inv, platforms, fws)
	if err != nil {
		return err
	}
	view := reportView{plans: a.plans, platforms: platforms, fws: fws, detail: f.verbosity >= 1, verbose: f.verbosity >= 2, single: o.single()}
	if err := writeReport(cmd, format, a.rep, view); err != nil {
		return err
	}
	return checkExit(a.rep, f.plan)
}

// answer is one request answered: the report and the plans behind it.
type answer struct {
	rep   report.Report
	plans []inventory.ClusterPlan
}

// answer locates the request of f across inv, designs the changes it
// needs and builds the report, scripts attached.
func (o *options) answer(cmd *cobra.Command, f checkFlags, inv *inventory.Inventory, platforms map[string]bootstrap.Platform, fws map[string]*firemon.Firewall) (answer, error) {
	in, err := intake.Parse(f.src, f.dst, f.service, intakeOptions(platforms, fws))
	if err != nil {
		if f.file == "" {
			printNotes(&printer{w: cmd.OutOrStdout()}, in.Notes)
		}
		return answer{}, &usageError{err}
	}
	nat, err := f.nat.intent()
	if err != nil {
		return answer{}, &usageError{err}
	}
	if nat != nil && !f.plan {
		return answer{}, &usageError{errors.New("--nat 需要设计变更方案，请去掉 --no-design")}
	}
	req := query.Request{
		Src: in.Src, Dst: in.Dst, DstDomains: in.DstDomains, Service: in.Service, Applications: in.Applications,
		FromZone: f.fromZone, ToZone: f.toZone, VirtualRouter: f.vr,
		Strict: f.strict, Users: f.users, URLCategories: f.urlCategories,
	}
	if f.at != "" {
		if req.At, err = time.Parse(time.RFC3339, f.at); err != nil {
			return answer{}, &usageError{fmt.Errorf("--at %q 不是 RFC 3339 时刻，例如 2026-11-18T09:00:00+08:00", f.at)}
		}
	}
	if f.resolve && len(in.DstDomains) > 0 {
		req.Resolved = dns.Resolver{}.Resolve(cmd.Context(), in.DstDomains)
	}
	tr, err := locatePublished(inv, req, nat)
	if err != nil {
		return answer{}, err
	}
	until, err := o.untilTime(f.until)
	if err != nil {
		return answer{}, err
	}
	var plans []inventory.ClusterPlan
	if f.plan && !in.Dst.IsEmpty() {
		intent := design.Intent{
			Src: in.Src, Dst: in.Dst, Service: in.Service, FromZone: f.fromZone, ToZone: f.toZone, VirtualRouter: f.vr, Schedule: f.schedule,
			NoLog: f.noLog, LogSetting: o.logSetting,
			// A deny that blocks the request is passed: the new rule goes
			// before it, and the report asks to confirm that is intended.
			Name: f.name, Description: f.description, Override: true, NAT: nat,
			Strict: f.strict, Users: f.users, URLCategories: f.urlCategories, Until: until,
		}
		if plans, err = inv.Plan(intent); err != nil {
			return answer{}, err
		}
	}
	rep := report.Build(in.Notes, tr, fws, plans)
	rep = rep.WithFlows(report.Flows(tr, fws, in.SrcItems, in.DstItems, in.Service))
	if err := attachScripts(&rep, plans, platforms); err != nil {
		return answer{}, err
	}
	return answer{rep: rep, plans: plans}, nil
}

// Output formats of search.
const (
	formatText     = "text"
	formatMarkdown = "markdown"
	formatJSON     = "json"
)

// outputFormat reads --format; --json chooses JSON as before.
func (o *options) outputFormat(f string) (string, error) {
	if o.json {
		return formatJSON, nil
	}
	switch f {
	case "", formatText:
		return formatText, nil
	case formatMarkdown, "md":
		return formatMarkdown, nil
	case formatJSON:
		return formatJSON, nil
	default:
		return "", &usageError{fmt.Errorf("--format %q：可选 text、markdown、json", f)}
	}
}

// writeReport writes one report in the chosen format.
func writeReport(cmd *cobra.Command, format string, rep report.Report, view reportView) error {
	switch format {
	case formatJSON:
		return writeJSON(cmd.OutOrStdout(), rep)
	case formatMarkdown:
		return printMarkdown(cmd.OutOrStdout(), rep, view)
	default:
		if !view.detail {
			return printBrief(cmd.OutOrStdout(), rep, view)
		}
		return printReport(cmd, rep, view)
	}
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
		if rep.Settled() {
			return nil // both ends in one zone: no rule decides it
		}
		return errUndecided // ends the inventory does not cover
	case report.StatusIndeterminate, report.StatusPartialMatch, report.StatusNeedNew, report.StatusBlocked:
		if len(rep.Firewalls) == 0 {
			return errUndecided // firewalls the request may cross were not evaluated
		}
	}
	if !designed {
		if rep.Status == report.StatusIndeterminate || slices.ContainsFunc(rep.Firewalls, undecided) {
			return errUndecided
		}
		return errNotAllowed
	}
	if !planned(rep) {
		return errUndecided
	}
	return errNotAllowed
}

// planned reports that every firewall the request needs a change on has a
// verified plan without conflicts or unknown parts. Undecided traffic is
// then settled: the plan permits the request whatever the undecidable
// rules do.
func planned(rep report.Report) bool {
	for _, f := range rep.Firewalls {
		if f.Status != report.StatusFullMatch && !settledByPlan(f) {
			return false
		}
	}
	return len(rep.Firewalls) > 0
}

// settledByPlan reports a verified plan without conflicts or unknown parts
// on the firewall.
func settledByPlan(f report.Firewall) bool {
	return f.Plan != nil && f.Plan.Verified && len(f.Plan.Conflicts) == 0 && len(f.Plan.Unknown) == 0
}

// undecided reports a firewall where rules that cannot be evaluated
// offline may decide part of the request.
func undecided(f report.Firewall) bool {
	return f.Incomplete || len(f.Undecided) > 0 || len(f.ZoneConflicts) > 0
}

// single reports a command run on one firewall named by --config,
// --snapshot or --host rather than on the inventory.
func (o *options) single() bool { return o.file != "" || o.snapshot != "" || o.device.host != "" }

// checkFleet loads the inventory: one firewall from --config or --snapshot,
// or the whole snapshot store.
func (o *options) checkFleet(cmd *cobra.Command) (*inventory.Inventory, map[string]bootstrap.Platform, map[string]*firemon.Firewall, error) {
	fws := map[string]*firemon.Firewall{}
	if o.single() {
		loaded, p, err := o.load(cmd.Context())
		if err != nil {
			return nil, nil, nil, err
		}
		name := cmp.Or(o.snapshot, loaded.Config.Hostname, "firewall")
		// The operator named the firewall: it answers for every address,
		// so no part of the request is set aside as not crossing it.
		everything := inventory.Protection{Firewall: name, Networks: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}}
		inv, err := inventory.New([]inventory.Member{{Name: name, Firewall: loaded.Firewall, Naming: p.Naming, Capabilities: p.Capabilities}},
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
func intakeOptions(platforms map[string]bootstrap.Platform, fws map[string]*firemon.Firewall) intake.Options {
	services := firemon.ServiceBook{}
	apps := firemon.ServiceBook{}
	// Later books win on name clashes: merge in a fixed order so that the
	// result does not depend on map iteration.
	for _, name := range slices.Sorted(maps.Keys(platforms)) {
		p := platforms[name]
		services = services.With(p.Services)
		apps = apps.With(p.Applications)
	}
	// Applications the rules name are known too, with or without ports.
	named := map[string]bool{}
	for _, fw := range fws {
		if fw == nil {
			continue
		}
		for _, r := range fw.Rules() {
			for _, a := range r.Spec().Applications() {
				named[strings.ToLower(a)] = true
			}
		}
	}
	return intake.Options{Services: services, IsApplication: func(name string) bool {
		_, ok := apps.Lookup(name)
		return ok || named[strings.ToLower(name)]
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
	if path.VirtualRouter != "" {
		target += " 虚拟路由 " + path.VirtualRouter
		if path.EgressVirtualRouter != "" && path.EgressVirtualRouter != path.VirtualRouter {
			target += " → " + path.EgressVirtualRouter
		}
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
		p.f("    %d 条 application-default 策略（%s%s）的已知默认端口排除了本次请求中的部分服务\n",
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
func haNote(devices []inventory.Device, on string) string {
	var others []string
	for _, d := range devices {
		if d.Name != on {
			others = append(others, d.Label())
		}
	}
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
		line += "：" + zhReason(n.Reason)
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

// untilTime reads --until in the device time zone: a day means its end
// (23:59), a minute that minute. It must lie in the future.
func (o *options) untilTime(text string) (time.Time, error) {
	if text == "" {
		return time.Time{}, nil
	}
	loc := time.Local
	if o.timezone != "" {
		if l, err := time.LoadLocation(o.timezone); err == nil {
			loc = l
		}
	}
	var t time.Time
	var err error
	for _, layout := range []string{"2006-01-02T15:04", "2006-01-02 15:04", time.RFC3339} {
		if t, err = time.ParseInLocation(layout, text, loc); err == nil {
			break
		}
	}
	if err != nil {
		day, derr := time.ParseInLocation("2006-01-02", text, loc)
		if derr != nil {
			return time.Time{}, &usageError{fmt.Errorf("--until %q 不是日期或时刻：例如 2026-12-31 或 2026-12-31T18:00", text)}
		}
		t = day.Add(24*time.Hour - time.Minute)
	}
	now := time.Now
	if o.deps.Now != nil {
		now = o.deps.Now
	}
	if !t.After(now()) {
		return time.Time{}, &usageError{fmt.Errorf("--until %s 已经过去", t.Format("2006-01-02 15:04"))}
	}
	return t, nil
}
