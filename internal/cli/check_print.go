package cli

import (
	"cmp"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/design"
	"github.com/gatework/firemon/intake"
	"github.com/gatework/firemon/internal/bootstrap"
	"github.com/gatework/firemon/inventory"
	"github.com/gatework/firemon/query"
	"github.com/gatework/firemon/report"
)

// reportView is what printing the check report needs besides the report.
type reportView struct {
	plans     []inventory.ClusterPlan
	platforms map[string]bootstrap.Platform
	fws       map[string]*firemon.Firewall
	// detail (-v) prints the reasoning: rule details, premises in full,
	// risks and candidates; verbose (-vv) adds paths, NAT and objects and
	// lifts the list bounds. Neither prints the brief answer.
	detail  bool
	verbose bool
	single  bool // one firewall from --config, --snapshot or --host: no inventory
	flows   bool // the flow table lists the deciding rules
}

// printReport writes what an operator acts on: per firewall the verdict,
// the existing rules that decide the request, and what to do. -v adds the
// paths, NAT, input notes, inferences and candidates.
func printReport(cmd *cobra.Command, rep report.Report, v reportView) error {
	p := &printer{w: cmd.OutOrStdout()}
	v.flows = flowTable(rep)
	p.f("结论：%s%s\n", conclusion(rep), flowSummary(rep.Flows))
	printPremises(p, rep, deviceLabels(rep), v.verbose)
	if v.detail && len(rep.Notes) > 0 {
		p.f("\n输入说明：\n")
		printNotes(p, rep.Notes)
	} else if warn := warningNotes(rep.Notes); len(warn) > 0 {
		p.f("\n输入提示：\n")
		printNotes(p, warn)
	}
	if rep.Excluded.Src != "" || rep.Excluded.Dst != "" {
		p.f("%s\n", cut(fmt.Sprintf("\n不在任何防火墙的受保护网段内（库存未覆盖，或确实不经过防火墙）：源 %s  目的 %s", orDash(rep.Excluded.Src), orDash(rep.Excluded.Dst)), v.verbose))
	}
	if !flowTable(rep) { // the flow table lists them otherwise
		for _, in := range rep.Inside {
			p.f("不经过防火墙：%s（两端都在 %s 的 %s 一侧）\n", in.Traffic, in.Cluster, in.Zone)
		}
	}
	for _, name := range rep.ZonesNeeded {
		p.f("提示：%s\n", zonesHint(name, rep, v.single))
	}
	for _, a := range rep.Ambiguous {
		p.f("%s\n", cut("归属不唯一（多个防火墙同等声明，均已检查）："+a, v.verbose))
	}
	if len(rep.Firewalls) == 0 && rep.Excluded.Src == "" && rep.Excluded.Dst == "" && len(rep.Inside) == 0 && len(rep.ZonesNeeded) == 0 {
		p.f("\n该流量不经过防火墙的策略检查：源和目的在防火墙同一侧（从同一接口进出），或没有到达目的的路由\n")
	}
	printZonePairs(p, rep)
	printFlowTable(p, rep, v.verbose)
	for _, f := range rep.Firewalls {
		printFirewall(p, f, v)
	}
	return p.err
}

// zonesHint says why the zone of the far end on a transparent (layer 2)
// firewall is unknown and how to give it.
func zonesHint(name string, rep report.Report, single bool) string {
	domains := slices.ContainsFunc(rep.Notes, func(n intake.Note) bool { return n.Code == intake.CodeDomain })
	switch {
	case domains:
		return name + " 是透明模式（二层），目的是域名，无法据此判断它在哪个安全区域：加 --resolve 解析为地址，或用 --from-zone/--to-zone 指定"
	case single:
		return name + " 是透明模式（二层），无法从路由判断另一端在哪个安全区域：请用 --from-zone/--to-zone 指定，或改用库存并为区域绑定网段"
	default:
		return name + " 是透明模式（二层），另一端不在该防火墙任何绑定的网段里，无法判断它在哪个安全区域：请在库存的 zones 中为该区域绑定网段（IPv4 用 0.0.0.0/0，IPv6 用 ::/0），或用 --from-zone/--to-zone 指定"
	}
}

// conclusion is the verdict over every firewall; a request that crosses
// none is settled only when both ends sit in one zone.
func conclusion(rep report.Report) string {
	switch {
	case rep.Status != report.StatusUnset:
		undecidedParts := rep.Status == report.StatusIndeterminate || slices.ContainsFunc(rep.Firewalls, undecided)
		if undecidedParts && planned(rep) {
			// Same reading as the exit code: the verified plan permits the
			// request whatever the undecidable rules do.
			return "需要新增策略（无法离线判定的部分，由已验证的方案确保放通）"
		}
		verdict := text(statusText, rep.Status, rep.Status.String())
		if word := plannedWord(rep); word != "" && rep.Status != report.StatusIndeterminate {
			verdict = word // what the verified plans do
		}
		if rep.Status != report.StatusIndeterminate && undecidedParts {
			verdict += "（部分流量需确认）"
		}
		return verdict
	case rep.Settled():
		return "无需策略：不经过防火墙"
	case rep.Excluded.Src != "" || rep.Excluded.Dst != "":
		return "需确认：请求不经过库存中的任何防火墙，请检查库存的 zones 是否覆盖源和目的"
	default:
		return "需确认：请求不经过防火墙的策略检查"
	}
}

func printFirewall(p *printer, f report.Firewall, v reportView) {
	verdict := firewallVerdict(f)
	if v.flows {
		verdict = flowVerdict(f)
	}
	p.f("\n■ %s：%s\n", firewallLabel(f), verdict)
	if line := haLine(f); line != "" {
		p.f("  %s\n", line)
	}
	if line := basisLine(f.Basis); line != "" {
		p.f("  命中依据：%s\n", cut(line, v.verbose))
	}
	for _, conflict := range f.ZoneConflicts {
		end := "目的"
		if conflict.Source {
			end = "源"
		}
		p.f("  需确认 %s：%s区域绑定为 %s，虚拟路由 %s 经 %s 指向 %s\n",
			trafficText(conflict.Traffic), end, conflict.BoundZone, conflict.VirtualRouter, conflict.Interface, conflict.RouteZone)
	}
	if v.verbose {
		p.f("  成员：%s（%s）\n", strings.Join(f.Members, "、"), text(ownershipText, f.Ownership, f.Ownership.String()))
		for _, path := range f.Paths {
			printPath(p, path)
		}
	}
	if !v.verbose {
		printNATSummary(p, f.Paths)
	}
	if v.verbose || !v.flows {
		printFlows(p, f, v.verbose) // the flow table lists them otherwise
	}
	if f.Unrouted != "" {
		p.f("  无路由（会被丢弃）的目的：%s\n", f.Unrouted)
	}
	printUndecided(p, f)
	if f.Incomplete {
		p.f("  评估超出预算被截断，结论只覆盖已评估的部分\n")
	}
	if v.verbose {
		printCandidates(p, f.Candidates)
	}
	printAction(p, f, v)
}

// firewallVerdict is the verdict with its reason: what blocks the request
// when nothing permits it.
func firewallVerdict(f report.Firewall) string {
	if (f.Status == report.StatusIndeterminate || undecided(f)) && settledByPlan(f) && len(f.Plan.Changes) > 0 {
		return "需要新增策略（无法离线判定的部分，由已验证的方案确保放通）"
	}
	verdict := text(statusText, f.Status, f.Status.String())
	switch f.Status {
	case report.StatusBlocked:
		ids := make([]string, len(f.Blocked))
		for i, h := range f.Blocked {
			ids[i] = h.Rule
		}
		return verdict + "（被策略 " + strings.Join(ids, "、") + " 拒绝）"
	case report.StatusNeedNew:
		return verdict + "（没有放通的策略，默认拒绝）"
	case report.StatusUnset, report.StatusFullMatch, report.StatusPartialMatch, report.StatusIndeterminate:
	}
	return verdict
}

// printFlows lists the request flow by flow: what is permitted and by
// which rule, what a rule denies, and what nothing permits.
func printFlows(p *printer, f report.Firewall, verbose bool) {
	rule := func(mark, what string, h report.Hit) {
		d, ok := ruleDetail(f.Rules, h.Rule)
		position := ""
		if ok {
			position = "（第 " + itoa(d.Position) + " 条）"
		}
		p.f("  %s  %s\n", mark, trafficText(h.Traffic))
		p.f("      %s：%s%s\n", what, hitLabel(h.Rule, h.Name), position)
		switch {
		case !ok:
		case verbose:
			printRuleDetail(p, d)
		default:
			p.f("      区域 %s → %s；源 %s；目的 %s；服务 %s%s；%s\n", zoneList(d.From), zoneList(d.To),
				objectsBrief(d.Source, d.NegateSource), objectsBrief(d.Destination, d.NegateDest), objectsBrief(d.Services, false), appsBrief(d.Applications), logText(d.Log))
		}
		if ok {
			if line := timeBound(d); line != "" {
				p.f("      ⚠ 限时策略：%s，此结论只在该时段内成立\n", line)
			}
		}
	}
	// First match: the rules in the order the firewall tries them.
	byPosition := func(hits []report.Hit) []report.Hit {
		out := slices.Clone(hits)
		slices.SortStableFunc(out, func(a, b report.Hit) int {
			da, _ := ruleDetail(f.Rules, a.Rule)
			db, _ := ruleDetail(f.Rules, b.Rule)
			return da.Position - db.Position
		})
		return out
	}
	for _, h := range byPosition(f.Permitted) {
		rule("✓ 已放通", "放通策略", h)
	}
	for _, h := range byPosition(f.Blocked) {
		rule("✗ 被拒绝", "拒绝策略", h)
	}
	if f.Defaulted != "" {
		p.f("  ✗ 无放通策略  %s\n      没有策略放通，默认拒绝\n", trafficText(f.Defaulted))
	}
}

// partOf is the report's summary of traffic in many pieces.
var partOf = regexp.MustCompile(`part of (.+?) \((\d+) pieces\)`)

// trafficText writes a traffic description in Chinese.
func trafficText(s string) string {
	parts := strings.Split(s, "; ")
	for i, part := range parts {
		parts[i] = anyTraffic(protocolNumbers(part))
	}
	return partOf.ReplaceAllString(strings.Join(parts, "; "), "$1 中的部分流量（共 $2 段，-v 或 --json 查看命中策略的定义）")
}

// protocolNumbers writes the protocols without a name in the service of
// "src -> dst service" as ip/N, the form the input takes ("47" alone
// reads as a port).
func protocolNumbers(part string) string {
	i := strings.LastIndexByte(part, ' ')
	if i < 0 || !strings.Contains(part, " -> ") {
		return part
	}
	items := strings.Split(part[i+1:], ",")
	for j, item := range items {
		if item != "" && strings.Trim(item, "0123456789") == "" {
			items[j] = "ip/" + item
		}
	}
	return part[:i+1] + strings.Join(items, ",")
}

// timeBound describes when a rule is in force, for a rule bound to a
// schedule or a validity period; empty for a permanent rule.
func timeBound(d report.RuleDetail) string {
	var parts []string
	if d.Schedule != nil {
		parts = append(parts, "时间计划 "+d.Schedule.Name+"（"+strings.Join(d.Schedule.Values, "；")+"）")
	}
	if d.Window != "" {
		w := strings.NewReplacer("until ", "至 ", "from ", "自 ", " ~ ", " 至 ").Replace(d.Window)
		parts = append(parts, "有效期 "+w)
	}
	return strings.Join(parts, "，")
}

func ruleDetail(rules []report.RuleDetail, id string) (report.RuleDetail, bool) {
	i := slices.IndexFunc(rules, func(r report.RuleDetail) bool { return r.Rule == id })
	if i < 0 {
		return report.RuleDetail{}, false
	}
	return rules[i], true
}

// printUndecided says which rules keep part of the request undecided and
// what decides it if they do not match.
func printUndecided(p *printer, f report.Firewall) {
	if len(f.Undecided) == 0 {
		return
	}
	names := make([]string, 0, len(f.Undecided))
	for _, h := range f.Undecided {
		kinds := make([]string, len(h.Reasons))
		for i, k := range h.Reasons {
			kinds[i] = text(issueKindText, k, k)
		}
		names = append(names, hitLabel(h.Rule, h.Name)+"（"+actionWord(h.Action)+"，"+strings.Join(kinds, "、")+"）")
	}
	p.f("  需确认：%s\n", cut(trafficText(f.UndecidedTraffic), false))
	p.f("    可能先命中并改变结论：%s\n", strings.Join(names, "，"))
	for _, h := range f.Otherwise {
		outcome := "拒绝"
		if h.Final == query.OutcomePermit {
			outcome = "放通"
		}
		p.f("    若都不命中：由%s%s\n", hitLabel(h.Rule, h.Name), outcome)
	}
}

// printCandidates lists existing rules that could carry the request.
func printCandidates(p *printer, cs []report.Candidate) {
	for _, c := range cs {
		mark := "候选"
		if c.Recommended {
			mark = "推荐修改"
		}
		reasons := make([]string, len(c.Reasons))
		for i, r := range c.Reasons {
			reasons[i] = text(reasonText, r, string(r))
		}
		state := "尚未验证"
		if c.Recommended {
			state = "已验证"
		}
		if c.Cost != nil {
			reasons = append(reasons, fmt.Sprintf("变更成本 %d", *c.Cost))
		}
		reasons = append(reasons, cmp.Or(c.ProofError, state))
		p.f("  %s %s：源%s，目的%s，服务%s；%s\n", mark, hitLabel(c.Rule, c.Name), text(relationText, c.Src, c.Src.String()),
			text(relationText, c.Dst, c.Dst.String()), text(relationText, c.Service, c.Service.String()), strings.Join(reasons, "；"))
	}
}

// printAction says what to do on the firewall: nothing, the verified
// commands, or what to confirm first.
func printAction(p *printer, f report.Firewall, v reportView) {
	switch f.Status {
	case report.StatusFullMatch:
		p.f("  处置：无需变更\n")
		return
	case report.StatusUnset:
		return
	case report.StatusPartialMatch, report.StatusNeedNew, report.StatusBlocked, report.StatusIndeterminate:
	}
	designed := false
	for _, cp := range v.plans {
		if cp.Cluster != f.Cluster || cp.Plan == nil {
			continue
		}
		designed = true
		printPlanNotes(p, cp.Plan, v.verbose)
		if len(cp.Plan.Changes) == 0 {
			continue
		}
		if !cp.Plan.Verified {
			p.f("  处置：需确认，方案验证未通过（%s），不输出命令\n", cmp.Or(cp.Plan.VerifyError, "未验证"))
			continue
		}
		script, err := v.platforms[cp.Firewall].Render(cp.Plan)
		if err != nil {
			p.f("  处置：需确认，方案无法生成命令：%v\n", err)
			continue
		}
		p.f("  处置：%s，在 %s 上执行%s（已验证：只放通本次请求）\n", actionSummary(cp.Plan), firewallLabel(f), haNote(f.Devices, cp.Firewall))
		if ids := passedDenies(cp.Plan, v.fws[f.Cluster]); len(ids) > 0 {
			them := "它"
			if len(ids) > 1 {
				them = "它们"
			}
			p.f("    ⚠ 放在拒绝策略 %s 之前，会绕过%s：请确认符合安全要求\n", strings.Join(ids, "、"), them)
		}
		printChanges(p, f.Planned, cp.Plan.Changes, v.verbose)
		printRisks(p, f.Risks)
		printRejected(p, f, f.Planned)
		p.f("    命令：\n")
		for _, c := range script.Commands {
			p.f("      %s\n", c)
		}
		p.f("    回退：\n")
		for _, c := range script.Rollback {
			p.f("      %s\n", c)
		}
		p.f("    下发后快照才会反映变更：用 firemon deploy 下发会自动更新快照；手工执行后请运行 firemon collect，否则再次查询会重复设计\n")
	}
	switch {
	case !designed && f.Status == report.StatusIndeterminate:
		p.f("  处置：先确认上述策略是否命中\n")
	case !designed:
		p.f("  处置：%s（去掉 --no-design 可生成变更方案）\n", text(statusText, f.Status, f.Status.String()))
	}
}

// printChanges numbers the changes of a plan: the rules it adds or
// modifies in full, then the other changes worth a line (all with -v).
func printChanges(p *printer, planned []report.PlannedRule, changes []design.Change, verbose bool) {
	n := 0
	for _, pr := range planned {
		n++
		printPlannedRule(p, n, pr)
	}
	for _, c := range changes {
		_, rule := c.(design.AddRule)
		_, ext := c.(design.ExtendRule)
		if (rule || ext) && len(planned) > 0 {
			continue // written in full above
		}
		if line := ruleChangeText(c); line != "" || verbose {
			n++
			p.f("    %d. %s\n", n, cmp.Or(line, changeText(c)))
		}
	}
}

// printPlanNotes writes the NAT outcome, what could not be designed and
// the planner's warnings; the notes about application rules are detail.
func printPlanNotes(p *printer, plan *design.Plan, verbose bool) {
	printNATOutcome(p, plan.NAT)
	for _, c := range plan.Conflicts {
		p.f("  设计冲突：策略 %s 拒绝 %s（%s → %s）\n", c.RuleID, c.Text, c.From, c.To)
	}
	for _, u := range plan.Unknown {
		p.f("  无法设计：%s\n", planNote(u))
	}
	for _, w := range plan.Warnings {
		if verbose {
			p.f("  注意：%s\n", planNote(w))
		}
	}
}

// passedDenies are the deny rules new rules are placed before.
func passedDenies(plan *design.Plan, fw *firemon.Firewall) []string {
	out := slices.Clone(plan.Bypassed)
	for _, c := range plan.Changes {
		add, ok := c.(design.AddRule)
		if !ok || add.Before == "" || fw == nil {
			continue
		}
		if r, ok := fw.Rule(add.Before); ok && r.Action() == firemon.ActionDeny && !slices.Contains(out, add.Before) {
			out = append(out, add.Before)
		}
	}
	return out
}

// hitLabel names a rule as "策略 ID 名称", or the default action.
func hitLabel(id, name string) string {
	if id == "(default)" || id == "" {
		return "默认动作"
	}
	if name == "" || name == id {
		return "策略 " + id
	}
	return "策略 " + id + " " + name
}

func actionWord(a firemon.Action) string {
	switch a {
	case firemon.ActionPermit:
		return "命中则放通"
	case firemon.ActionDeny:
		return "命中则拦截"
	case firemon.ActionUnset:
		return "动作未知"
	default:
		return "动作未知"
	}
}

// logText says what a rule logs.
func logText(l firemon.Logging) string {
	var parts []string
	if l.Start {
		parts = append(parts, "会话开始")
	}
	if l.End {
		parts = append(parts, "会话结束")
	}
	if l.Deny {
		parts = append(parts, "拒绝")
	}
	if len(parts) == 0 {
		return "未开启日志"
	}
	out := "日志 " + strings.Join(parts, "+")
	if l.Forward != "" {
		out += "（转发配置 " + l.Forward + "）"
	}
	return out
}

// printRuleDetail writes a rule as configured with its objects expanded.
func printRuleDetail(p *printer, r report.RuleDetail) {
	if r.Disabled {
		p.f("      已禁用\n")
	}
	p.f("      %s\n", logText(r.Log))
	p.f("      区域：%s → %s\n", zoneList(r.From), zoneList(r.To))
	printObjects(p, "源地址", r.Source, r.NegateSource)
	printObjects(p, "目的地址", r.Destination, r.NegateDest)
	printObjects(p, "服务", r.Services, false)
	if len(r.Applications) > 0 {
		p.f("      应用：%s\n", strings.Join(r.Applications, "、"))
	}
	if r.Schedule != nil {
		printObjects(p, "时间计划", []report.Object{*r.Schedule}, false)
	}
	if r.Description != "" {
		p.f("      描述：%s\n", r.Description)
	}
}

func zoneList(zs []string) string {
	if len(zs) == 0 {
		return "任意"
	}
	return strings.Join(zs, "、")
}

// objectsBrief writes one dimension on one line. A long list shows only
// the objects that hold the request, with how many there are in all.
func objectsBrief(objs []report.Object, negate bool) string {
	if len(objs) == 0 {
		return "任意"
	}
	shown := objs
	if len(objs) > briefObjects {
		shown = slices.DeleteFunc(slices.Clone(objs), func(o report.Object) bool { return !o.Matched })
	}
	parts := make([]string, 0, len(shown))
	for _, o := range shown {
		if b := objectBrief(o); !slices.Contains(parts, b) {
			parts = append(parts, b)
		}
	}
	out := strings.Join(parts, "、")
	if len(shown) < len(objs) {
		out = cmp.Or(out, "无") + "（共 " + itoa(len(objs)) + " 项，列出命中的 " + itoa(len(shown)) + " 项；-v 查看全部）"
	}
	if negate {
		out = "除 " + out + " 以外"
	}
	return out
}

// briefObjects is how many objects of one dimension are listed in full.
const briefObjects = 3

func objectBrief(o report.Object) string {
	vals := leafValues(o)
	switch {
	case o.Missing:
		return o.Name + "（未定义）"
	case o.Name == "":
		return strings.Join(vals, "、")
	case o.Name == "Any" || o.Name == "any":
		return "任意"
	case len(vals) == 1 && vals[0] == o.Name:
		return o.Name
	case len(vals) == 0:
		return o.Name + "（空）"
	case len(vals) > 3:
		return o.Name + "（" + strings.Join(vals[:3], "、") + " 等 " + itoa(len(vals)) + " 项）"
	default:
		return o.Name + "（" + strings.Join(vals, "、") + "）"
	}
}

// leafValues are an object's values and those of its members, in order.
func leafValues(o report.Object) []string {
	out := slices.Clone(o.Values)
	for _, m := range o.Members {
		for _, v := range leafValues(m) {
			if !slices.Contains(out, v) {
				out = append(out, v)
			}
		}
	}
	return out
}

func appsBrief(apps []string) string {
	if len(apps) == 0 {
		return ""
	}
	return "；应用 " + strings.Join(apps, "、")
}

// printObjects writes one dimension of a rule: "任意" when it names
// nothing, else each object with its values and members indented below.
func printObjects(p *printer, title string, objs []report.Object, negate bool) {
	if len(objs) == 0 {
		p.f("      %s：任意\n", title)
		return
	}
	prefix := ""
	if negate {
		prefix = "除以下以外的全部："
	}
	p.f("      %s：%s\n", title, prefix)
	for _, o := range objs {
		printObject(p, o, 8)
	}
}

func printObject(p *printer, o report.Object, indent int) {
	pad := strings.Repeat(" ", indent)
	switch {
	case o.Missing:
		p.f("%s%s（配置中未定义）\n", pad, o.Name)
	case o.Name == "":
		p.f("%s%s\n", pad, strings.Join(o.Values, "、"))
	case len(o.Members) == 0 && len(o.Values) == 1 && o.Values[0] == o.Name:
		p.f("%s%s\n", pad, o.Name) // named after its only value
	case len(o.Members) == 0:
		p.f("%s%s = %s\n", pad, o.Name, cmp.Or(strings.Join(o.Values, "、"), "（空）"))
	default:
		line := pad + o.Name + "（组）"
		if len(o.Values) > 0 {
			line += " = " + strings.Join(o.Values, "、")
		}
		p.f("%s\n", line)
		for _, m := range o.Members {
			printObject(p, m, indent+2)
		}
	}
}

// basisLine says why the request reaches the firewall: which end falls
// in which protected zone and networks.
func basisLine(bs []report.Basis) string {
	parts := make([]string, 0, len(bs))
	for _, b := range bs {
		if !slices.ContainsFunc(b.Networks, func(n string) bool { return n != "0.0.0.0/0" && n != "::/0" }) {
			continue // a firewall named on the command line answers for every address
		}
		end := "目的"
		if b.Source {
			end = "源"
		}
		where := ""
		switch b.Ownership {
		case inventory.OwnershipDeclared:
			where = "受保护网段 " + strings.Join(b.Networks, "、")
			if b.Zone != "" {
				where = "受保护区域 " + b.Zone + "（" + strings.Join(b.Networks, "、") + "）"
			}
		case inventory.OwnershipDerived:
			where = "本墙路由覆盖的网段 " + strings.Join(b.Networks, "、")
		case inventory.OwnershipTransit, inventory.OwnershipZones, inventory.OwnershipUnset:
			continue
		}
		if b.VirtualRouter != "" {
			where += "（虚拟路由 " + b.VirtualRouter + "）"
		}
		parts = append(parts, end+" "+b.Addresses+" 属于"+where)
	}
	return strings.Join(parts, "；")
}

// printNATSummary writes the translations the request goes through: they
// change which rules match it. Paths in -v show the rest.
func printNATSummary(p *printer, paths []report.Path) {
	// One line per translation: the paths of one request (one per
	// application or zone pair) often share it.
	type line struct {
		key, text string
		parts     int
	}
	var lines []line
	for _, path := range paths {
		for _, n := range path.NAT {
			key := n.Rule + "|" + n.Side.String() + "|" + n.Translated
			desc := "NAT 规则 " + n.Rule + " 可能生效，无法离线判定"
			if !n.Uncertain {
				order := ""
				if n.Position > 0 {
					order = "（第 " + itoa(n.Position) + " 条）"
				}
				desc = text(natSideText, n.Side, n.Side.String()) + " " + n.Rule + order + "：" + cmp.Or(n.Traffic, "-") + " → " + n.Translated
			}
			if i := slices.IndexFunc(lines, func(l line) bool { return l.key == key }); i >= 0 {
				lines[i].parts++
				continue
			}
			lines = append(lines, line{key: key, text: desc, parts: 1})
		}
	}
	for _, l := range lines {
		more := ""
		if l.parts > 1 {
			more = "（同一规则另转换 " + itoa(l.parts-1) + " 段流量）"
		}
		p.f("  %s%s\n", cut(l.text, false), more)
	}
}

// actionSummary says in a few words what the plan changes.
func actionSummary(plan *design.Plan) string {
	var added, extended, nat int
	for _, c := range plan.Changes {
		switch c.(type) {
		case design.AddRule:
			added++
		case design.ExtendRule:
			extended++
		case design.AddNAT, design.AddStaticNAT:
			nat++
		}
	}
	var parts []string
	if added > 0 {
		parts = append(parts, "新增 "+itoa(added)+" 条策略")
	}
	if extended > 0 {
		parts = append(parts, "修改 "+itoa(extended)+" 条已有策略")
	}
	if nat > 0 {
		parts = append(parts, "新增 "+itoa(nat)+" 条 NAT")
	}
	return cmp.Or(strings.Join(parts, "，"), "变更")
}

// ruleChangeText describes a change to the rules in one line, with what
// the rule matches; object changes are left to the commands.
func ruleChangeText(c design.Change) string {
	switch x := c.(type) {
	case design.AddRule:
		r := x.Rule
		names := func(refs []firemon.AddressRef) string {
			out := make([]string, 0, len(refs))
			for _, a := range refs {
				out = append(out, cmp.Or(a.Name, a.String()))
			}
			return cmp.Or(strings.Join(out, "、"), "任意")
		}
		return changeText(c) + "：" + zoneList(r.From) + " → " + zoneList(r.To) + "，源 " + names(r.Source) + "，目的 " + names(r.Destination) +
			"，服务 " + cmp.Or(strings.Join(r.Services, "、"), "任意")
	case design.ExtendRule, design.AddNAT, design.AddStaticNAT:
		return changeText(c)
	default:
		return ""
	}
}
