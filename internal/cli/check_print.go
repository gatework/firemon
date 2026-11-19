package cli

import (
	"cmp"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/design"
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
	verbose   bool
}

// printReport writes what an operator acts on: per firewall the verdict,
// the existing rules that decide the request, and what to do. -v adds the
// paths, NAT, input notes, inferences and candidates.
func printReport(cmd *cobra.Command, rep report.Report, v reportView) error {
	p := &printer{w: cmd.OutOrStdout()}
	p.f("结论：%s\n", text(statusText, rep.Status, rep.Status.String()))
	if v.verbose && len(rep.Notes) > 0 {
		p.f("\n输入说明：\n")
		printNotes(p, rep.Notes)
	}
	if rep.Excluded.Src != "" || rep.Excluded.Dst != "" {
		p.f("\n不经过任何防火墙（已剔除）：源 %s  目的 %s\n", orDash(rep.Excluded.Src), orDash(rep.Excluded.Dst))
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
	if len(rep.Firewalls) == 0 && rep.Excluded.Src == "" && rep.Excluded.Dst == "" && len(rep.Inside) == 0 {
		p.f("\n该流量不经过防火墙的策略检查：源和目的在防火墙同一侧（从同一接口进出），或没有到达目的的路由\n")
	}
	for _, f := range rep.Firewalls {
		printFirewall(p, f, v)
	}
	return p.err
}

func printFirewall(p *printer, f report.Firewall, v reportView) {
	p.f("\n■ %s：%s\n", f.Cluster, firewallVerdict(f))
	if v.verbose {
		p.f("  成员：%s（%s）\n", strings.Join(f.Members, "、"), text(ownershipText, f.Ownership, f.Ownership.String()))
		for _, path := range f.Paths {
			printPath(p, path)
		}
	}
	printExisting(p, f, v.verbose)
	if f.Status == report.StatusPartialMatch && f.Remaining != "" {
		p.f("  未放通：%s\n", f.Remaining)
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

// printExisting lists the existing rules that decide the request: one
// line each with what it does to which part, then its definition.
func printExisting(p *printer, f report.Firewall, verbose bool) {
	type hit struct {
		action string
		h      report.Hit
	}
	var hits []hit
	for _, h := range f.Permitted {
		hits = append(hits, hit{"放通", h})
	}
	for _, h := range f.Blocked {
		hits = append(hits, hit{"拒绝", h})
	}
	if len(hits) == 0 {
		return
	}
	p.f("  已有策略：\n")
	for _, x := range hits {
		d, ok := ruleDetail(f.Rules, x.h.Rule)
		position := ""
		if ok {
			position = "（第 " + itoa(d.Position) + " 条）"
		}
		p.f("    %s  %s%s：%s\n", x.action, hitLabel(x.h.Rule, x.h.Name), position, x.h.Traffic)
		if !ok {
			continue
		}
		if verbose {
			printRuleDetail(p, d)
			continue
		}
		p.f("          区域 %s → %s；源 %s；目的 %s；服务 %s%s\n", zoneList(d.From), zoneList(d.To),
			objectsBrief(d.Source, d.NegateSource), objectsBrief(d.Destination, d.NegateDest), objectsBrief(d.Services, false), appsBrief(d.Applications))
	}
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
	p.f("  需确认：%s\n", f.UndecidedTraffic)
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
		p.f("  %s %s：源%s，目的%s，服务%s；%s\n", mark, hitLabel(c.Rule, c.Name), text(relationText, c.Src, c.Src.String()),
			text(relationText, c.Dst, c.Dst.String()), text(relationText, c.Service, c.Service.String()), cmp.Or(strings.Join(reasons, "；"), "可直接扩展"))
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
		p.f("  处置：在 %s 上执行以下命令%s（已验证：只放通本次请求）\n", cp.Firewall, haNote(f.Members, cp.Firewall))
		for _, w := range passedDenies(cp.Plan, v.fws[f.Cluster]) {
			p.f("    ⚠ 新策略放在拒绝策略 %s 之前，将绕过它：请确认该放通符合安全要求\n", w)
		}
		for _, c := range cp.Plan.Changes {
			p.f("    · %s\n", changeText(c))
		}
		for _, c := range script.Commands {
			p.f("    %s\n", c)
		}
		p.f("    回退命令：\n")
		for _, c := range script.Rollback {
			p.f("    %s\n", c)
		}
	}
	switch {
	case !designed && f.Status == report.StatusIndeterminate:
		p.f("  处置：先确认上述策略是否命中\n")
	case !designed:
		p.f("  处置：%s（去掉 --no-design 可生成变更方案）\n", text(statusText, f.Status, f.Status.String()))
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
	var out []string
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

// printRuleDetail writes a rule as configured with its objects expanded.
func printRuleDetail(p *printer, r report.RuleDetail) {
	if r.Disabled {
		p.f("      已禁用\n")
	}
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
