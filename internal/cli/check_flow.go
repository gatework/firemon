package cli

import (
	"cmp"
	"slices"
	"strings"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/design"
	"github.com/gatework/firemon/intake"
	"github.com/gatework/firemon/inventory"
	"github.com/gatework/firemon/query"
	"github.com/gatework/firemon/report"
)

// flowStatusText names a flow's answer.
var flowStatusText = map[report.FlowStatus]string{
	report.FlowAllowed:       "✓ 已放通",
	report.FlowNoFirewall:    "— 无需策略（不经过防火墙）",
	report.FlowNeedChange:    "✗ 需新增或修改策略",
	report.FlowIndeterminate: "? 需确认",
	report.FlowUnlocated:     "? 不经过库存中的任何防火墙",
}

// flowSummary counts the flows by answer, for the conclusion line.
func flowSummary(flows []report.Flow) string {
	if len(flows) < 2 {
		return ""
	}
	counts := map[report.FlowStatus]int{}
	for _, f := range flows {
		counts[f.Status]++
	}
	var parts []string
	for _, s := range []report.FlowStatus{report.FlowNeedChange, report.FlowAllowed, report.FlowNoFirewall, report.FlowIndeterminate, report.FlowUnlocated} {
		if counts[s] == 0 {
			continue
		}
		label := map[report.FlowStatus]string{
			report.FlowNeedChange: "需变更", report.FlowAllowed: "已放通", report.FlowNoFirewall: "不经过防火墙",
			report.FlowIndeterminate: "需确认", report.FlowUnlocated: "未定位到防火墙",
		}[s]
		parts = append(parts, itoa(counts[s])+" 条"+label)
	}
	return "（" + itoa(len(flows)) + " 条流：" + strings.Join(parts, "，") + "）"
}

// Display bounds of the default output; -v lifts them, --json holds all.
const (
	maxPremiseApps = 5
	maxFlowApps    = 3
	maxHopRules    = 3
	maxListedFlows = 20
	maxPremises    = 10
	maxLineText    = 300 // a free-text line longer than this is cut
)

// cut shortens a line to maxLineText runes, saying how long it was.
func cut(s string, verbose bool) string {
	r := []rune(s)
	if verbose || len(r) <= maxLineText {
		return s
	}
	return string(r[:maxLineText]) + "…（共 " + itoa(len(r)) + " 字，-v 或 --json 查看全部）"
}

// printPremises states what the result assumes (ADR 0017).
func printPremises(p *printer, rep report.Report, labels map[string]string, verbose bool) {
	if len(rep.Premises) == 0 {
		return
	}
	p.f("\n前提：\n")
	shown := rep.Premises
	if len(shown) > maxPremises && !verbose {
		shown = shown[:maxPremises]
	}
	for _, pr := range shown {
		p.f("  · %s\n", cut(premiseText(pr, labels, verbose), verbose))
	}
	if rest := len(rep.Premises) - len(shown); rest > 0 {
		p.f("  · 另有 %d 条前提（-v 或 --json 查看）\n", rest)
	}
}

// deciderText names the rules that decide a premise's traffic now.
func deciderText(ids string) string {
	parts := strings.Split(ids, ",")
	for i, id := range parts {
		parts[i] = hitLabel(id, "")
	}
	return capped(parts, 3, "条策略")
}

func premiseText(pr report.Premise, labels map[string]string, verbose bool) string {
	if len(pr.Kinds) == 1 && pr.Kinds[0] == report.PremiseApplication {
		const how = "（实际应用不同请用 --service app:名称 指定，或加 --strict 保守判定）"
		if len(pr.Applications) == 0 {
			return "应用识别：" + trafficText(pr.Service) + " 不是任何标准应用的端口，按未识别应用处理，按应用匹配的策略都不命中" + how
		}
		limit := maxPremiseApps
		if verbose {
			limit = len(pr.Applications)
		}
		if len(pr.Applications) > limit {
			return "应用识别：按标准端口识别应用（" + capped(pr.Applications, limit, "个应用") + "），应用列表不含它的策略不命中" + how
		}
		return "应用识别：" + trafficText(pr.Service) + " 按标准端口识别为 " + strings.Join(pr.Applications, "、") + "，应用列表不含它的策略不命中" + how
	}
	var cond []string
	for _, k := range pr.Kinds {
		switch k {
		case report.PremiseUser:
			cond = append(cond, "按用户匹配，未给出 --user 视为不命中")
		case report.PremiseURLCategory:
			cond = append(cond, "按 URL 分类匹配，未给出 --url-category 视为不命中")
		case report.PremiseSchedule:
			cond = append(cond, "受时间限制，查询时刻不生效")
		case report.PremiseDomain:
			cond = append(cond, "按域名匹配，目的地址视为不属于这些域名的解析结果（如属于，请用 --dst 域名 查询）")
		}
	}
	criteria := ""
	if len(pr.Criteria) > 0 {
		criteria = "（" + strings.Join(pr.Criteria, "、") + "）"
	}
	outcome := "拒绝"
	if pr.Action == firemon.ActionPermit {
		outcome = "放通"
	}
	where := cmp.Or(labels[pr.Cluster], pr.Cluster)
	return where + " " + hitLabel(pr.Rule, pr.Name) + criteria + strings.Join(cond, "；") +
		"；若命中，" + trafficText(pr.Traffic) + " 将被它" + outcome + "（现由" + deciderText(pr.Decider) + "决定）"
}

// capped lists the first n items and how many there are in all.
func capped(items []string, n int, unit string) string {
	if len(items) <= n {
		return strings.Join(items, "、")
	}
	return strings.Join(items[:n], "、") + " 等 " + itoa(len(items)) + " " + unit
}

// printFlowTable lists each flow and, firewall by firewall in the order it
// crosses them, the rules deciding it with what they match.
func printFlowTable(p *printer, rep report.Report, verbose bool) {
	if !flowTable(rep) {
		return
	}
	p.f("\n流量明细：\n")
	flows := rep.Flows
	if len(flows) > maxListedFlows && !verbose {
		// Many flows: the ones needing action, the rest counted.
		flows = slices.DeleteFunc(slices.Clone(flows), func(f report.Flow) bool {
			return f.Status == report.FlowAllowed || f.Status == report.FlowNoFirewall
		})
		p.f("  共 %d 条流，以下只列需变更或需确认的 %d 条（-v 查看全部）\n", len(rep.Flows), len(flows))
	}
	marks := []string{"①", "②", "③", "④", "⑤", "⑥", "⑦", "⑧", "⑨"}
	for i, f := range flows {
		apps := ""
		if len(f.Applications) > 0 {
			n := maxFlowApps
			if verbose {
				n = len(f.Applications)
			}
			apps = "（" + capped(f.Applications, n, "个应用") + "）"
		}
		p.f("  流 %d  %s → %s  %s%s  %s\n", i+1, anyAddrText(f.Src), anyAddrText(f.Dst), trafficText(f.Service), apps, text(flowStatusText, f.Status, f.Status.String()))
		if f.Inside != nil {
			p.f("      两端都在 %s 的 %s 一侧\n", f.Inside.Cluster, f.Inside.Zone)
		}
		for j, h := range f.Hops {
			mark := itoa(j+1) + "."
			if j < len(marks) {
				mark = marks[j]
			}
			printHop(p, rep, mark, h, verbose)
		}
	}
}

// printHop writes one firewall on a flow's way: how the flow reaches it,
// and the rules deciding it there with what they match.
func printHop(p *printer, rep report.Report, mark string, h report.Hop, verbose bool) {
	p.f("      %s %s  %s → %s\n", mark, h.Device.Label(), orDash(h.From), orDash(h.To))
	if h.Via != nil {
		p.f("         经 %s 的 NAT 转换后到达：%s\n", cmp.Or(deviceLabels(rep)[h.Via.Cluster], h.Via.Cluster), trafficText(h.Via.Translated))
	}
	fw := firewallOf(rep, h.Cluster)
	ds := h.Decisions
	if len(ds) > maxHopRules && !verbose {
		ds = ds[:maxHopRules]
	}
	for _, d := range ds {
		p.f("         %s  %s\n", outcomeMark(d.Outcome), decisionLabel(d))
		if d.Rule == "" || fw == nil {
			continue
		}
		if rd, ok := ruleDetail(fw.Rules, d.Rule); ok {
			p.f("            %s\n", ruleBrief(rd))
			if line := timeBound(rd); line != "" {
				p.f("            ⚠ 限时策略：%s，此结论只在该时段内成立\n", line)
			}
		}
	}
	if rest := len(h.Decisions) - len(ds); rest > 0 {
		p.f("         另有 %d 条策略决定其中部分流量（-v 查看）\n", rest)
	}
}

// ruleBrief is one line of what a rule matches.
func ruleBrief(d report.RuleDetail) string {
	return "区域 " + zoneList(d.From) + " → " + zoneList(d.To) + "；源 " + objectsBrief(d.Source, d.NegateSource) +
		"；目的 " + objectsBrief(d.Destination, d.NegateDest) + "；服务 " + objectsBrief(d.Services, false) + appsBrief(d.Applications) + "；" + logText(d.Log)
}

func firewallOf(rep report.Report, cluster string) *report.Firewall {
	for i := range rep.Firewalls {
		if rep.Firewalls[i].Cluster == cluster {
			return &rep.Firewalls[i]
		}
	}
	return nil
}

// anyAddrText writes the whole address space, as reports print it, as 任意.
func anyAddrText(s string) string {
	switch s {
	case "any", "0.0.0.0/0,::/0", "0.0.0.0/0", "::/0":
		return "任意"
	}
	return s
}

// printZonePairs summarizes a wide request by zone pair on each firewall.
func printZonePairs(p *printer, rep report.Report) {
	if !wide(rep) {
		return
	}
	p.f("\n区域对汇总：\n")
	for _, f := range rep.Firewalls {
		p.f("  %s\n", firewallLabel(f))
		for _, zp := range f.ZonePairs {
			parts := []string{}
			if zp.Permits > 0 {
				parts = append(parts, "放通 "+itoa(zp.Permits)+" 条策略")
			}
			if zp.Denies > 0 {
				parts = append(parts, "拒绝 "+itoa(zp.Denies)+" 条策略")
			}
			if zp.Default {
				parts = append(parts, "其余默认拒绝")
			}
			if zp.Unknown > 0 {
				parts = append(parts, "需确认 "+itoa(zp.Unknown)+" 处")
			}
			p.f("    %s → %s：%s（策略 %s）\n", orDash(zp.From), orDash(zp.To), strings.Join(parts, "，"), cmp.Or(strings.Join(zp.Rules, "、"), "无"))
		}
	}
}

// wide reports a request decided by many rules: its zone-pair summary
// comes before the flows.
func wide(rep report.Report) bool {
	n := 0
	for _, f := range rep.Firewalls {
		for _, zp := range f.ZonePairs {
			n += zp.Permits + zp.Denies
		}
	}
	return n > 6
}

// flowTable reports whether the report lists its flows: several flows, or
// one through several firewalls. One flow through one firewall is said
// in full by the firewall section.
func flowTable(rep report.Report) bool {
	return len(rep.Flows) > 1 || (len(rep.Flows) == 1 && len(rep.Flows[0].Hops) > 1)
}

func outcomeMark(o query.Outcome) string {
	switch o {
	case query.OutcomePermit:
		return "✓ 放通"
	case query.OutcomeDeny:
		return "✗ 拒绝"
	case query.OutcomeDefault:
		return "✗ 默认拒绝"
	case query.OutcomeUnknown, query.OutcomeUnset:
		return "? 需确认"
	default:
		return "?"
	}
}

func decisionLabel(d report.HopDecision) string {
	if d.Rule == "" {
		return "没有策略命中，默认动作拒绝"
	}
	return hitLabel(d.Rule, d.Name) + "（第 " + itoa(d.Position) + " 条）"
}

// deviceLabels names each cluster by its evaluated member.
func deviceLabels(rep report.Report) map[string]string {
	out := map[string]string{}
	for _, f := range rep.Firewalls {
		out[f.Cluster] = firewallLabel(f)
	}
	return out
}

// firewallLabel is the evaluated member as "NAME(IP)".
func firewallLabel(f report.Firewall) string {
	if len(f.Devices) > 0 {
		return f.Devices[0].Label()
	}
	return inventory.Device{Name: cmp.Or(f.Firewall, f.Cluster)}.Label()
}

// haLine names the cluster and the members that receive the change by
// synchronization.
func haLine(f report.Firewall) string {
	if len(f.Devices) < 2 {
		return ""
	}
	others := make([]string, 0, len(f.Devices)-1)
	for _, d := range f.Devices[1:] {
		others = append(others, d.Label())
	}
	return "集群 " + f.Cluster + "：按主 " + f.Devices[0].Label() + " 评估，" + strings.Join(others, "、") + " 由 HA 同步配置"
}

// printPlannedRule writes a rule the plan adds or modifies in full.
func printPlannedRule(p *printer, n int, pr report.PlannedRule) {
	r := pr.Rule
	switch pr.Kind {
	case "add":
		where := "放在末尾"
		if pr.Before != "" {
			where = "放在策略 " + pr.Before + " 之前"
		}
		p.f("    %d. 新增策略 %s（ID %s，%s）\n", n, cmp.Or(r.Name, r.Rule), r.Rule, where)
	default:
		fields := make([]string, len(pr.Fields))
		for i, f := range pr.Fields {
			fields[i] = map[string]string{"source": "源地址", "destination": "目的地址", "service": "服务"}[f]
		}
		p.f("    %d. 修改%s（第 %d 条）：扩展 %s\n", n, hitLabel(r.Rule, r.Name), r.Position, strings.Join(fields, "、"))
	}
	created := func(objs []report.Object) string {
		parts := make([]string, 0, len(objs))
		for _, o := range objs {
			b := objectBrief(o)
			if o.Name != "" && slices.Contains(pr.Created, o.Name) {
				b += "【新建】"
			}
			parts = append(parts, b)
		}
		if len(parts) == 0 {
			return "任意"
		}
		return strings.Join(parts, "、")
	}
	action := "拒绝"
	if r.Action == firemon.ActionPermit {
		action = "放通"
	}
	p.f("       动作：%s\n", action)
	p.f("       区域：%s → %s\n", zoneList(r.From), zoneList(r.To))
	p.f("       源地址：%s\n", created(r.Source))
	p.f("       目的地址：%s\n", created(r.Destination))
	p.f("       服务：%s\n", created(r.Services))
	p.f("       应用：%s\n", cmp.Or(strings.Join(r.Applications, "、"), "任意"))
	when := "永久"
	if line := timeBound(r); line != "" {
		when = line
	}
	p.f("       时间：%s\n", when)
	p.f("       日志：%s\n", strings.TrimPrefix(logText(r.Log), "日志 "))
	if r.Description != "" {
		p.f("       描述：%s\n", r.Description)
	}
	if pr.Original != nil {
		o := *pr.Original
		p.f("       修改前：源 %s；目的 %s；服务 %s\n", objectsBrief(o.Source, o.NegateSource), objectsBrief(o.Destination, o.NegateDest), objectsBrief(o.Services, false))
	}
}

// devicesOf names members known only by name.
func devicesOf(names []string) []inventory.Device {
	out := make([]inventory.Device, len(names))
	for i, n := range names {
		out[i] = inventory.Device{Name: n}
	}
	return out
}

// warningNotes are the input notes shown without -v: readings that may
// not be what the operator meant.
func warningNotes(notes []intake.Note) []intake.Note {
	var out []intake.Note
	for _, n := range notes {
		if n.Code == intake.CodeNetworkHost {
			out = append(out, n)
		}
	}
	return out
}

// anyTraffic writes "any" in "src -> dst service" as 任意.
func anyTraffic(part string) string {
	src, rest, ok := strings.Cut(part, " -> ")
	if !ok {
		return part
	}
	dst, svc, _ := strings.Cut(rest, " ")
	if svc == "any" {
		svc = "任意服务"
	}
	return strings.TrimSpace(anyAddrText(src) + " -> " + anyAddrText(dst) + " " + svc)
}

// flowVerdict is a firewall's verdict in flows, matching the flow table.
func flowVerdict(f report.Firewall) string {
	c := f.FlowCounts
	var parts []string
	if c.Allowed > 0 {
		parts = append(parts, "放通 "+itoa(c.Allowed)+" 条流")
	}
	if c.NeedChange > 0 {
		parts = append(parts, "需变更 "+itoa(c.NeedChange)+" 条流")
	}
	if c.Unknown > 0 {
		parts = append(parts, "需确认 "+itoa(c.Unknown)+" 条流")
	}
	if len(parts) == 0 {
		return firewallVerdict(f)
	}
	return strings.Join(parts, "，")
}

// maxRejected bounds the candidates a plan says it did not modify.
const maxRejected = 2

// printRejected says, when a plan adds rules and modifies none, which
// existing rules came closest and why they were not modified: the
// operator asked for the best rule to be modified when one partly fits.
func printRejected(p *printer, f report.Firewall, planned []report.PlannedRule) {
	if slices.ContainsFunc(planned, func(pr report.PlannedRule) bool { return pr.Kind != "add" }) || len(planned) == 0 {
		return
	}
	n := 0
	for _, c := range f.Candidates {
		if c.Recommended || len(c.Reasons) == 0 {
			continue
		}
		if n == maxRejected {
			break
		}
		n++
		reasons := make([]string, len(c.Reasons))
		for i, r := range c.Reasons {
			reasons[i] = text(reasonText, r, string(r))
		}
		p.f("    未选择修改%s：源%s，目的%s，服务%s；%s\n", hitLabel(c.Rule, c.Name), text(relationText, c.Src, c.Src.String()),
			text(relationText, c.Dst, c.Dst.String()), text(relationText, c.Service, c.Service.String()), strings.Join(reasons, "；"))
	}
	if n == 0 {
		p.f("    未选择修改已有策略：没有只差一个维度、且扩展后不放通需求外流量的策略\n")
	}
}

var riskLevelText = map[design.RiskLevel]string{design.RiskLow: "低", design.RiskMedium: "中", design.RiskHigh: "高"}

// printRisks grades what the plan opens, most severe first.
func printRisks(p *printer, risks []design.Risk) {
	for _, r := range risks {
		p.f("    风险：%s｜%s\n", text(riskLevelText, r.Level, r.Level.String()), cut(riskText(r), false))
	}
}

// riskText says what a risk is about.
func riskText(r design.Risk) string {
	switch r.Code {
	case design.RiskAnyAddress:
		return "策略 " + r.Rule + " 的源或目的为任意"
	case design.RiskWideNetwork:
		return "策略 " + r.Rule + " 放通的网段宽于 /16：" + r.Detail
	case design.RiskAnyService:
		return "策略 " + r.Rule + " 放通全部服务"
	case design.RiskManyPorts:
		return "策略 " + r.Rule + " 放通的端口超过 100 个：" + r.Detail
	case design.RiskSensitiveService:
		return "策略 " + r.Rule + " 跨区放通高危服务 " + r.Detail
	case design.RiskBypassIsolation:
		return "绕过网段隔离策略 " + r.Rule + "（" + trafficText(r.Detail) + " 全部服务拒绝）"
	case design.RiskBypassDeny:
		return "绕过拒绝策略 " + r.Rule + "（" + trafficText(r.Detail) + "）"
	default:
		return string(r.Code) + " " + r.Rule
	}
}

// plannedWord names what the verified plans of a report do: add rules,
// modify existing ones, or both; empty when nothing is planned.
func plannedWord(rep report.Report) string {
	add, mod := false, false
	for _, f := range rep.Firewalls {
		for _, pr := range f.Planned {
			if pr.Kind == "add" {
				add = true
			} else {
				mod = true
			}
		}
	}
	switch {
	case add && mod:
		return "需要新增和修改策略"
	case mod:
		return "需要修改已有策略"
	case add:
		return "需要新增策略"
	default:
		return ""
	}
}
