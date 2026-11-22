package cli

import (
	"cmp"
	"io"
	"slices"
	"strings"

	"github.com/gatework/firemon/design"
	"github.com/gatework/firemon/query"
	"github.com/gatework/firemon/report"
)

// printBrief answers a query with scripts, firewall by firewall: the
// existing rules that already permit the traffic, as the device holds
// them, and the script that adds or modifies the rules it still needs,
// with its rollback. -v prints the reasoning.
func printBrief(w io.Writer, rep report.Report, v reportView) error {
	p := &printer{w: w}
	p.f("结论：%s\n", headline(rep))
	if len(rep.Premises) > 0 {
		p.f("前提：%s（-v 查看说明）\n", premiseShort(rep.Premises[0]))
	}
	briefWarnings(p, rep, v)
	for _, d := range rep.Devices {
		briefDevice(p, rep, d, v)
	}
	if inside := insideFlows(rep); inside != "" {
		p.f("\n不经过防火墙：%s\n", inside)
	}
	return p.err
}

// briefWarnings are the lines that change how the answer reads.
func briefWarnings(p *printer, rep report.Report, v reportView) {
	if warn := warningNotes(rep.Notes); len(warn) > 0 {
		printNotes(p, warn)
	}
	for _, name := range rep.ZonesNeeded {
		p.f("提示：%s\n", zonesHint(name, rep, v.single))
	}
	if rep.Excluded.Src != "" || rep.Excluded.Dst != "" {
		p.f("%s\n", cut("不在任何防火墙的受保护网段内：源 "+orDash(rep.Excluded.Src)+"  目的 "+orDash(rep.Excluded.Dst), false))
	}
}

// briefDevice writes one firewall: the existing rules permitting the
// flows, then the change script for those it denies.
func briefDevice(p *printer, rep report.Report, d report.DeviceView, v reportView) {
	f := firewallOf(rep, d.Cluster)
	if f == nil {
		return
	}
	p.f("\n━━ %s%s\n", d.Device.Label(), peersText(d))
	for _, u := range d.Allowed {
		if u.Rule == "" {
			p.f("\n已有：默认动作放通 %s\n", flowsText(rep, u.Flows))
			continue
		}
		p.f("\n已有策略 %s 放通 %s：\n", strings.TrimPrefix(hitLabel(u.Rule, u.Name), "策略 "), flowsText(rep, u.Flows))
		for _, line := range existingScript(v, f, u.Rule) {
			p.f("    %s\n", line)
		}
		if rd, ok := ruleDetail(f.Rules, u.Rule); ok && timeBound(rd) != "" {
			p.f("  ⚠ 限时策略：%s，此结论只在该时段内成立\n", timeBound(rd))
		}
	}
	for _, u := range d.Unknown {
		p.f("\n需确认：%s 可能被无法离线判定的策略决定（-v 查看原因）\n", flowsText(rep, u.Flows))
	}
	briefChange(p, rep, d, f)
}

// briefChange writes what a firewall still needs: the script, its
// rollback and the risks worth a look; or why none could be designed.
func briefChange(p *printer, rep report.Report, d report.DeviceView, f *report.Firewall) {
	if len(d.Added)+len(d.Modified) == 0 {
		if len(d.Blocked) == 0 {
			return
		}
		blocked := make([]string, 0, len(d.Blocked))
		for _, u := range d.Blocked {
			if u.Rule == "" {
				blocked = append(blocked, flowsText(rep, u.Flows)+" 无策略放通（默认拒绝）")
				continue
			}
			blocked = append(blocked, flowsText(rep, u.Flows)+" 被"+hitLabel(u.Rule, u.Name)+" 拒绝")
		}
		p.f("\n%s\n", strings.Join(blocked, "；"))
		switch {
		case d.Unplanned != "":
			p.f("  无法给出变更：%s（-v 查看）\n", cut(d.Unplanned, false))
		case !d.Designed:
			p.f("  去掉 --no-design 生成新增策略脚本\n")
		}
		return
	}
	var what []string
	for _, a := range d.Added {
		what = append(what, "新增 "+cmp.Or(a.Rule.Name, a.Rule.Rule)+" 放通 "+flowsText(rep, a.Flows)+blockedBy(d, a.Flows))
	}
	for _, m := range d.Modified {
		what = append(what, "修改"+hitLabel(m.Rule.Rule, m.Rule.Name)+" 放通 "+flowsText(rep, m.Flows)+blockedBy(d, m.Flows))
	}
	if len(what) == 1 {
		p.f("\n%s：\n", what[0])
	} else {
		p.f("\n%d 条变更：\n", len(what))
		for _, w := range what {
			p.f("  · %s\n", w)
		}
		p.f("  脚本：\n")
	}
	for _, s := range f.Scripts {
		for _, c := range s.Commands {
			p.f("    %s\n", c)
		}
		p.f("  回退：\n")
		for _, c := range s.Rollback {
			p.f("    %s\n", c)
		}
	}
	for _, r := range d.Risks {
		if r.Level >= design.RiskHigh {
			p.f("  ⚠ %s\n", cut(riskText(r), false))
		}
	}
}

// blockedBy names the rules that deny flows now, which the change goes
// before.
func blockedBy(d report.DeviceView, flows []int) string {
	var names []string
	for _, u := range d.Blocked {
		if !slices.ContainsFunc(u.Flows, func(n int) bool { return slices.Contains(flows, n) }) {
			continue
		}
		if u.Rule == "" {
			names = append(names, "默认动作")
			continue
		}
		names = append(names, hitLabel(u.Rule, u.Name))
	}
	switch {
	case len(names) == 0:
		return ""
	case len(names) == 1 && names[0] == "默认动作":
		return "（原无策略放通，默认拒绝）"
	default:
		return "（原被" + strings.Join(names, "、") + " 拒绝）"
	}
}

// existingScript is an existing rule as the device holds it: the text
// the parser recorded, after the objects the rule names; the vendor's
// renderer writes it when no text was recorded.
func existingScript(v reportView, f *report.Firewall, id string) []string {
	fw := v.fws[f.Cluster]
	if fw == nil {
		return nil
	}
	if lines, ok := fw.Config().RuleSource(id); ok {
		return lines
	}
	platform, ok := v.platforms[f.Firewall]
	if !ok || platform.Render == nil {
		return nil
	}
	r, ok := fw.Rule(id)
	if !ok {
		return nil
	}
	s, err := platform.Render(&design.Plan{Changes: []design.Change{design.AddRule{Rule: r.Spec()}}})
	if err != nil {
		return []string{"（无法按设备语法写出：" + err.Error() + "）"}
	}
	return slices.DeleteFunc(s.Commands, func(c string) bool { return strings.HasPrefix(strings.TrimSpace(c), "move ") })
}

// flowsText writes flows as "src → dst service", joined.
func flowsText(rep report.Report, ns []int) string {
	parts := make([]string, 0, len(ns))
	for _, n := range ns {
		if n < 1 || n > len(rep.Flows) {
			continue
		}
		f := rep.Flows[n-1]
		parts = append(parts, anyAddrText(f.Src)+" → "+anyAddrText(f.Dst)+" "+flowServiceText(f.Service))
	}
	return capped(parts, 3, "段流量")
}

// insideFlows lists the flows that cross no firewall.
func insideFlows(rep report.Report) string {
	var parts []string
	for _, f := range rep.Flows {
		if f.Inside != nil {
			parts = append(parts, f.Src+" → "+f.Dst+"（"+f.Inside.Cluster+" "+f.Inside.Zone+" 内）")
		}
	}
	return capped(parts, 5, "段流量")
}

func peersText(d report.DeviceView) string {
	if len(d.Peers) == 0 {
		return ""
	}
	labels := make([]string, len(d.Peers))
	for i, peer := range d.Peers {
		labels[i] = peer.Label()
	}
	return "  HA 同步至 " + strings.Join(labels, "、")
}

// headline says in one sentence whether the request needs a change and
// where: what an operator answers a ticket with.
func headline(rep report.Report) string {
	var change []string
	for _, d := range rep.Devices {
		if n := len(d.Added) + len(d.Modified); n > 0 {
			change = append(change, d.Device.Label()+" "+itoa(n)+" 条")
		}
	}
	switch {
	case len(change) > 0:
		return "需要变更 —— " + strings.Join(change, "，") + "（脚本见下）"
	case rep.Status == report.StatusFullMatch:
		return "无需变更 —— 已有策略放通"
	case len(rep.Firewalls) == 0 && rep.Settled():
		return "无需策略 —— 流量不经过防火墙"
	case len(rep.Firewalls) == 0 && rep.Excluded.Src == "" && rep.Excluded.Dst == "" && len(rep.ZonesNeeded) == 0:
		return "无需策略 —— 源和目的在防火墙同一侧（从同一接口进出），或没有到达目的的路由"
	default:
		return conclusion(rep)
	}
}

// premiseShort is a premise in a few words.
func premiseShort(pr report.Premise) string {
	if len(pr.Kinds) == 1 && pr.Kinds[0] == report.PremiseApplication {
		if len(pr.Applications) == 0 {
			return trafficText(pr.Service) + " 按未识别应用判定"
		}
		if len(pr.Applications) > 3 {
			return "按标准端口识别应用（" + capped(pr.Applications, 3, "个") + "）"
		}
		return trafficText(pr.Service) + " 按 " + strings.Join(pr.Applications, "、") + " 判定"
	}
	why := map[string]string{
		report.PremiseUser: "用户", report.PremiseURLCategory: "URL 分类", report.PremiseDomain: "域名", report.PremiseSchedule: "时间",
	}
	var kinds []string
	for _, k := range pr.Kinds {
		kinds = append(kinds, why[k])
	}
	return hitLabel(pr.Rule, pr.Name) + " 按" + strings.Join(kinds, "、") + "匹配，视为不命中"
}

// flowServiceText writes a service, protocol numbers as ip/N.
func flowServiceText(s string) string {
	if s == "any" {
		return "任意服务"
	}
	return strings.TrimPrefix(protocolNumbers("x -> x "+s), "x -> x ")
}

func zonePair(from, to string) string {
	if from == "" && to == "" {
		return ""
	}
	return orDash(from) + " → " + orDash(to)
}

// hopRule names the rule deciding a flow on one firewall.
func hopRule(h report.Hop) string {
	if len(h.Decisions) == 0 {
		return ""
	}
	d := h.Decisions[0]
	name := "默认拒绝"
	if d.Rule != "" {
		name = strings.TrimPrefix(hitLabel(d.Rule, d.Name), "策略 ")
	}
	if n := len(h.Decisions); n > 1 {
		name += " 等 " + itoa(n) + " 条"
	}
	return name
}

// hopResult is what happens to flow n on a firewall: permitted, or denied
// and the change that opens it.
func hopResult(rep report.Report, h report.Hop, n int) string {
	deny, unknown := false, false
	for _, d := range h.Decisions {
		switch d.Outcome {
		case query.OutcomeDeny, query.OutcomeDefault:
			deny = true
		case query.OutcomeUnknown, query.OutcomeUnset:
			unknown = true
		case query.OutcomePermit:
		}
	}
	switch {
	case unknown:
		return "? 需确认"
	case !deny:
		return "✓ 已放通"
	}
	i := slices.IndexFunc(rep.Devices, func(d report.DeviceView) bool { return d.Cluster == h.Cluster })
	if i >= 0 {
		for _, a := range rep.Devices[i].Added {
			if slices.Contains(a.Flows, n) {
				return "✗ 拒绝 → 新增 " + cmp.Or(a.Rule.Name, a.Rule.Rule)
			}
		}
		for _, m := range rep.Devices[i].Modified {
			if slices.Contains(m.Flows, n) {
				return "✗ 拒绝 → 修改策略 " + m.Rule.Rule
			}
		}
	}
	return "✗ 拒绝"
}
