package cli

import (
	"io"
	"strings"

	"github.com/gatework/firemon/report"
)

// printMarkdown writes the report as Markdown to paste into a ticket: the
// conclusion, premises, a table of the flows, and per firewall the rules
// to add or modify, the risks, the commands and their rollback.
func printMarkdown(w io.Writer, rep report.Report, v reportView) error {
	p := &printer{w: w}
	labels := deviceLabels(rep)
	p.f("**结论**：%s%s\n", headline(rep), flowSummary(rep.Flows))
	if len(rep.Premises) > 0 {
		p.f("\n**前提**\n\n")
		for _, pr := range rep.Premises {
			p.f("- %s\n", mdText(cut(premiseText(pr, labels, v.verbose), v.verbose)))
		}
	}
	mdFlows(p, rep)
	for _, f := range rep.Firewalls {
		mdChanges(p, f)
	}
	return p.err
}

// mdCell makes text safe in a Markdown table cell.
func mdCell(s string) string {
	return strings.NewReplacer("|", "\\|", "\n", "<br>").Replace(s)
}

// mdText keeps text from being read as Markdown markup.
func mdText(s string) string {
	return strings.NewReplacer("*", "\\*", "_", "\\_", "`", "\\`").Replace(s)
}

// mdFlows writes the flows as a table, a row per firewall each crosses,
// in the columns of the brief answer.
func mdFlows(p *printer, rep report.Report) {
	if len(rep.Flows) == 0 {
		return
	}
	p.f("\n| # | 源 | 目的 | 服务 | 防火墙 | 区域 | 命中策略 | 结果 |\n|---|---|---|---|---|---|---|---|\n")
	for i, f := range rep.Flows {
		first := []string{itoa(i + 1), anyAddrText(f.Src), anyAddrText(f.Dst), flowServiceText(f.Service)}
		if len(f.Hops) == 0 {
			fw, result := "—", text(flowStatusText, f.Status, f.Status.String())
			if f.Inside != nil {
				fw, result = f.Inside.Cluster+"（"+f.Inside.Zone+" 内）", "不经过防火墙"
			}
			mdRow(p, append(first, fw, "", "", result))
			continue
		}
		for j, h := range f.Hops {
			row := []string{"", "", "", ""}
			if j == 0 {
				row = first
			}
			mdRow(p, append(row, h.Device.Label(), zonePair(h.From, h.To), hopRule(h), hopResult(rep, h, i+1)))
		}
	}
}

func mdRow(p *printer, cells []string) {
	for i, c := range cells {
		cells[i] = mdCell(c)
	}
	p.f("| %s |\n", strings.Join(cells, " | "))
}

// mdChanges writes one firewall's planned rules, risks and commands.
func mdChanges(p *printer, f report.Firewall) {
	if len(f.Planned) == 0 && len(f.Scripts) == 0 {
		return
	}
	p.f("\n### 变更：%s\n\n", firewallLabel(f))
	if line := haLine(f); line != "" {
		p.f("%s\n\n", line)
	}
	for i, pr := range f.Planned {
		mdPlanned(p, i+1, pr)
	}
	if len(f.Risks) > 0 {
		var sb strings.Builder
		printRisks(&printer{w: &sb}, f.Risks)
		for line := range strings.SplitSeq(strings.TrimRight(sb.String(), "\n"), "\n") {
			p.f("- %s\n", mdText(strings.TrimSpace(line)))
		}
		p.f("\n")
	}
	for _, s := range f.Scripts {
		p.f("命令：\n\n```\n%s\n```\n\n回退：\n\n```\n%s\n```\n", strings.Join(s.Commands, "\n"), strings.Join(s.Rollback, "\n"))
	}
}

// mdPlanned writes a rule the plan adds or modifies as a table.
func mdPlanned(p *printer, n int, pr report.PlannedRule) {
	r := pr.Rule
	title := "新增策略 " + firstOf(r.Name, r.Rule)
	if pr.Kind != "add" {
		title = "修改" + hitLabel(r.Rule, r.Name)
	} else if pr.Before != "" {
		title += "（放在策略 " + pr.Before + " 之前）"
	}
	p.f("%d. **%s**\n\n| 项 | 内容 |\n|---|---|\n", n, mdText(title))
	p.f("| 区域 | %s → %s |\n", mdCell(zoneList(r.From)), mdCell(zoneList(r.To)))
	p.f("| 源地址 | %s |\n| 目的地址 | %s |\n| 服务 | %s |\n", mdCell(objectsBrief(r.Source, r.NegateSource)), mdCell(objectsBrief(r.Destination, r.NegateDest)), mdCell(objectsBrief(r.Services, false)))
	when := "永久"
	if line := timeBound(r); line != "" {
		when = line
	}
	p.f("| 时间 | %s |\n| 日志 | %s |\n", mdCell(when), mdCell(strings.TrimPrefix(logText(r.Log), "日志 ")))
	if pr.Original != nil {
		o := *pr.Original
		p.f("| 修改前 | 源 %s；目的 %s；服务 %s |\n", mdCell(objectsBrief(o.Source, o.NegateSource)), mdCell(objectsBrief(o.Destination, o.NegateDest)), mdCell(objectsBrief(o.Services, false)))
	}
	p.f("\n")
}
