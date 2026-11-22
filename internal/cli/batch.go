package cli

import (
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/internal/bootstrap"
	"github.com/gatework/firemon/inventory"
	"github.com/gatework/firemon/report"
)

// ticket is one row of a batch file: an access request with its ticket
// number, which names the rules designed for it.
type ticket struct {
	Line        int    `json:"line"`
	ID          string `json:"ticket"`
	Src         string `json:"src"`
	Dst         string `json:"dst"`
	Service     string `json:"service"`
	FromZone    string `json:"from_zone,omitempty"`
	ToZone      string `json:"to_zone,omitempty"`
	Until       string `json:"until,omitempty"`
	Description string `json:"description,omitempty"`
}

// ticketResult is a ticket answered, or why it could not be.
type ticketResult struct {
	Ticket ticket         `json:"ticket"`
	Report *report.Report `json:"report,omitempty"`
	Error  string         `json:"error,omitempty"`
	// DependsOn are the earlier tickets whose new rules this ticket's plan
	// modifies: they must be deployed first.
	DependsOn []string `json:"depends_on,omitempty"`
	answer    answer
	fws       map[string]*firemon.Firewall
	err       error
}

// readTickets reads a CSV batch file: ticket, source, destination,
// service, then optional source zone, destination zone, end of access and
// description. A first row naming the columns is skipped; so are blank
// rows and rows starting with #.
func readTickets(path string) ([]ticket, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, &usageError{fmt.Errorf("读取批量文件 %s 失败：%w", path, err)}
	}
	defer f.Close()
	r := csv.NewReader(f)
	r.FieldsPerRecord, r.TrimLeadingSpace, r.Comment = -1, true, '#'
	var out []ticket
	for line := 1; ; line++ {
		rec, err := r.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, &usageError{fmt.Errorf("批量文件 %s 第 %d 行：%w", path, line, err)}
		}
		for i := range rec {
			rec[i] = strings.TrimSpace(strings.TrimPrefix(rec[i], "\uFEFF"))
		}
		if len(rec) == 0 || strings.Join(rec, "") == "" {
			continue
		}
		if len(out) == 0 && header(rec[0]) {
			continue
		}
		if len(rec) < 4 {
			return nil, &usageError{fmt.Errorf("批量文件 %s 第 %d 行：至少需要 工单号,源,目的,服务 四列", path, line)}
		}
		t := ticket{Line: line, ID: rec[0], Src: rec[1], Dst: rec[2], Service: rec[3]}
		for i, dst := range []*string{&t.FromZone, &t.ToZone, &t.Until, &t.Description} {
			if len(rec) > 4+i {
				*dst = rec[4+i]
			}
		}
		out = append(out, t)
	}
	if len(out) == 0 {
		return nil, &usageError{fmt.Errorf("批量文件 %s 没有工单", path)}
	}
	return out, nil
}

// header reports a first cell that names the ticket column.
func header(cell string) bool {
	low := strings.ToLower(cell)
	return strings.Contains(cell, "工单") || low == "ticket" || low == "id" || low == "no" || cell == "编号"
}

// batch answers every ticket of --file in order. On a firewall several
// tickets change, each is designed on the configuration the verified
// plans before it leave: their objects are reused and their rule IDs do
// not collide. The summary comes first, then each ticket in full.
func (o *options) batch(cmd *cobra.Command, f checkFlags, format string, inv *inventory.Inventory, platforms map[string]bootstrap.Platform) error {
	tickets, err := readTickets(f.file)
	if err != nil {
		return err
	}
	results := make([]ticketResult, 0, len(tickets))
	created := map[string]string{} // cluster/rule ID -> ticket that adds it
	for _, t := range tickets {
		tf := f
		tf.src, tf.dst, tf.service = t.Src, t.Dst, t.Service
		tf.name = t.ID
		tf.fromZone, tf.toZone = firstOf(t.FromZone, f.fromZone), firstOf(t.ToZone, f.toZone)
		tf.until, tf.description = firstOf(t.Until, f.until), firstOf(t.Description, f.description)
		fws := clusterFirewalls(inv)
		a, err := o.answer(cmd, tf, inv, platforms, fws)
		res := ticketResult{Ticket: t, answer: a, fws: fws, err: err}
		if err != nil {
			res.Error = err.Error()
		} else {
			res.Report = &a.rep
			res.DependsOn = dependencies(a.rep, created, t.ID)
			next, aerr := inv.Applied(a.plans)
			if aerr != nil {
				return aerr
			}
			inv = next
		}
		results = append(results, res)
	}
	if err := writeBatch(cmd, format, results, platforms, reportView{detail: f.verbosity >= 1, verbose: f.verbosity >= 2}); err != nil {
		return err
	}
	return batchExit(results, f.plan)
}

func firstOf(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// clusterFirewalls maps each cluster to the firewall it is evaluated on.
func clusterFirewalls(inv *inventory.Inventory) map[string]*firemon.Firewall {
	out := map[string]*firemon.Firewall{}
	for _, name := range inv.Clusters() {
		out[name] = inv.Firewall(name)
	}
	return out
}

// batchExit is the worst exit of the tickets: one that could not be
// answered or needs a person outweighs one that needs a change.
func batchExit(results []ticketResult, designed bool) error {
	var worst error
	for _, r := range results {
		err := r.err
		if err == nil {
			err = checkExit(r.answer.rep, designed)
		} else {
			err = errUndecided
		}
		switch {
		case errors.Is(err, errUndecided):
			worst = errUndecided
		case errors.Is(err, errNotAllowed) && worst == nil:
			worst = errNotAllowed
		}
	}
	return worst
}

// writeBatch writes the summary table and each ticket.
func writeBatch(cmd *cobra.Command, format string, results []ticketResult, platforms map[string]bootstrap.Platform, base reportView) error {
	if format == formatJSON {
		return writeJSON(cmd.OutOrStdout(), results)
	}
	p := &printer{w: cmd.OutOrStdout()}
	md := format == formatMarkdown
	if md {
		p.f("## 批量工单汇总（%d 单）\n\n| 工单 | 请求 | 结论 | 变更 |\n|---|---|---|---|\n", len(results))
	} else {
		p.f("批量工单汇总（%d 单）：\n", len(results))
	}
	for _, r := range results {
		t := r.Ticket
		request := t.Src + " → " + t.Dst + " " + t.Service
		verdict, change := "无法处理："+r.Error, "-"
		if r.Report != nil {
			verdict = conclusion(*r.Report) + flowSummary(r.Report.Flows)
			change = changeSummary(*r.Report)
			if len(r.DependsOn) > 0 {
				change += "（修改工单 " + strings.Join(r.DependsOn, "、") + " 新建的策略，需在其后下发）"
			}
		}
		if md {
			p.f("| %s | %s | %s | %s |\n", mdCell(t.ID), mdCell(request), mdCell(verdict), mdCell(change))
		} else {
			p.f("  %-16s %s\n      %s；%s\n", t.ID, request, verdict, change)
		}
	}
	if p.err != nil {
		return p.err
	}
	for _, r := range results {
		if r.Report == nil {
			continue
		}
		view := base
		view.plans, view.platforms, view.fws = r.answer.plans, platforms, r.fws
		if md {
			p.f("\n---\n\n# 工单 %s\n\n", r.Ticket.ID)
		} else {
			p.f("\n==================== 工单 %s（第 %d 行） ====================\n", r.Ticket.ID, r.Ticket.Line)
		}
		if p.err != nil {
			return p.err
		}
		if err := writeReport(cmd, format, *r.Report, view); err != nil {
			return err
		}
	}
	return nil
}

// changeSummary says what a report's plans change, device by device.
func changeSummary(rep report.Report) string {
	var parts []string
	for _, f := range rep.Firewalls {
		add, mod := 0, 0
		for _, pr := range f.Planned {
			if pr.Kind == "add" {
				add++
			} else {
				mod++
			}
		}
		if add+mod == 0 {
			continue
		}
		what := ""
		if add > 0 {
			what = "新增 " + itoa(add) + " 条"
		}
		if mod > 0 {
			what = strings.TrimSpace(what + " 修改 " + itoa(mod) + " 条")
		}
		parts = append(parts, firewallLabel(f)+" "+what)
	}
	if len(parts) == 0 {
		return "无需变更"
	}
	return strings.Join(parts, "；")
}

// dependencies records the rules a ticket adds and returns the earlier
// tickets whose rules it modifies.
func dependencies(rep report.Report, created map[string]string, id string) []string {
	var out []string
	for _, f := range rep.Firewalls {
		for _, pr := range f.Planned {
			key := f.Cluster + "/" + pr.Rule.Rule
			switch {
			case pr.Kind == "add":
				created[key] = id
			case created[key] != "" && created[key] != id && !slices.Contains(out, created[key]):
				out = append(out, created[key])
			}
		}
	}
	return out
}
