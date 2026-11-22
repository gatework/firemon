package cli

import (
	"strings"

	"github.com/spf13/cobra"

	"github.com/gatework/firemon/audit"
)

func newAuditCmd(o *options) *cobra.Command {
	var verbosity int
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "策略审计：冗余、被覆盖、过期、禁用、全放通策略，以及未使用的对象",
		Long:  "默认按问题类别汇总数量；-v 逐条列出策略或对象与说明。治理与清理脚本见 firemon converge，全网总览见 firemon health。",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			loaded, _, err := o.load(cmd.Context())
			if err != nil {
				return err
			}
			r := audit.Run(loaded.Firewall, audit.Options{Now: o.deps.Now})
			if o.json {
				return writeJSON(cmd.OutOrStdout(), r)
			}
			p := &printer{w: cmd.OutOrStdout()}
			printAudit(p, r, verbosity > 0)
			return p.err
		},
	}
	cmd.Flags().CountVarP(&verbosity, "verbose", "v", "逐条列出")
	return cmd
}

// printAudit counts the findings by kind, in the order they first appear;
// verbose lists each.
func printAudit(p *printer, r audit.Report, verbose bool) {
	var kinds []audit.Kind
	counts := map[audit.Kind]int{}
	for _, f := range r.Findings {
		if counts[f.Kind] == 0 {
			kinds = append(kinds, f.Kind)
		}
		counts[f.Kind]++
	}
	if len(kinds) == 0 {
		p.f("没有发现问题\n")
	}
	rows := [][]string{{"问题", "数量"}}
	for _, k := range kinds {
		rows = append(rows, []string{text(auditKindText, k, k.String()), itoa(counts[k])})
	}
	if len(kinds) > 0 {
		columns(p, "", rows)
	}
	if len(r.Incomplete) > 0 {
		p.f("覆盖分析未完成的策略：%s\n", strings.Join(r.Incomplete, ","))
	}
	if !verbose {
		if len(kinds) > 0 {
			p.f("\n（-v 逐条列出；firemon converge --plan 生成已验证的清理脚本）\n")
		}
		return
	}
	detail := make([][]string, 0, len(r.Findings))
	for _, f := range r.Findings {
		subject := f.Rule
		if subject == "" {
			subject = f.Object
		}
		d := zhReason(f.Detail)
		if len(f.By) > 0 {
			d = "被策略 " + strings.Join(f.By, ",") + " 覆盖"
		}
		detail = append(detail, []string{text(auditKindText, f.Kind, f.Kind.String()), subject, d})
	}
	p.f("\n")
	p.table("问题\t策略/对象\t说明", detail)
}
