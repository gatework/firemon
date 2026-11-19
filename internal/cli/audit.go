package cli

import (
	"strings"

	"github.com/spf13/cobra"

	"github.com/gatework/firemon/audit"
)

func newAuditCmd(o *options) *cobra.Command {
	return &cobra.Command{
		Use:   "audit",
		Short: "策略审计：冗余、被覆盖、过期、禁用、全放通策略，以及未使用的对象",
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
			rows := make([][]string, 0, len(r.Findings))
			for _, f := range r.Findings {
				subject := f.Rule
				if subject == "" {
					subject = f.Object
				}
				detail := zhReason(f.Detail)
				if len(f.By) > 0 {
					detail = "被策略 " + strings.Join(f.By, ",") + " 覆盖"
				}
				rows = append(rows, []string{text(auditKindText, f.Kind, f.Kind.String()), subject, detail})
			}
			p := &printer{w: cmd.OutOrStdout()}
			p.table("问题\t策略/对象\t说明", rows)
			if len(r.Incomplete) > 0 {
				p.f("以下策略的覆盖分析超出预算，未完成：%s\n", strings.Join(r.Incomplete, ","))
			}
			return p.err
		},
	}
}
