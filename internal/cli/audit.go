package cli

import (
	"strings"

	"github.com/spf13/cobra"

	"github.com/gatework/firemon/audit"
)

func newAuditCmd(o *options) *cobra.Command {
	return &cobra.Command{
		Use:   "audit",
		Short: "Find redundant, shadowed, expired and disabled rules, permit-any rules and unused objects",
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
				detail := f.Detail
				if len(f.By) > 0 {
					detail = "covered by " + strings.Join(f.By, ",")
				}
				rows = append(rows, []string{f.Kind.String(), subject, detail})
			}
			p := &printer{w: cmd.OutOrStdout()}
			p.table("FINDING\tRULE/OBJECT\tDETAIL", rows)
			if len(r.Incomplete) > 0 {
				p.f("shadowing analysis incomplete for rules %s\n", strings.Join(r.Incomplete, ","))
			}
			return p.err
		},
	}
}
