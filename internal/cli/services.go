package cli

import (
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/gatework/firemon"
)

func newServicesCmd(o *options) *cobra.Command {
	return &cobra.Command{
		Use:   "services",
		Short: "Print the effective predefined service book of a vendor",
		Long: "services prints the predefined services firemon assumes for --vendor: the built-in default\n" +
			"overridden by --service-book. Built-in services differ by model and release; compare the output\n" +
			"with the device, save the corrected JSON and pass it with --service-book.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			p, err := o.platform()
			if err != nil {
				return err
			}
			if o.json {
				return writeJSON(cmd.OutOrStdout(), p.Services)
			}
			rows := make([][]string, 0, len(p.Services))
			for _, name := range p.Services.Names() {
				exprs := make([]string, 0, len(p.Services[name]))
				for _, e := range p.Services[name] {
					exprs = append(exprs, e.String())
				}
				rows = append(rows, []string{name, strings.Join(exprs, ",")})
			}
			pr := &printer{w: cmd.OutOrStdout()}
			pr.table("SERVICE\tPORTS", rows)
			return pr.err
		},
	}
}

// serviceBook reads --service-book; nil means the vendor default.
func (o *options) serviceBook() (firemon.ServiceBook, error) {
	if o.book == "" {
		return nil, nil //nolint:nilnil // a nil book selects the vendor default
	}
	raw, err := os.ReadFile(o.book)
	if err != nil {
		return nil, err
	}
	return firemon.ParseServiceBook(raw)
}
