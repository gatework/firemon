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
		Short: "打印厂商实际生效的预定义服务表",
		Long: "打印 firemon 对 --vendor 采用的预定义服务：内置默认值，再用 --service-book 覆盖。\n" +
			"不同型号和版本的内置服务有差异；请与设备对照，把修正后的 JSON 保存下来并用 --service-book 指定。",
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
			pr.table("服务\t端口", rows)
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
