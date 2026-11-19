package cli

import (
	"strconv"

	"github.com/spf13/cobra"

	"github.com/gatework/firemon/query"
	"github.com/gatework/firemon/traffic"
)

func newUsageCmd(o *options) *cobra.Command {
	var addr string
	var withAny bool
	cmd := &cobra.Command{
		Use:   "usage",
		Short: "列出引用某个地址的地址对象和策略",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			a, err := traffic.ParseAddressSet(addr)
			if err != nil {
				return &usageError{err}
			}
			loaded, _, err := o.load(cmd.Context())
			if err != nil {
				return err
			}
			u := query.New(loaded.Firewall, query.Options{Now: o.deps.Now}).Usage(a, withAny)
			type objectView struct {
				Name     string `json:"name"`
				Relation string `json:"relation"`
			}
			type ruleView struct {
				Rule        string `json:"rule"`
				Source      string `json:"source"`
				Destination string `json:"destination"`
			}
			var objects []objectView
			for _, ob := range u.Objects {
				objects = append(objects, objectView{ob.Name, usageRelation(ob.Relation)})
			}
			var rules []ruleView
			for _, r := range u.Rules {
				rules = append(rules, ruleView{ruleLabel(r.Rule), usageRelation(r.Source), usageRelation(r.Destination)})
			}
			if o.json {
				return writeJSON(cmd.OutOrStdout(), map[string]any{"objects": objects, "rules": rules})
			}
			p := &printer{w: cmd.OutOrStdout()}
			orows := make([][]string, 0, len(objects))
			for _, ob := range objects {
				orows = append(orows, []string{ob.Name, ob.Relation})
			}
			p.table("对象\t关系", orows)
			rrows := make([][]string, 0, len(rules))
			for _, r := range rules {
				rrows = append(rrows, []string{r.Rule, r.Source, r.Destination})
			}
			p.f("\n")
			p.table("策略\t源\t目的", rrows)
			return p.err
		},
	}
	cmd.Flags().StringVar(&addr, "addr", "", "要查找的地址、网段或范围")
	cmd.Flags().BoolVar(&withAny, "include-any", false, "同时列出源或目的为任意地址的策略")
	return cmd
}

// usageRelation says how an object or rule side relates to the searched
// addresses, from the object's point of view.
func usageRelation(r traffic.Relation) string {
	switch r {
	case traffic.RelationEqual:
		return "相等"
	case traffic.RelationSuperset:
		return "包含所查地址"
	case traffic.RelationSubset:
		return "在所查地址之内"
	case traffic.RelationOverlap:
		return "部分重叠"
	case traffic.RelationDisjoint:
		return "-"
	case traffic.RelationUnset:
	}
	return r.String()
}

func itoa(n int) string { return strconv.Itoa(n) }
