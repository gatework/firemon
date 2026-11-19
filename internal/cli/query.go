package cli

import (
	"strconv"

	"github.com/spf13/cobra"

	"github.com/gatework/firemon/query"
	"github.com/gatework/firemon/traffic"
)

func newQueryCmd(o *options) *cobra.Command {
	var t trafficFlags
	cmd := &cobra.Command{
		Use:   "query",
		Short: "单台防火墙的流量判定：路径、NAT、命中策略与结论",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			loaded, platform, err := o.load(cmd.Context())
			if err != nil {
				return err
			}
			req, err := t.parse(platform.Services)
			if err != nil {
				return err
			}
			e := query.New(loaded.Firewall, query.Options{Now: o.deps.Now})
			res, err := e.Query(query.Request{
				Src: req.src, Dst: req.dst, Service: req.service, At: req.at, DstDomains: req.domains, Applications: req.apps,
				FromZone: t.fromZone, ToZone: t.toZone, VirtualRouter: t.vr,
			})
			if err != nil {
				return err
			}
			if err := printQuery(cmd, o.json, res); err != nil {
				return err
			}
			if res.Verdict != query.VerdictAllowed {
				return errNotAllowed
			}
			return nil
		},
	}
	t.register(cmd)
	return cmd
}

func printQuery(cmd *cobra.Command, asJSON bool, res *query.Result) error {
	views := make([]pathView, len(res.Paths))
	for i, p := range res.Paths {
		views[i] = viewPath(p)
	}
	if asJSON {
		return writeJSON(cmd.OutOrStdout(), struct {
			Verdict  query.Verdict `json:"verdict"`
			Unrouted string        `json:"unrouted,omitempty"`
			Paths    []pathView    `json:"paths"`
		}{res.Verdict, unrouted(res.Unrouted), views})
	}
	p := &printer{w: cmd.OutOrStdout()}
	p.f("结论：%s\n", text(verdictText, res.Verdict, res.Verdict.String()))
	if !res.Unrouted.IsEmpty() {
		p.f("无路由的目的：%s\n", res.Unrouted)
	}
	for _, v := range views {
		p.f("\n路径 %s → %s（%s → %s）：%s\n", v.From, v.To, orDash(v.Ingress), orDash(v.Egress), text(verdictText, v.Verdict, v.Verdict.String()))
		for _, n := range natLines(v.path) {
			p.f("  %s\n", n)
		}
		rows := make([][]string, 0, len(v.Decisions))
		for _, d := range v.Decisions {
			possible := ""
			if len(d.Possible) > 0 {
				possible = "前面可能有 " + strconv.Itoa(len(d.Possible)) + " 条无法离线判定的策略先命中"
			}
			rows = append(rows, []string{"  " + defaultLabel(d.Rule), text(outcomeText, d.Outcome, d.Outcome.String()), d.Space, possible})
		}
		p.table("  策略\t结果\t流量\t备注", rows)
	}
	return p.err
}

func unrouted(s traffic.AddressSet) string {
	if s.IsEmpty() {
		return ""
	}
	return s.String()
}

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
				objects = append(objects, objectView{ob.Name, ob.Relation.String()})
			}
			var rules []ruleView
			for _, r := range u.Rules {
				rules = append(rules, ruleView{ruleLabel(r.Rule), r.Source.String(), r.Destination.String()})
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

func itoa(n int) string { return strconv.Itoa(n) }
