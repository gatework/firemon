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
		Short: "Show how the firewall treats traffic: paths, NAT, deciding rules and verdict",
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
	p.f("verdict: %s\n", res.Verdict)
	if !res.Unrouted.IsEmpty() {
		p.f("unrouted: %s\n", res.Unrouted)
	}
	for _, v := range views {
		p.f("\n%s -> %s  (%s -> %s)  %s\n", v.From, v.To, v.Ingress, v.Egress, v.Verdict)
		if v.DestinationNAT != "" {
			p.f("  %s\n", v.DestinationNAT)
		}
		for _, s := range v.SourceNAT {
			p.f("  %s\n", s)
		}
		rows := make([][]string, 0, len(v.Decisions))
		for _, d := range v.Decisions {
			possible := ""
			if len(d.Possible) > 0 {
				possible = "maybe " + strconv.Itoa(len(d.Possible)) + " undecidable rule(s) first"
			}
			rows = append(rows, []string{"  " + d.Rule, d.Outcome.String(), d.Space, possible})
		}
		p.table("  RULE\tOUTCOME\tTRAFFIC\tNOTE", rows)
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
		Short: "List the address objects and rules that reference an address",
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
			p.table("OBJECT\tRELATION", orows)
			rrows := make([][]string, 0, len(rules))
			for _, r := range rules {
				rrows = append(rrows, []string{r.Rule, r.Source, r.Destination})
			}
			p.f("\n")
			p.table("RULE\tSOURCE\tDESTINATION", rrows)
			return p.err
		},
	}
	cmd.Flags().StringVar(&addr, "addr", "", "address, prefix or range to look up")
	cmd.Flags().BoolVar(&withAny, "include-any", false, "also list rules that match any address on a side")
	return cmd
}

func itoa(n int) string { return strconv.Itoa(n) }
