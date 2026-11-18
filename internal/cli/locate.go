package cli

import (
	"errors"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/gatework/firemon/adapter/filestore"
	"github.com/gatework/firemon/design"
	"github.com/gatework/firemon/internal/bootstrap"
	"github.com/gatework/firemon/internal/workflow"
	"github.com/gatework/firemon/inventory"
	"github.com/gatework/firemon/query"
)

func newLocateCmd(o *options) *cobra.Command {
	var in intentFlags
	var plan bool
	cmd := &cobra.Command{
		Use:   "locate",
		Short: "Find the firewalls among all snapshots a flow crosses, with each verdict (and plans with --design)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			intent, err := in.intent()
			if err != nil {
				return err
			}
			inv, platforms, err := o.inventory(cmd)
			if err != nil {
				return err
			}
			tr, err := inv.Locate(query.Request{Src: intent.Src, Dst: intent.Dst, Service: intent.Service, VirtualRouter: intent.VirtualRouter})
			if err != nil {
				return err
			}
			var plans map[string]*design.Plan
			if plan {
				if plans, err = inv.Plan(intent); err != nil {
					return err
				}
			}
			if err := o.printTrace(cmd, tr, plans, platforms); err != nil {
				return err
			}
			if tr.Verdict != query.VerdictAllowed {
				return errNotAllowed
			}
			return nil
		},
	}
	in.register(cmd)
	cmd.Flags().BoolVar(&plan, "design", false, "design the change on every crossed firewall")
	return cmd
}

// inventory loads every snapshot in the store.
func (o *options) inventory(cmd *cobra.Command) (*inventory.Inventory, map[string]bootstrap.Platform, error) {
	store, err := filestore.New(o.store)
	if err != nil {
		return nil, nil, err
	}
	snaps, err := store.List(cmd.Context())
	if err != nil {
		return nil, nil, err
	}
	if len(snaps) == 0 {
		return nil, nil, errors.New("no snapshots in " + o.store + "; store some with collect")
	}
	var members []inventory.Member
	platforms := map[string]bootstrap.Platform{}
	for _, meta := range snaps {
		snap, err := store.Load(cmd.Context(), meta.Device)
		if err != nil {
			return nil, nil, err
		}
		loaded, err := workflow.FromConfig(snap.Config)
		if err != nil {
			return nil, nil, err
		}
		if platforms[snap.Device], err = bootstrap.Lookup(snap.Vendor, snap.Config.Location, nil); err != nil {
			return nil, nil, err
		}
		members = append(members, inventory.Member{Name: snap.Device, Firewall: loaded.Firewall})
	}
	inv, err := inventory.New(members, inventory.Options{Now: o.deps.Now})
	return inv, platforms, err
}

func (o *options) printTrace(cmd *cobra.Command, tr inventory.Trace, plans map[string]*design.Plan, platforms map[string]bootstrap.Platform) error {
	type crossingView struct {
		Firewall string        `json:"firewall"`
		Verdict  query.Verdict `json:"verdict"`
		Paths    []pathView    `json:"paths"`
		Plan     *proposalView `json:"plan,omitempty"`
	}
	var views []crossingView
	for _, c := range tr.Crossings {
		v := crossingView{Firewall: c.Firewall, Verdict: c.Verdict}
		for _, p := range c.Paths {
			v.Paths = append(v.Paths, viewPath(p))
		}
		if p, ok := plans[c.Firewall]; ok {
			script, err := platforms[c.Firewall].Render(p)
			if err != nil {
				return err
			}
			changes := make([]string, len(p.Changes))
			for i, ch := range p.Changes {
				changes[i] = ch.String()
			}
			v.Plan = &proposalView{Plan: p, ChangeList: changes, Script: script}
		}
		views = append(views, v)
	}
	if o.json {
		return writeJSON(cmd.OutOrStdout(), map[string]any{"verdict": tr.Verdict, "crossings": views})
	}
	p := &printer{w: cmd.OutOrStdout()}
	p.f("verdict: %s\n", tr.Verdict)
	for _, v := range views {
		zones := make([]string, 0, len(v.Paths))
		for _, pv := range v.Paths {
			zones = append(zones, pv.From+" -> "+pv.To)
		}
		p.f("\n%s  %s  %s\n", v.Firewall, v.Verdict, strings.Join(slices.Compact(zones), ", "))
		if v.Plan != nil {
			p.f("  plan: %s, verified %v\n", v.Plan.Status, v.Plan.Verified)
			for _, c := range v.Plan.Script.Commands {
				p.f("    %s\n", c)
			}
		}
	}
	return p.err
}
