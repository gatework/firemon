package cli

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/gatework/firemon/adapter/filestore"
	"github.com/gatework/firemon/adapter/yamlfile"
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
			inv, platforms, err := o.inventory(cmd)
			if err != nil {
				return err
			}
			intent, err := in.intent(intakeOptions(platforms).Services)
			if err != nil {
				return err
			}
			tr, err := inv.Locate(query.Request{Src: intent.Src, Dst: intent.Dst, Service: intent.Service, VirtualRouter: intent.VirtualRouter})
			if err != nil {
				return err
			}
			plans := map[string]*design.Plan{}
			if plan {
				cps, err := inv.Plan(intent)
				if err != nil {
					return err
				}
				for _, cp := range cps {
					if _, seen := plans[cp.Cluster]; !seen {
						plans[cp.Cluster] = cp.Plan
					}
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

// fleetMember is one firewall to load: its member name, cluster and
// snapshot.
type fleetMember struct {
	name, cluster, snapshot string
	active                  bool
}

// inventory loads the fleet: the firewalls of --inventory with their
// clusters and protected networks, or every stored snapshot.
func (o *options) inventory(cmd *cobra.Command) (*inventory.Inventory, map[string]bootstrap.Platform, error) {
	store, err := filestore.New(o.store)
	if err != nil {
		return nil, nil, err
	}
	fleet, protections, err := o.fleet(cmd, store)
	if err != nil {
		return nil, nil, err
	}
	var members []inventory.Member
	platforms := map[string]bootstrap.Platform{}
	for _, fm := range fleet {
		snap, err := store.Load(cmd.Context(), fm.snapshot)
		if err != nil {
			return nil, nil, fmt.Errorf("firewall %s: %w", fm.name, err)
		}
		loaded, err := workflow.FromConfig(snap.Config)
		if err != nil {
			return nil, nil, err
		}
		if platforms[fm.name], err = bootstrap.Lookup(snap.Vendor, snap.Config.Location, nil); err != nil {
			return nil, nil, err
		}
		members = append(members, inventory.Member{
			Name: fm.name, Cluster: fm.cluster, Firewall: loaded.Firewall, Naming: platforms[fm.name].Naming,
			Active: fm.active,
		})
	}
	inv, err := inventory.New(members, inventory.Options{Now: o.deps.Now, Protections: protections})
	return inv, platforms, err
}

func (o *options) fleet(cmd *cobra.Command, store *filestore.Store) ([]fleetMember, []inventory.Protection, error) {
	if o.inventoryFile != "" {
		f, err := yamlfile.Load(o.inventoryFile)
		if err != nil {
			return nil, nil, err
		}
		protections, err := f.Protections(cmd.Context())
		if err != nil {
			return nil, nil, err
		}
		out := make([]fleetMember, 0, len(f.Firewalls))
		for _, fw := range f.Firewalls {
			out = append(out, fleetMember{name: fw.Name, cluster: fw.Cluster, snapshot: fw.SnapshotOf(), active: fw.Active()})
		}
		return out, protections, nil
	}
	snaps, err := store.List(cmd.Context())
	if err != nil {
		return nil, nil, err
	}
	if len(snaps) == 0 {
		return nil, nil, errors.New("no snapshots in " + o.store + "; store some with collect")
	}
	out := make([]fleetMember, 0, len(snaps))
	for _, s := range snaps {
		out = append(out, fleetMember{name: s.Device, snapshot: s.Device})
	}
	return out, nil, nil
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
		v := crossingView{Firewall: c.Cluster, Verdict: c.Verdict}
		for _, p := range c.Paths {
			v.Paths = append(v.Paths, viewPath(p))
		}
		if p, ok := plans[c.Cluster]; ok {
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
