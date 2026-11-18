package cli

import (
	"strings"

	"github.com/spf13/cobra"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/design"
	"github.com/gatework/firemon/internal/workflow"
)

// intentFlags extend the traffic flags with what a new rule records.
type intentFlags struct {
	trafficFlags
	nat                         natFlags
	name, description, schedule string
	override                    bool
}

func (i *intentFlags) register(cmd *cobra.Command) {
	i.trafficFlags.register(cmd)
	f := cmd.Flags()
	f.StringVar(&i.name, "name", "", "name of new rules (default fm_<n>)")
	f.StringVar(&i.description, "description", "", "description of new rules, for example the ticket")
	f.StringVar(&i.schedule, "schedule", "", "existing schedule to attach to new rules")
	f.BoolVar(&i.override, "override", false, "place new rules above specific deny rules instead of reporting conflicts")
	i.nat.register(f)
}

func (i *intentFlags) intent(book firemon.ServiceBook) (design.Intent, error) {
	t, err := i.parse(book)
	if err != nil {
		return design.Intent{}, err
	}
	nat, err := i.nat.intent()
	if err != nil {
		return design.Intent{}, &usageError{err}
	}
	return design.Intent{
		Src: t.src, Dst: t.dst, Service: t.service,
		FromZone: i.fromZone, ToZone: i.toZone, VirtualRouter: i.vr,
		Name: i.name, Description: i.description, Schedule: i.schedule, Override: i.override, NAT: nat,
	}, nil
}

func newDesignCmd(o *options) *cobra.Command {
	var in intentFlags
	cmd := &cobra.Command{
		Use:   "design",
		Short: "Design and render the change that permits traffic, without touching the device",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			loaded, platform, err := o.load(cmd.Context())
			if err != nil {
				return err
			}
			intent, err := in.intent(platform.Services)
			if err != nil {
				return err
			}
			prop, err := workflow.Propose(loaded.Firewall, platform, intent, o.deps.Now)
			if err != nil {
				return err
			}
			if err := printProposal(cmd, o.json, prop); err != nil {
				return err
			}
			if !prop.Plan.Verified {
				return errNotAllowed
			}
			return nil
		},
	}
	in.register(cmd)
	return cmd
}

// proposalView is the JSON form of a proposal.
type proposalView struct {
	*design.Plan
	ChangeList []string      `json:"changes"`
	Script     design.Script `json:"script"`
}

func printProposal(cmd *cobra.Command, asJSON bool, prop workflow.Proposal) error {
	changes := make([]string, len(prop.Plan.Changes))
	for i, c := range prop.Plan.Changes {
		changes[i] = c.String()
	}
	if asJSON {
		return writeJSON(cmd.OutOrStdout(), proposalView{Plan: prop.Plan, ChangeList: changes, Script: prop.Script})
	}
	p := &printer{w: cmd.OutOrStdout()}
	plan := prop.Plan
	p.f("status: %s  verified: %v  baseline: %s\n", plan.Status, plan.Verified, plan.Baseline[:16])
	if plan.VerifyError != "" {
		p.f("verification failed: %s\n", plan.VerifyError)
	}
	if n := plan.NAT; n != nil {
		p.f("nat: %s", n.Status)
		switch {
		case len(n.Existing) > 0:
			p.f(" by rule %s", strings.Join(n.Existing, ","))
		case n.Rule != "":
			p.f(" rule %s", n.Rule)
			if n.Before != "" {
				p.f(" before %s (NAT matches in order)", n.Before)
			}
		}
		if n.Address != "" {
			p.f(" address %s", n.Address)
		}
		if n.Interface != "" {
			p.f(" interface address of %s", n.Interface)
		}
		if n.Reused {
			p.f(" (reused)")
		}
		if n.Reason != "" {
			p.f(": %s", n.Reason)
		}
		p.f("\n")
	}
	for _, c := range plan.Conflicts {
		p.f("conflict: rule %s denies %s -> %s: %s (use --override to place new rules above it)\n", c.RuleID, c.From, c.To, c.Text)
	}
	for _, u := range plan.Unknown {
		p.f("undecidable: %s\n", u)
	}
	for _, w := range plan.Warnings {
		p.f("warning: %s\n", w)
	}
	if len(changes) > 0 {
		p.f("\nchanges:\n  %s\n", strings.Join(changes, "\n  "))
		p.f("\ncommands:\n%s\n", strings.Join(prop.Script.Commands, "\n"))
		p.f("\nrollback:\n%s\n", strings.Join(prop.Script.Rollback, "\n"))
	}
	return p.err
}
