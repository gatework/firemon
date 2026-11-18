package cli

import (
	"bufio"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/gatework/firemon/internal/bootstrap"
	"github.com/gatework/firemon/internal/workflow"
)

func newDeployCmd(o *options) *cobra.Command {
	var in intentFlags
	var apply, yes bool
	var journalRoot string
	cmd := &cobra.Command{
		Use:   "deploy",
		Short: "Design a change on the live device and, with --apply, push, verify and save it",
		Long: "deploy reads the running configuration, designs and renders the change, and prints it.\n" +
			"Nothing is sent unless --apply is given and confirmed. With --apply the device must still\n" +
			"match the configuration the plan was designed on; every write is journaled, nothing is\n" +
			"retried, and the configuration is read back and checked before it is saved or committed.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if o.file != "" {
				return &usageError{errors.New("deploy reads the device; do not set --config")}
			}
			intent, err := in.intent()
			if err != nil {
				return err
			}
			loaded, platform, err := o.load(cmd.Context())
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
			if !apply || len(prop.Plan.Changes) == 0 {
				return nil
			}
			if !prop.Plan.Verified {
				return errors.New("the plan is not verified; refusing to deploy")
			}
			if !yes && !confirm(cmd) {
				return errors.New("not confirmed; nothing was sent")
			}
			return o.push(cmd, platform, prop, journalRoot)
		},
	}
	in.register(cmd)
	f := cmd.Flags()
	f.BoolVar(&apply, "apply", false, "send the change to the device (default: dry run)")
	f.BoolVar(&yes, "yes", false, "do not ask for confirmation with --apply")
	f.StringVar(&journalRoot, "journal", defaultJournalRoot(), "directory for deployment journals")
	return cmd
}

func (o *options) push(cmd *cobra.Command, platform bootstrap.Platform, prop workflow.Proposal, journalRoot string) error {
	client, err := o.device.client(platform, o.deps.Getenv)
	if err != nil {
		return err
	}
	journal, dir, err := bootstrap.Journal(journalRoot)
	if err != nil {
		return err
	}
	receipt, err := workflow.Apply(cmd.Context(), client, platform, prop, journal, o.deps.Now)
	p := &printer{w: cmd.OutOrStdout()}
	p.f("\ndeployment %s, journal %s\n", receipt.State.Status, dir)
	if err != nil {
		p.f("rollback commands are listed above; nothing will be retried automatically\n")
		return errors.Join(err, p.err)
	}
	return p.err
}

func confirm(cmd *cobra.Command) bool {
	p := &printer{w: cmd.OutOrStdout()}
	p.f("\nsend these commands to the device? type yes to continue: ")
	line, err := bufio.NewReader(cmd.InOrStdin()).ReadString('\n')
	return (err == nil || line != "") && strings.TrimSpace(line) == "yes"
}

func defaultJournalRoot() string {
	dir, err := os.UserCacheDir()
	if err != nil {
		return "firemon-journal"
	}
	return filepath.Join(dir, "firemon", "deploy")
}
