package cli

import (
	"errors"
	"os"
	"strconv"
	"time"

	"github.com/spf13/cobra"

	"github.com/gatework/firemon/adapter/filestore"
	"github.com/gatework/firemon/hits"
)

func newHitsCmd(o *options) *cobra.Command {
	var name, command, file string
	var show bool
	cmd := &cobra.Command{
		Use:   "hits",
		Short: "Collect a device's rule hit counters (read-only), import them, or show the stored ones",
		Long: "hits reads the rule hit counters of the device (--host, --user) with a read-only command and stores\n" +
			"them under --store for the snapshot --name; --file imports counters exported as JSON or CSV\n" +
			"(columns rule,hits[,last_hit,first_hit,reset]); --show prints the latest stored counters.\n" +
			"converge uses them as evidence that a rule is unused.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if name == "" {
				return &usageError{errors.New("--name is required")}
			}
			store, err := filestore.New(o.store)
			if err != nil {
				return err
			}
			if show {
				snap, err := store.LatestHits(cmd.Context(), name)
				if err != nil {
					return err
				}
				return printHits(o, cmd, snap)
			}
			snap, err := o.readHits(cmd, name, command, file)
			if err != nil {
				return err
			}
			if err := store.SaveHits(cmd.Context(), name, snap); err != nil {
				return err
			}
			return printHits(o, cmd, snap)
		},
	}
	f := cmd.Flags()
	f.StringVar(&name, "name", "", "snapshot name the counters belong to")
	f.StringVar(&command, "command", "", "read-only command that lists the counters (default: the vendor's)")
	f.StringVar(&file, "file", "", "import counters from a JSON or CSV file instead of the device")
	f.BoolVar(&show, "show", false, "print the latest stored counters")
	return cmd
}

// readHits reads counters from a file or the device.
func (o *options) readHits(cmd *cobra.Command, name, command, file string) (hits.Snapshot, error) {
	now := o.deps.Now()
	if file != "" {
		fh, err := os.Open(file)
		if err != nil {
			return hits.Snapshot{}, err
		}
		defer fh.Close()
		snap, err := hits.Decode(fh, now, time.Time{})
		snap.Firewall = name
		return snap, err
	}
	p, err := o.platform()
	if err != nil {
		return hits.Snapshot{}, err
	}
	client, err := o.device.client(p, o.deps.Getenv)
	if err != nil {
		return hits.Snapshot{}, err
	}
	if command == "" {
		command = p.HitCountCommand
	}
	text, err := client.Show(cmd.Context(), command)
	if err != nil {
		return hits.Snapshot{}, err
	}
	return p.ParseHits(text, name, now)
}

func printHits(o *options, cmd *cobra.Command, snap hits.Snapshot) error {
	if o.json {
		return writeJSON(cmd.OutOrStdout(), snap)
	}
	rows := make([][]string, 0, len(snap.Counters))
	for _, c := range snap.Counters {
		last := "-"
		if !c.LastHit.IsZero() {
			last = c.LastHit.Format(time.RFC3339)
		}
		rows = append(rows, []string{c.Rule, strconv.FormatUint(c.Hits, 10), last})
	}
	p := &printer{w: cmd.OutOrStdout()}
	p.f("%s: %d counters, taken %s\n", snap.Firewall, len(snap.Counters), snap.Taken.Format(time.RFC3339))
	p.table("RULE\tHITS\tLAST HIT", rows)
	return p.err
}
