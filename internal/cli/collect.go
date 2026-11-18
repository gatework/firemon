package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/adapter/filestore"
	"github.com/gatework/firemon/internal/bootstrap"
	"github.com/gatework/firemon/internal/workflow"
)

func newCollectCmd(o *options) *cobra.Command {
	var name string
	var list bool
	cmd := &cobra.Command{
		Use:   "collect",
		Short: "Store a device's configuration as a snapshot, or list the stored snapshots",
		Long: "collect reads the running configuration (or --config), parses it and stores it under --store\n" +
			"as the snapshot named --name; other commands use it with --snapshot NAME.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			store, err := filestore.New(o.store)
			if err != nil {
				return err
			}
			if list {
				return o.listSnapshots(cmd, store)
			}
			if name == "" {
				return &usageError{errors.New("--name is required")}
			}
			loaded, _, err := o.load(cmd.Context())
			if err != nil {
				return err
			}
			snap, err := store.Save(cmd.Context(), filestore.Snapshot{
				Device: name, Host: o.device.host, CollectedAt: o.deps.Now().UTC(), Config: loaded.Config, Raw: loaded.Raw,
			})
			if err != nil {
				return err
			}
			if o.json {
				return writeJSON(cmd.OutOrStdout(), snap)
			}
			p := &printer{w: cmd.OutOrStdout()}
			p.f("stored %s (%s, %d rules, fingerprint %s) in %s\n", snap.Device, snap.Vendor, len(loaded.Config.Rules), snap.Fingerprint[:16], o.store)
			return p.err
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "snapshot name, usually the device name")
	cmd.Flags().BoolVar(&list, "list", false, "list stored snapshots")
	return cmd
}

func (o *options) listSnapshots(cmd *cobra.Command, store *filestore.Store) error {
	snaps, err := store.List(cmd.Context())
	if err != nil {
		return err
	}
	if o.json {
		return writeJSON(cmd.OutOrStdout(), snaps)
	}
	rows := make([][]string, 0, len(snaps))
	for _, s := range snaps {
		rows = append(rows, []string{s.Device, s.Vendor.String(), s.Host, s.CollectedAt.Format(time.RFC3339), s.Fingerprint[:16]})
	}
	p := &printer{w: cmd.OutOrStdout()}
	p.table("DEVICE\tVENDOR\tHOST\tCOLLECTED\tFINGERPRINT", rows)
	return p.err
}

// loadSnapshot compiles a stored snapshot; its vendor selects the platform.
func (o *options) loadSnapshot(ctx context.Context) (workflow.Loaded, bootstrap.Platform, error) {
	if o.file != "" {
		return workflow.Loaded{}, bootstrap.Platform{}, &usageError{errors.New("--config and --snapshot are exclusive")}
	}
	store, err := filestore.New(o.store)
	if err != nil {
		return workflow.Loaded{}, bootstrap.Platform{}, err
	}
	snap, err := store.Load(ctx, o.snapshot)
	if err != nil {
		return workflow.Loaded{}, bootstrap.Platform{}, err
	}
	if o.vendor != "" {
		if v, err := firemon.ParseVendor(o.vendor); err != nil || v != snap.Vendor {
			return workflow.Loaded{}, bootstrap.Platform{}, &usageError{errors.New("--vendor does not match the snapshot vendor " + snap.Vendor.String())}
		}
	}
	p, err := bootstrap.Lookup(snap.Vendor, snap.Config.Location)
	if err != nil {
		return workflow.Loaded{}, bootstrap.Platform{}, err
	}
	loaded, err := workflow.FromConfig(snap.Config)
	return loaded, p, err
}

func defaultStore() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "firemon-snapshots"
	}
	return filepath.Join(dir, "firemon", "snapshots")
}
