package cli

import (
	"cmp"
	"context"
	"errors"
	"fmt"
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
		Short: "保存设备配置为快照，或列出已保存的快照",
		Long: "读取运行配置（或 --config 指定的文件），解析后以 --name 为名保存到快照目录 --store；\n" +
			"其他命令用 --snapshot 名称 使用该快照。--list 列出已保存的快照。",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			store, err := bootstrap.OpenSnapshots(o.store)
			if err != nil {
				return err
			}
			if list {
				return o.listSnapshots(cmd, store)
			}
			if name == "" {
				return &usageError{errors.New("需要 --name 指定快照名称")}
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
			p.f("已保存快照 %s（%s，%d 条策略，指纹 %s）到 %s\n", snap.Device, snap.Vendor, len(loaded.Config.Rules), snap.Fingerprint[:16], o.store)
			return p.err
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "快照名称，通常用设备名")
	cmd.Flags().BoolVar(&list, "list", false, "列出已保存的快照")
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
	p.table("设备\t厂商\t主机名\t采集时间\t指纹", rows)
	return p.err
}

// loadSnapshot compiles a stored snapshot; its vendor selects the platform.
func (o *options) loadSnapshot(ctx context.Context) (workflow.Loaded, bootstrap.Platform, error) {
	if o.file != "" {
		return workflow.Loaded{}, bootstrap.Platform{}, &usageError{errors.New("--config 和 --snapshot 只能二选一")}
	}
	store, err := bootstrap.OpenSnapshots(o.store)
	if err != nil {
		return workflow.Loaded{}, bootstrap.Platform{}, err
	}
	snap, err := o.loadStored(ctx, store, o.snapshot)
	if err != nil {
		return workflow.Loaded{}, bootstrap.Platform{}, snapshotError(err, o.snapshot, o.store)
	}
	if o.vendor != "" {
		if v, err := firemon.ParseVendor(o.vendor); err != nil || v != snap.Vendor {
			return workflow.Loaded{}, bootstrap.Platform{}, &usageError{errors.New("--vendor 与快照的厂商 " + snap.Vendor.String() + " 不一致")}
		}
	}
	p, err := bootstrap.Lookup(snap.Vendor, snap.Config.Location, nil)
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

// loadStored loads a snapshot; one stored by another firemon version is
// parsed again from its collected text and saved, so upgrades never strand
// the store.
func (o *options) loadStored(ctx context.Context, store *filestore.Store, name string) (filestore.Snapshot, error) {
	snap, err := store.Load(ctx, name)
	if !errors.Is(err, filestore.ErrStale) {
		return snap, err
	}
	raw, err := store.Raw(ctx, name)
	if err != nil {
		return filestore.Snapshot{}, err
	}
	loc, err := time.LoadLocation(cmp.Or(o.timezone, "Local"))
	if err != nil {
		return filestore.Snapshot{}, &usageError{err}
	}
	p, err := bootstrap.Lookup(snap.Vendor, loc, nil)
	if err != nil {
		return filestore.Snapshot{}, err
	}
	cfg, err := p.Parse(raw)
	if err != nil {
		return filestore.Snapshot{}, fmt.Errorf("重新解析快照 %s：%w", name, err)
	}
	snap.Config, snap.Raw = cfg, raw
	saved, err := store.Save(ctx, snap)
	if err != nil {
		return filestore.Snapshot{}, err
	}
	fmt.Fprintf(o.deps.Stderr, "提示：快照 %s 由旧版本保存，已按当前版本从原始配置重新解析并更新\n", name)
	saved.Config = cfg
	return saved, nil
}
