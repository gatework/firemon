package cli

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/gatework/firemon/adapter/filestore"
	"github.com/gatework/firemon/deploy"
	"github.com/gatework/firemon/internal/bootstrap"
	"github.com/gatework/firemon/internal/workflow"
)

func newDeployCmd(o *options) *cobra.Command {
	var in intentFlags
	var apply, yes bool
	var journalRoot, authzPath string
	var leaseTTL time.Duration
	cmd := &cobra.Command{
		Use:   "deploy",
		Short: "在设备上设计变更；加 --apply 时下发、核对并保存",
		Long: "读取设备运行配置，设计并渲染变更，然后打印出来。\n" +
			"不加 --apply 并确认时不会向设备发送任何命令。加 --apply 时，设备配置必须仍与设计时一致；\n" +
			"每次写入都记日志，不自动重试；保存或提交前会回读配置并核对。",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if o.file != "" {
				return &usageError{errors.New("deploy 直接读取设备，不要指定 --config")}
			}
			// --snapshot names the stored snapshot to refresh after the
			// change; the configuration itself is read from the device.
			refresh := o.snapshot
			o.snapshot = ""
			loaded, platform, err := o.load(cmd.Context())
			if err != nil {
				return err
			}
			in.logSetting = o.logSetting
			intent, err := in.intent(platform.Services)
			if err != nil {
				return err
			}
			prop, err := workflow.Propose(loaded.Firewall, platform, intent, o.deps.Now)
			if err != nil {
				return err
			}
			if err := printProposal(cmd, o.json, prop, loaded.Firewall); err != nil {
				return err
			}
			if !apply || len(prop.Plan.Changes) == 0 {
				return nil
			}
			if !prop.Plan.Verified {
				return errors.New("方案未通过验证，拒绝下发")
			}
			if !yes && !confirm(cmd) {
				return errors.New("未确认，没有发送任何命令")
			}
			guard, err := bootstrap.Guard(cmd.Context(), o.deps.Getenv, authzPath, leaseTTL)
			if err != nil {
				return err
			}
			if err := o.push(cmd, platform, prop, journalRoot, guard); err != nil {
				return err
			}
			return o.refreshSnapshot(cmd, platform, refresh)
		},
	}
	in.register(cmd)
	f := cmd.Flags()
	f.BoolVar(&apply, "apply", false, "把变更下发到设备（默认只演练）")
	f.BoolVar(&yes, "yes", false, "加 --apply 时不再询问确认")
	f.StringVar(&journalRoot, "journal", defaultJournalRoot(), "下发日志目录")
	f.StringVar(&authzPath, "authz", "", "权限策略文件（省略表示不做权限检查）")
	f.DurationVar(&leaseTTL, "lease-ttl", time.Hour, "设备租约时长；进程异常退出后到期自动释放")
	return cmd
}

func (o *options) push(cmd *cobra.Command, platform bootstrap.Platform, prop workflow.Proposal, journalRoot string, guard deploy.Guard) error {
	client, err := o.device.client(platform, o.deps.Getenv)
	if err != nil {
		return err
	}
	journal, dir, err := bootstrap.Journal(journalRoot)
	if err != nil {
		return err
	}
	receipt, err := workflow.Apply(cmd.Context(), client, platform, prop, journal, guard, o.deps.Now)
	p := &printer{w: cmd.OutOrStdout()}
	p.f("\n下发结果：%s，日志 %s\n", receipt.Record.Status, dir)
	if err != nil {
		p.f("回退命令见上方；不会自动重试\n")
		return errors.Join(err, p.err)
	}
	return p.err
}

func confirm(cmd *cobra.Command) bool {
	p := &printer{w: cmd.OutOrStdout()}
	p.f("\n确认把以上命令下发到设备？输入 yes 继续：")
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

// refreshSnapshot stores the device's configuration after a change, so
// that the next search sees it and does not design the same change again.
// The snapshot is the one --snapshot names, else the one stored from the
// same device address.
func (o *options) refreshSnapshot(cmd *cobra.Command, platform bootstrap.Platform, name string) error {
	store, err := bootstrap.OpenSnapshots(o.store)
	if err != nil {
		return err
	}
	if name == "" {
		snaps, err := store.List(cmd.Context())
		if err != nil {
			return err
		}
		for _, s := range snaps {
			if s.Host != "" && s.Host == o.device.host {
				name = s.Device
				break
			}
		}
	}
	p := &printer{w: cmd.OutOrStdout()}
	if name == "" {
		p.f("提示：快照库中没有该设备的快照；下次用 --snapshot 指定快照名，下发后会自动更新它，否则请运行 firemon collect\n")
		return p.err
	}
	client, err := o.device.client(platform, o.deps.Getenv)
	if err != nil {
		return err
	}
	loaded, err := workflow.Load(cmd.Context(), workflow.Source{Platform: platform, Device: client})
	if err != nil {
		return fmt.Errorf("下发成功，但更新快照 %s 时读取设备失败，请运行 firemon collect：%w", name, err)
	}
	if _, err := store.Save(cmd.Context(), filestore.Snapshot{
		Device: name, Host: o.device.host, CollectedAt: o.deps.Now().UTC(), Config: loaded.Config, Raw: loaded.Raw,
	}); err != nil {
		return err
	}
	p.f("快照 %s 已按下发后的设备配置更新；同集群的备机经 HA 同步后，用 firemon collect 更新其快照\n", name)
	return p.err
}
