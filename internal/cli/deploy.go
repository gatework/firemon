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
		Short: "在设备上设计变更；加 --apply 时下发、核对并保存",
		Long: "读取设备运行配置，设计并渲染变更，然后打印出来。\n" +
			"不加 --apply 并确认时不会向设备发送任何命令。加 --apply 时，设备配置必须仍与设计时一致；\n" +
			"每次写入都记日志，不自动重试；保存或提交前会回读配置并核对。",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if o.file != "" || o.snapshot != "" {
				return &usageError{errors.New("deploy 直接读取设备，不要指定 --config 或 --snapshot")}
			}
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
			if !apply || len(prop.Plan.Changes) == 0 {
				return nil
			}
			if !prop.Plan.Verified {
				return errors.New("方案未通过验证，拒绝下发")
			}
			if !yes && !confirm(cmd) {
				return errors.New("未确认，没有发送任何命令")
			}
			return o.push(cmd, platform, prop, journalRoot)
		},
	}
	in.register(cmd)
	f := cmd.Flags()
	f.BoolVar(&apply, "apply", false, "把变更下发到设备（默认只演练）")
	f.BoolVar(&yes, "yes", false, "加 --apply 时不再询问确认")
	f.StringVar(&journalRoot, "journal", defaultJournalRoot(), "下发日志目录")
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
	p.f("\n下发结果：%s，日志 %s\n", receipt.State.Status, dir)
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
