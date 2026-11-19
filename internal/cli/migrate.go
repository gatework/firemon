package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/adapter/yamlfile"
	"github.com/gatework/firemon/internal/bootstrap"
	"github.com/gatework/firemon/migrate"
)

type migrateFlags struct {
	to, mapping, initMapping, out string
}

func newMigrateCmd(o *options) *cobra.Command {
	var f migrateFlags
	cmd := &cobra.Command{
		Use:   "migrate",
		Short: "策略迁移：把一个厂商的配置翻译成另一个厂商的完整配置与翻译报告",
		Long: "把配置（--config、--snapshot 或设备）翻译成目标厂商 --to 的命令：网络、对象、时间计划、按顺序的策略和 NAT。\n" +
			"--mapping 指定目标上的区域、接口、虚拟路由器、预定义服务和应用名称；--init-mapping 生成待填写的骨架。\n" +
			"每一项都标为精确、近似（附差异）或无法翻译；无法翻译的策略以禁用状态带过去。不会向任何设备发送命令。",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return o.migrate(cmd, f)
		},
	}
	fl := cmd.Flags()
	fl.StringVar(&f.to, "to", "", "目标厂商：hillstone 或 paloalto")
	fl.StringVar(&f.mapping, "mapping", "", "映射文件（YAML）")
	fl.StringVar(&f.initMapping, "init-mapping", "", "根据源配置生成映射文件骨架到该路径，然后退出")
	fl.StringVar(&f.out, "out", "", "输出目录：commands.txt 与 report.txt；默认输出到终端")
	return cmd
}

func (o *options) migrate(cmd *cobra.Command, f migrateFlags) error {
	to, err := vendor("--to", f.to)
	if err != nil {
		return err
	}
	loaded, src, err := o.load(cmd.Context())
	if err != nil {
		return err
	}
	dst, err := bootstrap.Lookup(to, loaded.Config.Location, nil)
	if err != nil {
		return &usageError{err}
	}
	target, err := bootstrap.MigrationTarget(dst)
	if err != nil {
		return err
	}
	if f.initMapping != "" {
		return writeSkeleton(cmd, loaded.Config, target, f.initMapping)
	}
	var m migrate.Mapping
	if f.mapping != "" {
		if m, err = yamlfile.LoadMapping(f.mapping); err != nil {
			return &usageError{err}
		}
	}
	res, err := migrate.Translate(loaded.Config, m, target)
	if errors.Is(err, migrate.ErrSameVendor) {
		return &usageError{err}
	}
	if err != nil {
		return err
	}
	script, err := dst.Render(res.Plan)
	if err != nil {
		return err
	}
	if o.json {
		return writeJSON(cmd.OutOrStdout(), struct {
			From     firemon.Vendor `json:"from"`
			To       firemon.Vendor `json:"to"`
			Items    []migrate.Item `json:"items"`
			Commands []string       `json:"commands"`
		}{src.Vendor, to, res.Items, script.Commands})
	}
	var report strings.Builder
	printMigration(&printer{w: &report}, src.Vendor, to, res)
	if f.out == "" {
		p := &printer{w: cmd.OutOrStdout()}
		p.f("%s\n命令：\n%s\n", report.String(), strings.Join(script.Commands, "\n"))
		return p.err
	}
	if err := os.MkdirAll(f.out, 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(f.out, "commands.txt"), []byte(strings.Join(script.Commands, "\n")+"\n"), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(f.out, "report.txt"), []byte(report.String()), 0o600); err != nil {
		return err
	}
	p := &printer{w: cmd.OutOrStdout()}
	p.f("%s\n命令与报告已写入 %s\n", report.String(), f.out)
	return p.err
}

func writeSkeleton(cmd *cobra.Command, src *firemon.Config, target migrate.Target, path string) error {
	m, err := migrate.Skeleton(src, target)
	if err != nil {
		return err
	}
	fh, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if err := yamlfile.WriteMapping(fh, m); err != nil {
		_ = fh.Close()
		return err
	}
	if err := fh.Close(); err != nil {
		return err
	}
	p := &printer{w: cmd.OutOrStdout()}
	p.f("映射文件骨架已写入 %s：请填写接口对应的目标端口，并核对服务与应用的对应关系\n", path)
	return p.err
}

func printMigration(p *printer, from, to firemon.Vendor, res migrate.Result) {
	p.f("策略迁移报告：%s → %s\n", from, to)
	p.f("完全等价 %d 项，近似 %d 项，无法翻译 %d 项（无法翻译的策略已以禁用状态迁移）\n",
		res.Count(migrate.FidelityExact), res.Count(migrate.FidelityApproximate), res.Count(migrate.FidelityUntranslatable))
	for _, fid := range []migrate.Fidelity{migrate.FidelityUntranslatable, migrate.FidelityApproximate} {
		first := true
		for _, it := range res.Items {
			if it.Fidelity != fid {
				continue
			}
			if first {
				p.f("\n■ %s\n", text(fidelityText, fid, fid.String()))
				first = false
			}
			p.f("  %s %s → %s：%s\n", text(itemKindText, it.Kind, it.Kind.String()), it.Source, orDash(strings.Join(it.Target, ",")), it.Reason)
		}
	}
}
