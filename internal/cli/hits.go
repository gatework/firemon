package cli

import (
	"errors"
	"os"
	"strconv"
	"time"

	"github.com/gatework/firemon/internal/bootstrap"

	"github.com/spf13/cobra"

	"github.com/gatework/firemon/hits"
)

func newHitsCmd(o *options) *cobra.Command {
	var name, command, file string
	var show bool
	cmd := &cobra.Command{
		Use:   "hits",
		Short: "采集（只读）、导入或查看策略命中计数",
		Long: "用只读命令读取设备（--host、--user）的策略命中计数，按快照名 --name 保存到 --store；\n" +
			"--file 导入 JSON 或 CSV 格式的计数（列：rule,hits[,last_hit,first_hit,reset]）；--show 打印最近保存的计数。\n" +
			"converge 用它作为策略未被使用的证据。",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if name == "" {
				return &usageError{errors.New("需要 --name 指定快照名称")}
			}
			store, err := bootstrap.OpenSnapshots(o.store)
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
	f.StringVar(&name, "name", "", "计数所属的快照名称")
	f.StringVar(&command, "command", "", "列出命中计数的只读命令（默认使用厂商命令）")
	f.StringVar(&file, "file", "", "从 JSON 或 CSV 文件导入计数，而不是读取设备")
	f.BoolVar(&show, "show", false, "打印最近保存的计数")
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
	p.f("%s：%d 条计数，采集于 %s\n", snap.Firewall, len(snap.Counters), snap.Taken.Format(time.RFC3339))
	p.table("策略\t命中次数\t最近命中", rows)
	return p.err
}
