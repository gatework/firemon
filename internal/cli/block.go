package cli

import (
	"cmp"
	"errors"
	"strings"

	"github.com/spf13/cobra"

	"github.com/gatework/firemon/design"
	"github.com/gatework/firemon/intake"
	"github.com/gatework/firemon/traffic"
)

func newBlockCmd(o *options) *cobra.Command {
	var src, dst, service, name, description string
	var noLog bool
	cmd := &cobra.Command{
		Use:   "block [--src 源] [--dst 目的] [--service 服务]",
		Short: "全网封堵：在每台防火墙上拒绝某个地址或服务，已封堵的说明由哪条策略拒绝",
		Long: "对库存中的每台防火墙（或 --config/--snapshot 指定的一台）检查这些流量是否在所有区域之间都被拒绝：\n" +
			"  已被拒绝策略挡住的，说明是哪条策略；否则设计一条拒绝策略（区域为任意），放在第一条可能匹配这些流量的策略之前，\n" +
			"  验证在所有区域之间都拒绝、其他流量不受影响，并给出命令与回退。只靠默认拒绝的也会新增显式封堵策略。\n" +
			"源、目的省略表示任意，服务省略表示全部：\n" +
			"  firemon block --dst 203.0.113.66                 封堵访问某个地址的全部流量\n" +
			"  firemon block --src 198.51.100.7 --service 445   封堵某个地址访问 445 端口\n" +
			"退出码：0 已全部封堵，3 有已验证的封堵方案待执行，4 需确认。",
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) > 0 {
				return &usageError{errors.New("不接受位置参数：请用 --src、--dst、--service")}
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			if src == "" && dst == "" {
				return &usageError{errors.New("需要 --src 或 --dst 指定要封堵的地址")}
			}
			return o.block(cmd, blockRequest{src: cmp.Or(src, "any"), dst: cmp.Or(dst, "any"), service: cmp.Or(service, "any"),
				name: name, description: description, noLog: noLog})
		},
	}
	f := cmd.Flags()
	f.StringVar(&src, "src", "", "要封堵的源地址（省略为任意）")
	f.StringVar(&dst, "dst", "", "要封堵的目的地址（省略为任意）")
	f.StringVar(&service, "service", "", "要封堵的服务，例如 445、tcp/3389（省略为全部）")
	f.StringVar(&name, "name", "", "封堵策略名称，例如工单号（默认 B-日期-序号，如 B-20261118-001）")
	f.StringVar(&description, "description", "", "封堵策略描述（默认 名称-By-Firemon）")
	f.BoolVar(&noLog, "no-log", false, "封堵策略不记录日志（默认记录拒绝和会话结束）")
	return cmd
}

type blockRequest struct {
	src, dst, service, name, description string
	noLog                                bool
}

// blockResult is the JSON form of one firewall's block.
type blockResult struct {
	Cluster   string         `json:"cluster"`
	Firewall  string         `json:"firewall"`
	Members   []string       `json:"members"`
	BlockedBy []string       `json:"blocked_by,omitempty"`
	Plan      *design.Plan   `json:"plan,omitempty"`
	Script    *design.Script `json:"script,omitempty"`
}

func (o *options) block(cmd *cobra.Command, req blockRequest) error {
	inv, platforms, _, err := o.checkFleet(cmd)
	if err != nil {
		return err
	}
	opts := intakeOptions(platforms)
	in, err := intake.Parse(req.src, req.dst, req.service, opts)
	if err != nil {
		return &usageError{err}
	}
	intent := design.Intent{Src: in.Src, Dst: in.Dst, Service: in.Service, Name: req.name, Description: req.description,
		NoLog: req.noLog, LogSetting: o.logSetting}
	if intent.Service.IsEmpty() {
		intent.Service = traffic.AnyService()
	}
	var out []blockResult
	pending, undecided := false, false
	for _, cluster := range inv.Clusters() {
		name := inv.Primary(cluster)
		platform := platforms[name]
		bp, err := design.New(inv.Firewall(cluster), design.Options{Now: o.deps.Now, Naming: platform.Naming, Capabilities: platform.Capabilities}).PlanBlock(intent)
		if err != nil {
			return err
		}
		r := blockResult{Cluster: cluster, Firewall: name, Members: inv.Members(cluster), BlockedBy: bp.BlockedBy, Plan: bp.Plan}
		switch {
		case len(bp.Changes) == 0:
		case !bp.Verified:
			undecided = true
		default:
			script, err := platform.Render(bp.Plan)
			if err != nil {
				return err
			}
			r.Script, pending = &script, true
		}
		out = append(out, r)
	}
	if o.json {
		if err := writeJSON(cmd.OutOrStdout(), out); err != nil {
			return err
		}
	} else if err := printBlock(cmd, in.Notes, out); err != nil {
		return err
	}
	switch {
	case undecided:
		return errUndecided
	case pending:
		return errNotAllowed
	default:
		return nil
	}
}

func printBlock(cmd *cobra.Command, notes []intake.Note, out []blockResult) error {
	p := &printer{w: cmd.OutOrStdout()}
	todo := 0
	for _, r := range out {
		if len(r.Plan.Changes) > 0 {
			todo++
		}
	}
	if todo == 0 {
		p.f("结论：已在全部 %d 台防火墙上封堵\n", len(out))
	} else {
		p.f("结论：%d 台防火墙需要新增封堵策略（共 %d 台）\n", todo, len(out))
	}
	if len(notes) > 0 {
		printNotes(p, notes)
	}
	for _, r := range out {
		switch {
		case len(r.Plan.Changes) == 0:
			p.f("\n■ %s：已封堵（拒绝策略 %s）\n", r.Cluster, joinIDs(r.BlockedBy))
		case r.Script == nil:
			p.f("\n■ %s：需确认，封堵方案验证未通过（%s），不输出命令\n", r.Cluster, r.Plan.VerifyError)
		default:
			p.f("\n■ %s：需新增封堵策略\n", r.Cluster)
			p.f("  处置：%s，在 %s 上执行%s（已验证：所有区域之间都拒绝这些流量，其他流量不受影响）\n", actionSummary(r.Plan), r.Firewall, haNote(r.Members, r.Firewall))
			n := 0
			for _, c := range r.Plan.Changes {
				if line := ruleChangeText(c); line != "" {
					n++
					p.f("    %d. %s\n", n, line)
				}
			}
			p.f("    命令：\n")
			for _, c := range r.Script.Commands {
				p.f("      %s\n", c)
			}
			p.f("    回退：\n")
			for _, c := range r.Script.Rollback {
				p.f("      %s\n", c)
			}
		}
	}
	return p.err
}

func joinIDs(ids []string) string {
	if len(ids) == 0 {
		return "-"
	}
	return strings.Join(ids, "、")
}
