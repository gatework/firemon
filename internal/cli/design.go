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
	override, noLog             bool
	logSetting                  string
}

func (i *intentFlags) register(cmd *cobra.Command) {
	i.trafficFlags.register(cmd)
	f := cmd.Flags()
	f.StringVar(&i.name, "name", "", "新建策略的名称，例如工单号（默认 fm_<序号>）")
	f.StringVar(&i.description, "description", "", "新建策略的描述")
	f.StringVar(&i.schedule, "schedule", "", "新建策略使用的已有时间计划")
	f.BoolVar(&i.override, "override", false, "已不需要：被拒绝策略挡住时新策略会放在其前并提示确认")
	_ = f.MarkHidden("override")
	f.BoolVar(&i.noLog, "no-log", false, "新建策略不开启日志（默认记录会话开始和结束）")
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
		// As search: a deny that blocks the request is passed with a warning.
		Name: i.name, Description: i.description, Schedule: i.schedule, Override: true, NAT: nat,
		NoLog: i.noLog, LogSetting: i.logSetting,
	}, nil
}

type proposalView struct {
	*design.Plan
	ChangeList []string      `json:"changes"`
	Script     design.Script `json:"script"`
}

func printProposal(cmd *cobra.Command, asJSON bool, prop workflow.Proposal, fw *firemon.Firewall) error {
	changes := make([]string, len(prop.Plan.Changes))
	for i, c := range prop.Plan.Changes {
		changes[i] = c.String()
	}
	if asJSON {
		return writeJSON(cmd.OutOrStdout(), proposalView{Plan: prop.Plan, ChangeList: changes, Script: prop.Script})
	}
	for i, c := range prop.Plan.Changes {
		changes[i] = changeText(c) // JSON keeps the stable English form above
	}
	p := &printer{w: cmd.OutOrStdout()}
	plan := prop.Plan
	p.f("方案：%s  已验证：%s  基线指纹：%s\n", text(planStatusText, plan.Status, plan.Status.String()), yesNo(plan.Verified), plan.Baseline[:16])
	if plan.VerifyError != "" {
		p.f("验证未通过：%s\n", plan.VerifyError)
	}
	if n := plan.NAT; n != nil {
		p.f("NAT：%s", text(natStatusText, n.Status, n.Status.String()))
		switch {
		case len(n.Existing) > 0:
			p.f("，由 NAT 规则 %s 完成", strings.Join(n.Existing, ","))
		case n.Rule != "":
			p.f("，规则 %s", n.Rule)
			if n.Before != "" {
				p.f("，放在 %s 之前（NAT 按顺序首条命中）", n.Before)
			}
		}
		if n.Address != "" {
			p.f("，地址 %s", n.Address)
		}
		if n.Interface != "" {
			p.f("，使用 %s 的接口地址", n.Interface)
		}
		if n.Reused {
			p.f("（复用已有地址）")
		}
		if n.Reason != "" {
			p.f("：%s", n.Reason)
		}
		p.f("\n")
	}
	for _, c := range plan.Conflicts {
		p.f("冲突：策略 %s 拒绝 %s → %s 的 %s（确认后加 --override 把新策略放在它之前）\n", c.RuleID, c.From, c.To, c.Text)
	}
	for _, u := range plan.Unknown {
		p.f("无法设计：%s\n", planNote(u))
	}
	for _, w := range plan.Warnings {
		p.f("注意：%s\n", planNote(w))
	}
	if len(changes) > 0 {
		for _, w := range passedDenies(plan, fw) {
			p.f("⚠ 新策略放在拒绝策略 %s 之前，将绕过它：请确认该放通符合安全要求\n", w)
		}
		p.f("\n变更：\n  %s\n", strings.Join(changes, "\n  "))
		p.f("\n命令：\n%s\n", strings.Join(prop.Script.Commands, "\n"))
		p.f("\n回退命令：\n%s\n", strings.Join(prop.Script.Rollback, "\n"))
	}
	return p.err
}
