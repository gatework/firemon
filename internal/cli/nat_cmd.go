package cli

import (
	"errors"
	"maps"
	"slices"

	"github.com/spf13/cobra"

	"github.com/gatework/firemon/query"
	"github.com/gatework/firemon/traffic"
)

func newNATCmd(o *options) *cobra.Command {
	var ip, service string
	cmd := &cobra.Command{
		Use:   "nat --ip 地址 [--service 服务]",
		Short: "NAT 双向查询：内部地址如何出访和被发布，公网地址转换到哪台内部服务器",
		Long: "按地址查 NAT，正反两个方向都查：\n" +
			"  作为内部地址：出访时转换成什么地址，是否通过目的 NAT 或静态一对一被发布到公网；\n" +
			"  作为公网地址：转换到哪台内部服务器和端口，或被哪些内部网段用作源转换地址池。\n" +
			"每条给出规则、在 NAT 列表中的位置（按顺序首条命中）和是否生效：被前面的规则完全覆盖、已禁用、无法离线判定的都会注明。\n" +
			"  firemon nat --ip 10.0.5.20\n" +
			"  firemon nat --ip 198.51.100.50 --service tcp/443",
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) > 0 {
				return &usageError{errors.New("不接受位置参数：请用 --ip 地址")}
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			if ip == "" {
				return &usageError{errors.New("需要 --ip 指定要查的地址")}
			}
			addr, err := traffic.ParseAddressSet(ip)
			if err != nil {
				return &usageError{errors.New("--ip 无法识别：请写 IP、网段或范围")}
			}
			var svc traffic.ServiceSet
			if service != "" {
				if svc, err = traffic.ParseServiceSet(service); err != nil {
					return &usageError{errors.New("--service 无法识别：请写 tcp/443、udp/53 这样的协议/端口")}
				}
			}
			return o.natLookup(cmd, addr, svc)
		},
	}
	cmd.Flags().StringVar(&ip, "ip", "", "要查的地址：内部地址或公网地址，IP、网段或范围")
	cmd.Flags().StringVar(&service, "service", "", "只看该服务，例如 tcp/443（默认全部）")
	return cmd
}

// natFirewall is the JSON form of one firewall's NAT entries.
type natFirewall struct {
	Firewall string         `json:"firewall"`
	Entries  []query.NATUse `json:"entries"`
}

func (o *options) natLookup(cmd *cobra.Command, addr traffic.AddressSet, svc traffic.ServiceSet) error {
	_, _, fws, err := o.checkFleet(cmd)
	if err != nil {
		return err
	}
	var out []natFirewall
	for _, name := range slices.Sorted(maps.Keys(fws)) {
		uses := query.New(fws[name], query.Options{Now: o.deps.Now}).NATLookup(addr, svc)
		out = append(out, natFirewall{Firewall: name, Entries: uses})
	}
	if o.json {
		return writeJSON(cmd.OutOrStdout(), out)
	}
	p := &printer{w: cmd.OutOrStdout()}
	found := 0
	for _, f := range out {
		if len(f.Entries) == 0 {
			continue
		}
		found++
		p.f("\n■ %s\n", f.Firewall)
		for _, u := range f.Entries {
			p.f("  %s\n", natUseText(u))
		}
	}
	if found == 0 {
		p.f("没有 NAT 规则或静态映射涉及 %s\n", addr)
	}
	return p.err
}

// natUseText writes one NAT entry from the address's point of view.
func natUseText(u query.NATUse) string {
	label := "NAT 规则 " + u.ID
	if u.Static != nil {
		label = "静态 NAT " + u.ID
	}
	if u.Position > 0 {
		label += "（第 " + itoa(u.Position) + " 条）"
	}
	svc := func(s traffic.ServiceSet) string {
		if s.IsAny() {
			return ""
		}
		return " " + s.String()
	}
	to := u.Translated.String()
	if u.Translated.IsEmpty() {
		to = "出接口地址"
		if u.Interface != "" {
			to = u.Interface + " 的接口地址"
		}
	}
	var what string
	switch u.Role {
	case query.NATRoleOutbound:
		what = "出访源转换：源 " + u.Match.Src.String() + " → 目的 " + anyText(u.Match.Dst) + svc(u.Match.Service) + "，源转换为 " + to
	case query.NATRolePublished:
		what = "被发布：公网 " + u.Match.Dst.String() + svc(u.Match.Service) + " ⇒ 内部 " + to + svc(u.Service)
	case query.NATRoleInbound:
		what = "入站目的转换：公网 " + u.Match.Dst.String() + svc(u.Match.Service) + " ⇒ 内部 " + to + svc(u.Service)
	case query.NATRolePool:
		what = "作为源转换地址：源 " + u.Match.Src.String() + " → 目的 " + anyText(u.Match.Dst) + " 出访时转换为 " + to
	case query.NATRoleExempt:
		what = "不转换（NAT 豁免）：源 " + anyText(u.Match.Src) + " → 目的 " + anyText(u.Match.Dst) + svc(u.Match.Service)
	case query.NATRoleUnset:
	}
	return what + "  [" + label + "，" + natStateText(u) + "]"
}

func natStateText(u query.NATUse) string {
	switch u.State {
	case query.NATStateActive:
		return "生效"
	case query.NATStateShadowed:
		return "被前面的规则 " + u.ShadowedBy + " 完全覆盖，不会生效"
	case query.NATStateDisabled:
		return "已禁用"
	case query.NATStatePossible:
		return "可能生效，无法离线判定"
	case query.NATStateUnset:
	}
	return u.State.String()
}

func anyText(s traffic.AddressSet) string {
	if s.Equal(traffic.AnyAddress()) || s.Equal(traffic.AnyIPv4()) {
		return "任意"
	}
	return s.String()
}
