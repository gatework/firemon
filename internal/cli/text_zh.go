package cli

import (
	"regexp"
	"strings"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/audit"
	"github.com/gatework/firemon/converge"
	"github.com/gatework/firemon/design"
	"github.com/gatework/firemon/intake"
	"github.com/gatework/firemon/inventory"
	"github.com/gatework/firemon/migrate"
	"github.com/gatework/firemon/query"
	"github.com/gatework/firemon/report"
	"github.com/gatework/firemon/traffic"
)

// Operator-facing Chinese text for the check report (NAM-10). Keys are the
// typed values of the domain packages; anything missing falls back to the
// English identifier.

var statusText = map[report.Status]string{
	report.StatusUnset:         "不经过任何防火墙",
	report.StatusFullMatch:     "完全命中",
	report.StatusPartialMatch:  "部分命中",
	report.StatusNeedNew:       "需要新增策略",
	report.StatusBlocked:       "需要新增策略",
	report.StatusIndeterminate: "需确认",
}

var verdictText = map[query.Verdict]string{
	query.VerdictAllowed:       "放通",
	query.VerdictDenied:        "拒绝",
	query.VerdictPartial:       "部分放通",
	query.VerdictIndeterminate: "需确认",
}

var ownershipText = map[inventory.Ownership]string{
	inventory.OwnershipDeclared: "受保护网段",
	inventory.OwnershipDerived:  "路由推导",
	inventory.OwnershipTransit:  "途经",
	inventory.OwnershipZones:    "按指定区域",
}

var relationText = map[traffic.Relation]string{
	traffic.RelationEqual:    "相等",
	traffic.RelationSuperset: "已包含",
	traffic.RelationSubset:   "部分包含",
	traffic.RelationOverlap:  "有重叠",
	traffic.RelationDisjoint: "不相交",
}

var reasonText = map[report.Reason]string{
	report.ReasonSeveralDimensions: "需修改多个维度",
	report.ReasonWider:             "其余维度宽于需求，扩展会放通需求外流量",
	report.ReasonZoneAny:           "区域为 any，修改会影响其他区域",
	report.ReasonScheduled:         "带时间表",
	report.ReasonUndecidable:       "含无法离线判定的条件",
	report.ReasonAfterDeny:         "位于拒绝策略之后，修改无效",
}

var noteText = map[intake.Code]string{
	intake.CodeMasked:            "已清除主机位",
	intake.CodeMask:              "地址+掩码已转换为网段",
	intake.CodeShortRange:        "简写范围已展开",
	intake.CodeWildcard:          "通配地址已转换为网段",
	intake.CodeDomain:            "按域名策略匹配",
	intake.CodeDefaultTCP:        "未写协议，按 TCP 处理",
	intake.CodeInheritedProtocol: "沿用前一项的协议",
	intake.CodeServiceName:       "按服务名解析",
	intake.CodeApplication:       "按应用识别匹配",
	intake.CodeDuplicate:         "重复或已被覆盖，已忽略",
	intake.CodeInvalid:           "无法识别，已忽略",
	intake.CodeUnsupported:       "此处不支持，已忽略",
}

var fieldText = map[intake.Field]string{
	intake.FieldSource:      "源地址",
	intake.FieldDestination: "目的地址",
	intake.FieldService:     "服务",
}

var natSideText = map[firemon.NATKind]string{
	firemon.NATKindSource:      "源 NAT",
	firemon.NATKindDestination: "目的 NAT",
}

func text[K comparable](table map[K]string, key K, fallback string) string {
	if v, ok := table[key]; ok {
		return v
	}
	return fallback
}

var issueKindText = map[string]string{
	"domain":         "域名对象",
	"application":    "应用识别",
	"user":           "用户",
	"url-category":   "URL 分类",
	"schedule":       "时间表",
	"unknown-object": "未知对象",
	"nat":            "NAT 无法判定",
	"other":          "其他条件",
}

var natStatusText = map[design.NATStatus]string{
	design.NATStatusSatisfied:     "已满足",
	design.NATStatusAdded:         "需新增",
	design.NATStatusNeedsAddress:  "需分配公网地址",
	design.NATStatusIndeterminate: "无法判定",
	design.NATStatusConflict:      "冲突（加 --override 才会插到该规则之前）",
}

var categoryText = map[converge.Category]string{
	converge.CategoryUnusedObject:    "未使用对象",
	converge.CategoryEmptyObject:     "空对象",
	converge.CategoryNeverMatches:    "永不匹配的策略",
	converge.CategoryIncomplete:      "不完整策略（设备忽略）",
	converge.CategoryDisabled:        "已禁用策略",
	converge.CategoryExpired:         "已过期策略",
	converge.CategoryRedundant:       "冗余策略（被同动作策略完全覆盖）",
	converge.CategoryShadowed:        "被遮蔽策略（被相反动作策略完全覆盖）",
	converge.CategoryMergeable:       "可合并策略",
	converge.CategoryBroad:           "过宽放通",
	converge.CategoryZeroHit:         "零命中策略",
	converge.CategoryDuplicateObject: "重复对象（内容相同、名称不同）",
	converge.CategoryNoLog:           "放通但未开启日志的策略",
}

var tierText = map[converge.Tier]string{
	converge.TierSafe:   "可安全清理",
	converge.TierReview: "需人工确认",
}

var evidenceText = map[converge.Evidence]string{
	converge.EvidenceStatic: "配置分析",
	converge.EvidenceHits:   "命中计数",
	converge.EvidenceBoth:   "配置+命中",
}

var convergeReasonText = map[converge.Reason]string{
	converge.ReasonSourceAny:       "源为 any",
	converge.ReasonDestinationAny:  "目的为 any",
	converge.ReasonServiceAny:      "服务为 any",
	converge.ReasonZoneAny:         "区域为 any",
	converge.ReasonWideSource:      "源含 /16 及以上网段",
	converge.ReasonWideDestination: "目的含 /16 及以上网段",
	converge.ReasonVeryWide:        "含 /8 及以上网段",
	converge.ReasonNoHits:          "观察期内零命中，建议删除",
	converge.ReasonHits:            "有命中，收窄需结合流量日志",
	converge.ReasonCountersReset:   "计数观察期不足",
}

var objectKindText = map[firemon.ObjectKind]string{
	firemon.ObjectKindAddress:      "地址",
	firemon.ObjectKindAddressGroup: "地址组",
	firemon.ObjectKindService:      "服务",
	firemon.ObjectKindServiceGroup: "服务组",
	firemon.ObjectKindSchedule:     "时间计划",
}

var fieldText2 = map[design.Field]string{
	design.FieldSource:      "源地址",
	design.FieldDestination: "目的地址",
	design.FieldService:     "服务",
}

var fidelityText = map[migrate.Fidelity]string{
	migrate.FidelityExact:          "完全等价",
	migrate.FidelityApproximate:    "近似（存在说明的差异）",
	migrate.FidelityUntranslatable: "无法翻译",
}

var itemKindText = map[migrate.ItemKind]string{
	migrate.ItemKindVirtualRouter: "虚拟路由器",
	migrate.ItemKindZone:          "区域",
	migrate.ItemKindInterface:     "接口",
	migrate.ItemKindRoute:         "路由",
	migrate.ItemKindSchedule:      "时间计划",
	migrate.ItemKindAddress:       "地址",
	migrate.ItemKindAddressGroup:  "地址组",
	migrate.ItemKindService:       "服务",
	migrate.ItemKindServiceGroup:  "服务组",
	migrate.ItemKindRule:          "策略",
	migrate.ItemKindNAT:           "NAT",
	migrate.ItemKindDefault:       "默认动作",
}

// planNotes translate the planner's notes; a note of another form is
// printed as it is.
var planNotes = []struct {
	re   *regexp.Regexp
	repl string
}{
	{regexp.MustCompile(`^(.*) may already be permitted by undecidable rules (.*)$`), "$1 可能已被无法离线判定的策略 $2 放通"},
	{regexp.MustCompile(`^(.*): rules (.*) that match applications, URL categories or users may still decide part of it first$`), "$1：按应用、URL 分类或用户匹配的策略 $2 可能先命中其中一部分"},
	{regexp.MustCompile(`^(.*): deny rules (.*) that match applications, URL categories or users still come first$`), "$1：按应用、URL 分类或用户匹配的拒绝策略 $2 仍排在新策略之前"},
	{regexp.MustCompile(`^unrouted destinations (.*)$`), "目的 $1 无路由"},
	{regexp.MustCompile(`^rule (.*) does not log its sessions; consider enabling logging$`), "策略 $1 未开启日志，建议一并开启"},
	{regexp.MustCompile(`^(.*): NAT may apply \((.*)\)$`), "$1：NAT 规则 $2 可能生效，无法判定"},
	{regexp.MustCompile(`^(.*): (.*) needs an application match \(no port service\)$`), "$1：$2 需要按应用匹配（没有对应的端口服务）"},
}

func planNote(s string) string {
	for _, n := range planNotes {
		if n.re.MatchString(s) {
			return n.re.ReplaceAllString(s, n.repl)
		}
	}
	return s
}

// changeText describes a planned change in Chinese.
func changeText(c design.Change) string {
	where := func(before string) string {
		if before == "" {
			return "放在末尾"
		}
		return "放在策略 " + before + " 之前"
	}
	entries := func(es []firemon.AddressEntry) string {
		parts := make([]string, len(es))
		for i, e := range es {
			parts[i] = e.String()
		}
		return strings.Join(parts, "、")
	}
	switch x := c.(type) {
	case design.AddAddress:
		return "新增地址对象 " + x.Address.Name + " = " + entries(x.Address.Entries)
	case design.AddAddressGroup:
		return "新增地址组 " + x.Group.Name + "，成员 " + strings.Join(x.Group.Members, "、")
	case design.AddService:
		parts := make([]string, len(x.Service.Entries))
		for i, e := range x.Service.Entries {
			parts[i] = e.String()
		}
		return "新增服务对象 " + x.Service.Name + " = " + strings.Join(parts, "、")
	case design.AddServiceGroup:
		return "新增服务组 " + x.Group.Name + "，成员 " + strings.Join(x.Group.Members, "、")
	case design.AddRule:
		if x.Rule.Name == "" || x.Rule.Name == x.Rule.ID {
			return "新增策略 " + x.Rule.ID + "（" + where(x.Before) + "）"
		}
		return "新增策略 " + x.Rule.Name + "（ID " + x.Rule.ID + "，" + where(x.Before) + "）"
	case design.ExtendRule:
		return "策略 " + x.RuleID + " 的" + fieldText2[x.Field] + "增加 " + strings.Join(x.Names, "、")
	case design.ReduceRule:
		return "策略 " + x.RuleID + " 的" + fieldText2[x.Field] + "去掉 " + strings.Join(x.Names, "、")
	default:
		return otherChangeText(c)
	}
}

// otherChangeText describes cleanup, NAT and network changes.
func otherChangeText(c design.Change) string {
	where := func(before string) string {
		if before == "" {
			return "放在末尾"
		}
		return "放在策略 " + before + " 之前"
	}
	switch x := c.(type) {
	case design.DeleteRule:
		return "删除策略 " + x.Rule.ID
	case design.DeleteAddress:
		return "删除地址对象 " + x.Address.Name
	case design.DeleteAddressGroup:
		return "删除地址组 " + x.Group.Name
	case design.DeleteService:
		return "删除服务对象 " + x.Service.Name
	case design.DeleteServiceGroup:
		return "删除服务组 " + x.Group.Name
	case design.DeleteSchedule:
		return "删除时间计划 " + x.Schedule.Name
	case design.AddSchedule:
		return "新增时间计划 " + x.Schedule.Name
	case design.AddNAT:
		return "新增 NAT 规则 " + x.Rule.ID + "（" + where(x.Before) + "，NAT 按顺序首条命中）"
	case design.AddStaticNAT:
		return "新增静态 NAT " + x.Mapping.Real.String() + " ↔ " + x.Mapping.Mapped.String()
	case design.AddZone:
		return "新增安全区域 " + x.Zone.Name
	case design.AddInterface:
		return "配置接口 " + x.Interface.Name
	case design.AddRoute:
		return "新增静态路由 " + x.Route.Destination.String()
	case design.AddVirtualRouter:
		return "新增虚拟路由器 " + x.VirtualRouter.Name
	default:
		return c.String()
	}
}

var auditKindText = map[audit.Kind]string{
	audit.KindRedundant:      "冗余策略",
	audit.KindShadowed:       "被覆盖的策略",
	audit.KindDisabled:       "已禁用的策略",
	audit.KindExpired:        "已过期的策略",
	audit.KindUndecidable:    "无法离线判定的策略",
	audit.KindPermitAny:      "全放通策略",
	audit.KindUnusedAddress:  "未使用的地址对象",
	audit.KindUnusedService:  "未使用的服务对象",
	audit.KindUnusedSchedule: "未使用的时间计划",
	audit.KindIncomplete:     "不完整的策略",
	audit.KindNeverMatches:   "永不命中的策略",
	audit.KindEmptyObject:    "空对象",
}

var planStatusText = map[design.Status]string{
	design.StatusNoChange:      "无需变更",
	design.StatusChange:        "需要变更",
	design.StatusConflict:      "有冲突",
	design.StatusIndeterminate: "无法判定",
}

var countText = map[string]string{
	"zones": "安全区域", "interfaces": "接口", "routes": "路由", "addresses": "地址对象",
	"address_groups": "地址组", "services": "服务对象", "service_groups": "服务组", "schedules": "时间计划",
	"rules": "策略", "undecidable_rules": "无法离线判定的策略", "static_nats": "静态 NAT", "dynamic_nats": "动态 NAT",
}

func yesNo(b bool) string {
	if b {
		return "是"
	}
	return "否"
}
