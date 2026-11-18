package cli

import (
	"github.com/gatework/firemon"
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
	report.StatusUnset:         "未经过任何防火墙",
	report.StatusFullMatch:     "完全命中",
	report.StatusPartialMatch:  "部分命中",
	report.StatusNeedNew:       "需要新增",
	report.StatusBlocked:       "被拒绝",
	report.StatusIndeterminate: "无法判定",
}

var verdictText = map[query.Verdict]string{
	query.VerdictAllowed:       "放通",
	query.VerdictDenied:        "拒绝",
	query.VerdictPartial:       "部分放通",
	query.VerdictIndeterminate: "无法判定",
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
	report.ReasonApplications:      "按应用匹配",
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
	converge.CategoryUnusedObject: "未使用对象",
	converge.CategoryEmptyObject:  "空对象",
	converge.CategoryNeverMatches: "永不匹配的策略",
	converge.CategoryIncomplete:   "不完整策略（设备忽略）",
	converge.CategoryDisabled:     "已禁用策略",
	converge.CategoryExpired:      "已过期策略",
	converge.CategoryRedundant:    "冗余策略（被同动作策略完全覆盖）",
	converge.CategoryShadowed:     "被遮蔽策略（被相反动作策略完全覆盖）",
	converge.CategoryMergeable:    "可合并策略",
	converge.CategoryBroad:        "过宽放通",
	converge.CategoryZeroHit:      "零命中策略",
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
