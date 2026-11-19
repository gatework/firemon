package cli

import (
	"regexp"
	"strings"

	"github.com/gatework/firemon"
)

// reasonRule rewrites one reason of the library into Chinese. sub names the
// capture groups that are reasons themselves and are translated in turn.
type reasonRule struct {
	re   *regexp.Regexp
	repl string
	sub  []int
	// words translates the field names in the captures.
	words bool
}

// reasonRules translate the reasons the parsers, the compiler, audit,
// converge and migrate give; a reason of another form is printed as it is.
// The first rule that matches a part wins.
var reasonRules = []reasonRule{
	// Compiled rules and objects.
	{re: regexp.MustCompile(`^application match (.+)$`), repl: "按应用匹配（$1）"},
	{re: regexp.MustCompile(`^application-default service$`), repl: "服务为 application-default（按应用的默认端口）"},
	{re: regexp.MustCompile(`^category (.+)$`), repl: "按 URL 分类匹配（$1）"},
	{re: regexp.MustCompile(`^unresolvable fqdn "(.+)" in "(.+)"$`), repl: "域名 $1（对象 $2）无法离线解析"},
	{re: regexp.MustCompile(`^unresolvable fqdn "(.+)"$`), repl: "域名 $1 无法离线解析"},
	{re: regexp.MustCompile(`^unresolvable (.+)$`), repl: "无法离线解析：$1"},
	{re: regexp.MustCompile(`^domain-book (.+)$`), repl: "按域名库匹配（$1）"},
	{re: regexp.MustCompile(`^source-user (.+)$`), repl: "按用户匹配（$1）"},
	{re: regexp.MustCompile(`^user-group (.+)$`), repl: "按用户组匹配（$1）"},
	{re: regexp.MustCompile(`^vlan-id (.+)$`), repl: "按 VLAN $1 匹配"},
	{re: regexp.MustCompile(`^incomplete, never matches: no (.+)$`), repl: "策略不完整，永不命中：缺少$1", words: true},
	{re: regexp.MustCompile(`^incomplete rule, ignored by the device: no (.+)$`), repl: "策略不完整，设备上不生效：缺少$1", words: true},
	{re: regexp.MustCompile(`^not installed: no route reaches next hop (.+)$`), repl: "未生效：没有路由能到达下一跳 $1"},
	{re: regexp.MustCompile(`^only exclusions: read as every address except them$`), repl: "只有排除项：按“排除项以外的全部地址”处理"},
	{re: regexp.MustCompile(`^invalid entry (.+)$`), repl: "无效条目 $1"},
	{re: regexp.MustCompile(`^unknown address (.+)$`), repl: "未定义的地址 $1"},
	{re: regexp.MustCompile(`^unknown service (.+)$`), repl: "未定义的服务 $1"},
	{re: regexp.MustCompile(`^address membership cycle through (.+)$`), repl: "地址组循环引用：$1"},
	{re: regexp.MustCompile(`^service membership cycle through (.+)$`), repl: "服务组循环引用：$1"},
	{re: regexp.MustCompile(`^dynamic address group (.+)$`), repl: "动态地址组 $1"},
	{re: regexp.MustCompile(`^unsupported periodic schedule$`), repl: "不支持的周期时间计划"},
	{re: regexp.MustCompile(`^invalid address$`), repl: "无效地址"},
	{re: regexp.MustCompile(`^invalid address value$`), repl: "无效的地址值"},
	{re: regexp.MustCompile(`^invalid absolute schedule$`), repl: "无效的绝对时间计划"},
	{re: regexp.MustCompile(`^invalid icmp service$`), repl: "无效的 ICMP 服务"},
	{re: regexp.MustCompile(`^invalid interface address$`), repl: "无效的接口地址"},
	{re: regexp.MustCompile(`^invalid protocol$`), repl: "无效的协议"},
	{re: regexp.MustCompile(`^invalid rule operand$`), repl: "无效的策略条件"},
	{re: regexp.MustCompile(`^invalid service ports$`), repl: "无效的服务端口"},
	{re: regexp.MustCompile(`^invalid service$`), repl: "无效的服务"},
	{re: regexp.MustCompile(`^invalid static route attribute$`), repl: "无效的静态路由属性"},
	{re: regexp.MustCompile(`^Panorama scope is not supported$`), repl: "不支持 Panorama 作用域"},
	{re: regexp.MustCompile(`^several vsys are merged into one policy$`), repl: "多个 vsys 已合并为一套策略"},
	{re: regexp.MustCompile(`^unrecognized (address|address-group|service|service-group) attribute$`), repl: "无法识别的对象属性"},
	{re: regexp.MustCompile(`^unsupported periodic schedule$`), repl: "不支持的周期时间计划"},
	{re: regexp.MustCompile(`^unsupported schedule$`), repl: "不支持的时间计划"},
	{re: regexp.MustCompile(`^unsupported (.+)$`), repl: "不支持：$1"},
	{re: regexp.MustCompile(`^wildcard addresses are not supported$`), repl: "不支持通配地址"},
	// Audit and converge.
	{re: regexp.MustCompile(`^zones (\S+) -> (\S+)$`), repl: "区域 $1 → $2"},
	{re: regexp.MustCompile(`^an operand is empty$`), repl: "引用的对象为空"},
	{re: regexp.MustCompile(`^equal contents (.+)$`), repl: "内容相同（$1）"},
	{re: regexp.MustCompile(`^refer to one of (.+)$`), repl: "可统一引用其中之一：$1"},
	{re: regexp.MustCompile(`^definition not fully modelled: a rollback could not recreate it$`), repl: "定义未完全建模：回退无法完整重建"},
	{re: regexp.MustCompile(`^named in a configuration line that was not parsed: it may be in use$`), repl: "出现在未解析的配置行中：可能仍在使用"},
	{re: regexp.MustCompile(`^the rule has criteria the model does not hold: a rollback could not restore it exactly$`), repl: "策略含模型未覆盖的条件：回退无法精确恢复"},
	// Migration.
	{re: regexp.MustCompile(`^ignored by the source device \((.+)\); not carried over$`), repl: "源设备上不生效（$1），不迁移", sub: []int{1}},
	{re: regexp.MustCompile(`^criterion not translated: (.+)$`), repl: "条件未翻译：$1", sub: []int{1}},
	{re: regexp.MustCompile(`^rule group (.+) not carried over$`), repl: "策略组 $1 未迁移"},
	{re: regexp.MustCompile(`^services (.+) are applications on the target and the rule already matches applications$`), repl: "服务 $1 在目标设备上是应用，而策略已按应用匹配，无法合写"},
	{re: regexp.MustCompile(`^services without ports written as applications (.+)$`), repl: "无端口的服务写为应用 $1"},
	{re: regexp.MustCompile(`^negated (source|destination) cannot be resolved exactly$`), repl: "取反的$1无法精确解析", sub: []int{1}},
	{re: regexp.MustCompile(`^negated (source|destination) written as its complement (.+)$`), repl: "取反的$1写为补集对象 $2", sub: []int{1}},
	{re: regexp.MustCompile(`^(source|destination)$`), repl: "$1", words: true},
	{re: regexp.MustCompile(`^wildcard domain (\S+) has no address object form$`), repl: "通配域名 $1 无法写成地址对象"},
	{re: regexp.MustCompile(`^wildcard domain names have no address object form$`), repl: "通配域名无法写成地址对象"},
	{re: regexp.MustCompile(`^use a URL category$`), repl: "请改用 URL 分类"},
	{re: regexp.MustCompile(`^only TCP, UDP and SCTP ports are services on the target$`), repl: "目标设备的服务只能是 TCP、UDP、SCTP 端口"},
	{re: regexp.MustCompile(`^use an application such as icmp or ping$`), repl: "请改用应用（如 icmp、ping）"},
	{re: regexp.MustCompile(`^address (.+) cannot be resolved$`), repl: "地址 $1 无法解析"},
	{re: regexp.MustCompile(`^inline services of the rule have no target form$`), repl: "策略的内联服务在目标设备上无对应写法"},
	{re: regexp.MustCompile(`^application-default dropped: the applications match on any port$`), repl: "去掉 application-default：应用按任意端口匹配"},
	{re: regexp.MustCompile(`^application (.+) written as (.+) \(same protocol, vendor signatures differ\)$`), repl: "应用 $1 写为 $2（同一协议，厂商识别特征不同，请核对）"},
	{re: regexp.MustCompile(`^application (.+) has no mapping$`), repl: "应用 $1 在目标设备上没有对应"},
	{re: regexp.MustCompile(`^applications (.+) have no mapping$`), repl: "应用 $1 在目标设备上没有对应"},
	{re: regexp.MustCompile(`^the deny is kept on its services for every application \(stricter\)$`), repl: "拒绝策略保留原服务，对所有应用生效（更严格）"},
	{re: regexp.MustCompile(`^applications (.+) have no mapping and their ports are unknown$`), repl: "应用 $1 在目标设备上没有对应，且端口未知"},
	{re: regexp.MustCompile(`^map them \(--mapping\) or the deny is lost$`), repl: "请用 --mapping 补充对应，否则该拒绝策略失效"},
	{re: regexp.MustCompile(`^their ports (.+) have no service form$`), repl: "其端口 $1 无法写成服务"},
	{re: regexp.MustCompile(`^the deny is kept on their default ports (.+) for every application \(stricter there, blind elsewhere\)$`), repl: "拒绝策略按其默认端口 $1 对所有应用生效（这些端口上更严格，其他端口上的该应用不再被拦截）"},
	{re: regexp.MustCompile(`^a rule with both a schedule and a validity window$`), repl: "策略同时有时间计划和有效期"},
	{re: regexp.MustCompile(`^a (validity )?window without a start$`), repl: "有效期没有开始时间"},
	{re: regexp.MustCompile(`^rule-type (.+) written as (\d+) zone pairs$`), repl: "策略类型 $1 写为 $2 个区域对"},
	{re: regexp.MustCompile(`^the target's default differs: (.+)$`), repl: "目标设备的默认动作不同：$1"},
	{re: regexp.MustCompile(`^the mapping's addresses cannot be translated$`), repl: "映射的地址无法翻译"},
	{re: regexp.MustCompile(`^the zone is created; its bridging or tap setup \(vswitch, virtual wire\) is not translated$`), repl: "已创建区域；其桥接或旁路设置（vswitch、virtual wire）未翻译"},
	{re: regexp.MustCompile(`^name kept: map it to the target port$`), repl: "保留原名：请在映射文件中对应到目标端口"},
	{re: regexp.MustCompile(`^addresses taken from objects are written as addresses$`), repl: "引用对象的地址已写为具体地址"},
	{re: regexp.MustCompile(`^discard routes are not written for StoneOS$`), repl: "StoneOS 不写黑洞路由"},
	{re: regexp.MustCompile(`^action differs$`), repl: "动作不同"},
	{re: regexp.MustCompile(`^zones differ$`), repl: "区域不同"},
	{re: regexp.MustCompile(`^match differs after translation$`), repl: "翻译后匹配范围不同"},
	{re: regexp.MustCompile(`^the translated rule cannot be evaluated exactly$`), repl: "翻译后的策略无法精确判定"},
	{re: regexp.MustCompile(`^the source rule cannot be evaluated exactly, so the translation cannot be verified$`), repl: "源策略无法精确判定，翻译无法核对"},
	{re: regexp.MustCompile(`^the source (object|group|service) has lines that were not parsed$`), repl: "源对象有未解析的行"},
	{re: regexp.MustCompile(`^an empty (object|service) has no form on the target$`), repl: "空对象在目标设备上无对应写法"},
	{re: regexp.MustCompile(`^split into one object per entry, grouped under the same name$`), repl: "拆为每个条目一个对象，再以原名组成地址组"},
	{re: regexp.MustCompile(`^split into one service per protocol, grouped under the same name$`), repl: "按协议拆为多个服务，再以原名组成服务组"},
	{re: regexp.MustCompile(`^exclusions together with domain names cannot be computed$`), repl: "排除项与域名同时存在，无法计算"},
	{re: regexp.MustCompile(`^the (object|group) cannot be resolved exactly$`), repl: "对象无法精确解析"},
	{re: regexp.MustCompile(`^exclusions computed into the remaining ranges$`), repl: "排除项已计算为剩余的地址范围"},
	{re: regexp.MustCompile(`^dynamic address groups have no static form$`), repl: "动态地址组无法写成静态形式"},
	{re: regexp.MustCompile(`^inline entries and exclusions resolved into addresses$`), repl: "内联条目和排除项已解析为地址"},
	{re: regexp.MustCompile(`^the service cannot be resolved$`), repl: "服务无法解析"},
	{re: regexp.MustCompile(`^mapped to (.+), whose ports differ \((.+) vs (.+)\)$`), repl: "对应为 $1，但端口不同（$2 与 $3）"},
	{re: regexp.MustCompile(`^unsupported period (.+)$`), repl: "不支持的周期 $1"},
	{re: regexp.MustCompile(`^mixes kinds of periods, which one PAN-OS schedule cannot$`), repl: "混用多种周期，一个 PAN-OS 时间计划无法表达"},
	{re: regexp.MustCompile(`^ends rounded up to the minute \(PAN-OS counts minutes\)$`), repl: "结束时间进位到分钟（PAN-OS 以分钟计）"},
	// "name: reason" forms, last: the reason part is translated.
	{re: regexp.MustCompile(`^service (\S+): (.+)$`), repl: "服务 $1：$2", sub: []int{2}},
	{re: regexp.MustCompile(`^schedule (\S+): (.+)$`), repl: "时间计划 $1：$2", sub: []int{2}},
	{re: regexp.MustCompile(`^member (\S+): (.+)$`), repl: "成员 $1：$2", sub: []int{2}},
	{re: regexp.MustCompile(`^translated rule (\S+): (.+)$`), repl: "翻译后的策略 $1：$2", sub: []int{2}},
	{re: regexp.MustCompile(`^([^\s:]+): (.+)$`), repl: "$1：$2", sub: []int{2}},
}

// reasonWords translate the field names reasons list.
var reasonWords = strings.NewReplacer("action", "动作", "source", "源", "destination", "目的", "service", "服务", ", ", "、")

// zhReason translates a reason; parts joined by "; " are translated one by
// one.
func zhReason(s string) string {
	if s == "" {
		return ""
	}
	for _, r := range reasonRules {
		if strings.Contains(r.re.String(), "; ") && r.re.MatchString(s) {
			return zhPart(s, 0) // a reason that holds "; " itself
		}
	}
	parts := strings.Split(s, "; ")
	for i, part := range parts {
		parts[i] = zhPart(part, 0)
	}
	return strings.Join(parts, "；")
}

func zhPart(s string, depth int) string {
	if depth > 3 {
		return s
	}
	for _, r := range reasonRules {
		m := r.re.FindStringSubmatchIndex(s)
		if m == nil {
			continue
		}
		groups := make([]string, len(m)/2)
		for g := range groups {
			if m[2*g] >= 0 {
				groups[g] = s[m[2*g]:m[2*g+1]]
			}
		}
		for _, g := range r.sub {
			groups[g] = zhPart(groups[g], depth+1)
		}
		if r.words {
			for g := 1; g < len(groups); g++ {
				groups[g] = reasonWords.Replace(groups[g])
			}
		}
		out := r.repl
		for g := len(groups) - 1; g >= 1; g-- {
			out = strings.ReplaceAll(out, "$"+itoa(g), groups[g])
		}
		return out
	}
	return s
}

// issueObjects name the kinds of objects an issue is about.
var issueObjects = []struct{ prefix, zh string }{
	{"policy route ", "策略路由 "}, {"rule ", "策略 "}, {"route ", "路由 "}, {"nat ", "NAT "},
	{"address ", "地址 "}, {"service ", "服务 "}, {"schedule ", "时间计划 "}, {"static ", "静态 NAT "},
}

// zhIssue writes an issue as "对象：原因" in Chinese.
func zhIssue(i firemon.Issue) string {
	obj := i.Object
	for _, o := range issueObjects {
		if rest, ok := strings.CutPrefix(obj, o.prefix); ok {
			obj = o.zh + rest
			break
		}
	}
	if obj == "" {
		return zhReason(i.Reason)
	}
	return obj + "：" + zhReason(i.Reason)
}
