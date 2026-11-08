# Go 逐模块清理记录

本轮以 `main` 的 `10a52fd3ffd4fbaf9685b0e378afe11c0abb8da9` 为基线，
实现开发阶段的命名、兼容入口和重复实现清理。工作分支为
`refactor/idiomatic-go`；这些改动尚未发布。

设计依据为 [spec](spec.md)、[实施计划](plans/go-firewall.md) 和当前调用链。
命名按所属包和职责缩短；抽象围绕数据所有权、业务边界与可验证行为组织，
继续采用具体类型、组合和由使用方定义的小接口。

## 逐模块结果

| 模块 | 审查结论与实现 |
| --- | --- |
| `firemon` | 删除自写 `cmpInt`，排序使用标准库 `cmp.Compare`。保留不可变图、共享对象身份、复制读取与独立 `StaticNAT` / `DynamicNAT`。 |
| `flow` | 保留区间与多维流量集合。未发现本轮应删除的兼容层；零值、空集合和精确流量配对仍有不同语义。 |
| `config` | 保留 Content、Builder、事务和 source evidence 的原子提交，以及接口先于路由的阶段依赖。原生结构扫描器有各自语法责任。 |
| `policy` | 保留一次调用的 Engine 解析入口和绑定不可变图的 Resolver 缓存，两者是不同使用边界。未知条件、预算错误和首条命中行为保持。 |
| `analysis` | `RequestOptimizer` 改为 `Optimizer`，`PolicyMigrator` 改为 `Migrator`，源文件同步缩短且不留别名。用 `errors.AsType` 识别迁移拒绝；删除 RevisionComparer 返回同一错误的重复分支。 |
| `plan` | 删除无调用的 `nativeTrafficRegions` 和纯转发的 `proveBatchPolicy`。内部名称改为 `proveTargets`、`validateInlineOwners`、`preserveOutside`。候选成本、流量证明、外部行为保留和独立读回验证继续运行。 |
| `operations` | 重建与批量输入共享 `jsonio`；保留业务错误映射和边界校验。相同底层结构直接用 `BatchSourceDocument(source)` 转换。Runtime 和 RestorePlan 各有组合、快照恢复职责，保留。 |
| `snapshot` | 删除 `atomicWrite` 与锁转发文件，直接调用 `durablefile.Replace/Lock`。快照仍是持久化权威；加载不解析原始配置、不访问数据库。 |
| `deploy` | 删除 `writeJournal` 与 `journalLock` 转发。保留租约、落盘顺序、短写错误、关闭错误、取消和不重放未知写入的恢复契约。 |
| `inventory` / `projection` | 保留快照读取、版本选择和 outbox 投影边界；接口承担实际依赖隔离，未发现需要删除的过渡层。 |
| `device` | 保留 Reader 和配置视图契约，继续隔离只读采集与部署能力。 |
| `vendors` | 注册入口只接受七个规范名称；删除 aliases 字段和别名查找。`Normalize` 继续校验名称并填充 Fortinet 默认 context。 |
| `vendors/internal/render` | `NativeBuilder` 改为 `Builder`，并集中七厂商重复的 schedule 准备步骤；`Commands`、`ScheduleName` 表达批次职责。删除无调用的 `SameMatch`，将 schedule 版本判定与生成函数私有化。 |
| 七个原生驱动 | 保留各厂商 quoting、token、命令顺序和版本门槛。删除 `nativeName`、`nativename.Name` 及 Fortinet/Netscreen 的 `label` 回退，命名对象直接读取 `Name`。PAN 插入策略时，既有排序锚点缺名会拒绝渲染。删除 Fortinet 测试中立即被覆盖的首次解析。 |
| `adapter/netconnector` | 删除 `domainVendor` 别名归一化。`profileName` 只做规范名称到依赖 profile 的桥接；字段使用 `meta`、`opts`、`token`，校验表达式使用 `tokenPattern`。用 `strings.CutLast` 处理最后一行，并保留正文、提示符和命令回显边界。 |
| `cmd/firemon` | 删除仅供测试的 `run` 转发，测试直接传 `t.Context()` 到 `execute`。私有 DTO 使用 `queryDoc`、`inspectDoc`、`riskExprDoc`、`riskDoc`、`reclaimDoc`、`migrationDoc`、`counterDoc`；输入与限额写入名称缩短为 `readJSON`、`readUsage`、`limitWriter`。 |
| `internal/durablefile` | 接口使用 `dir`，测试替身使用 `fakeDir`；保留消费方所需的最小方法集合和文件替换顺序。 |
| `internal/jsonio` | 提供 `Read`、`Decode`、`Encode`，只处理字节上限、严格 JSON 和取消，不依赖业务包。 |
| `internal/names` | 保留对象/策略名称冲突索引，明确 ASA 对象组、SRX 安全域对和 Fortinet VDOM 的作用域差异。没有名称读取包装，也不根据图 ID 推断对象名称。 |

## 对象名、策略名与内部 ID

`Object.Name` 是配置中声明的对象名称，`Object.ID` 是图中对象的标识。
数字策略编号仍走对应厂商的明确规则；匿名内联地址、服务和关联 NAT pool 可以合法
没有名称。缺名的值仍参与查询，但不能被当成可复用的命名声明，也不能把图 ID 写作
地址、服务、区域或命名策略的配置名称。

对象目录直接保存每条引用的 kind、id、name、scope，删除按类型反查或推断名称的
`nativeObject` 包装。变更检查与读回匹配使用可比较结构键，分别保存名称、作用域、
NAT 分区和匿名记录 ID，替换拼接字符串的名称键。

策略去重使用单独的规则键：SRX 的同名策略按源/目的安全域对区分，PAN/Huawei
保留所在策略链内的名称唯一性；Hillstone、Fortinet、Netscreen 的策略编号和 ASA
ACL 条目标识独立于显示名称。修复了按通用对象名去重而误拒合法策略的问题。
18 个公开 `ValidateNativeChanges` 场景覆盖已有规则和同批新增两条路径。

回归用例分别证明：缺名地址/服务不作为命名对象复用；命令引用缺名对象或策略时拒绝；
PAN 既有排序锚点缺名时拒绝，不能把它当成不存在。新测试在修改前实现上失败，
修改后通过；原有数字策略、匿名 NAT 值和七厂商渲染测试继续验证各自语义。

## 输入与格式契约

厂商入口接受 `paloalto`、`srx`、`huawei`、`hillstone`、`fortinet`、
`netscreen`、`asa`。`palo_alto`、`juniper`、`screenos`、`cisco_asa`
均不能用作厂商输入。连接器依赖实际使用的 `palo_alto`、`juniper`
profile 名称只存在于适配器内部映射；`New` 接受对应的依赖 profile 或规范名称的
自定义 profile，metadata 保持规范名称。别名和不匹配 profile 在拨号前拒绝。
Fortinet 在线采集仍要求显式 context，离线解析仍默认 `root`。

JSON 读取最多消耗限额加一个字节，用于识别超限。解码拒绝未知字段和尾随内容，
编码的末尾换行计入上限。业务包继续负责 typed-nil 检查、校验和、版本和错误映射；
底层 I/O / JSON 错误保持可识别，失败与取消不产生公开的部分成功结果。
编码仍使用 `encoding/json` 的内部缓冲，上限限制输出大小，不是编码器的内存配额。

删除五处对非指针结构字段无效的 `omitempty`，保留零值时间和地址引用原有编码，
没有改成会删除字段的 `omitzero`。快照语义格式 10、重建格式 2、审批格式 4 均不变。

## 原生语义依据

实际检查了只读 Perl 参考树中的 `Firewall/Config/Parser/Asa.pm` 的
`isNewNat/parseNewNat`，以及 `Firewall/Policy/Designer/Hillstone.pm` 的
`createSchedule`。ASA 的 NAT 阶段/版本判断和 Hillstone 的 schedule 语法属于
设备业务语义，应保留；本轮删除的是 Go 接口别名与无行为包装。

名称纠正另追踪了 Perl `Policy/Designer/Asa.pm:216`、
`Policy/Designer/Hillstone.pm:128`、`Policy/Designer/Srx.pm:124` 与对应 Parser。
这些实现区分对象/服务名称、策略名称和数字策略编号。所查 Perl 目录没有 Palo Alto
实现；PAN 的命名证据来自当前 parser、renderer 和合成配置，未声称有 Perl 对照。

Schedule 准备移入 Builder 后，仍位于原生变更校验、厂商校验、声明登记与取消检查
之后。批次内 schedule 命令仍先于 nativeCommands 追加的命令；各驱动在批次外生成的
独立地址/服务声明仍保持原先位置。原生引用、时钟证据与版本门槛没有改变。

## 验证

本地环境为 macOS arm64、Go 1.27.1，模块要求保持 Go 1.27.0。
依赖版本和 `go.mod` / `go.sum` 均不变。验证使用合成配置与会话。

| 检查范围 | 结果 |
| --- | --- |
| 主模块，`GOWORK=off` | `go test -count=1 ./...`、`go test -race -count=1 ./...`、`go vet ./...`、`go build ./...`、`go mod verify` 全部通过。 |
| `adapter/netconnector` 与本轮主模块组合 | 临时 workspace 仅连接这两个模块；同样的测试、竞态、vet、构建和依赖校验全部通过。 |
| `adapter/netconnector` 独立依赖 | `GOWORK=off` 下普通测试、竞态、vet、构建和依赖校验通过；模块依赖声明未改动。 |
| 两个模块的静态检查 | Staticcheck v0.8.1、`deadcode -test` 均无报告；主模块基线分别有 3 项和 2 项。 |
| 现代化检查 | Go 1.27.1 的 fix 分析器以只读 vet 方式运行，除未纳入本轮的 `embedlit` 外，无报告。 |
| 格式与文档 | 修改的 Go 文件符合 gofmt，`git diff --check` 通过，修改文档中的相对文件链接有效。 |
| 原工作区保护 | 763 个路径的内容及删除状态核对一致，工作区状态、HEAD 和既有 tag 与初始记录一致。 |

专项验证覆盖：厂商别名拒绝且不拨号、profile 匹配、Fortinet context、
schedule 真实渲染入口、不可表示的 Fortinet 周期、空/单行/多行配置正文、
typed-nil 与错误优先级、JSON 尾随内容、读写上限和取消。
有限时间重建、三份策略重建和批量报告与重构前实际编码的 SHA-256 对照一致。
另一次只读复核未发现 JSON 提取引起的可观察行为回归。

## 交付边界

改动位于独立目录 `/Users/crate/Works/go/.firemon-cleanup-20261107`。
原 `/Users/crate/Works/go/firemon` 的工作区、索引、HEAD 和既有 tag 保留；
没有执行提交、推送或发布。此处验证是本地源码验证，不代表这些改动已通过远端 CI
或真实设备验收。
