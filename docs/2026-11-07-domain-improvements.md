# 2026-11-07 防火墙业务实现与改进建议

本次按已批准的计划补齐现有 Go 实现，保留已经建立的精确流量、原生顺序、未知条件和变更安全证明。厂商范围仍为 Palo Alto、SRX、Huawei、Hillstone、Fortinet、Netscreen、ASA。项目处于开发阶段，因此删除过渡接口和历史编码分支，不承担旧 API、旧快照或旧审批字节的兼容。

实施前保存了包含已有修改的 716 文件快照，并按文件哈希合入组件改动；没有覆盖其他工作区修改。没有提交、推送、发布或连接真实设备。

## 已实现的业务与设计

| 业务 | 当前实现 | 关键约束与入口 |
| --- | --- | --- |
| 配置解析 | 七厂商统一 `Parser.Parse(ctx, source, metadata)`；新增绝对及周期时间表语义、原生命令和规则引用；PAN set/XML 保留选定 vsys | `config` 原子提交对象草稿与来源；未知成员保留在所属对象；接口先于路由绑定；见 [时间表能力](../vendors/SCHEDULES.md) |
| 策略查询 | 复用精确多维流量集合、first-match 和各厂商 packet pipeline；增加跨厂商包效果等价证明 | [policy/migration.go](../policy/migration.go) 比较同一原始流量的动作、日志和有序转换关系，动态分配只表示可能性 |
| 需求拆分聚合 | 保留按设备、上下文、安全域和 NAT 坐标拆分的业务流程；以索引完成精确固定点聚合 | [RequestOptimizer](../analysis/request_optimizer.go) 不把源/目的配对扩展为笛卡尔积；本次不引入“拆分已有原生规则”的操作 |
| 策略设计 | 私有对象目录复用完整地址、服务及对象组；按 native namespace 检查作用域遮蔽和命名冲突 | [object_catalog.go](../plan/object_catalog.go) 只复用相等集合；有孔服务、更宽地址和外部作用域不能冒充等价对象 |
| 风险策略发现 | 声明/有效模式结果增加时间、chain、安全域、时间表状态、来源跨度和未知原因 | [RiskEvidence](../analysis/risk_evidence.go) 明示 `native-policy` 坐标；不把 ACL 地址误标为线上原始地址或 NAT 后地址 |
| 跨厂商迁移 | 目标驱动编译选定策略、对象、时间表及有效 NAT 依赖；整批证明后才产生计划 | [Planner.Migrate](../plan/migration.go)、[PolicyMigrator](../analysis/policy_migrator.go)、[能力矩阵](../vendors/MIGRATION.md) |
| 审批与恢复 | intent kind 明确；迁移同时绑定源快照和目标基线，恢复时重新运行编译、渲染与证明 | [reconstruction.go](../plan/reconstruction.go)、[恢复测试](../operations/reconstruction_migration_test.go)；命令文本、旧 proof 标志不能直接恢复为批准计划 |

不可变图继续使用具体领域对象，`StaticNAT` 和 `DynamicNAT` 分离。DTO 用于构造与持久化；封存后以私有索引和有序 slice 保存身份与执行顺序，对外提供标量访问、只读 `iter.Seq` 或独立副本。共享的是地址/服务集合、时钟、命名和证明原语，各厂商仍拥有自己的语法与行为差异。

接口由使用方定义：`Renderer`、`NativeRenderer`、`MigrationNATCompiler` 分别承担普通渲染、原生声明渲染和迁移编译。registry 用组合提供这些能力，避免为七厂商复制转发方法，也没有增加全能厂商基类、反射依赖注入容器或可变全局缓存。新增实现使用标准库。

## 时间、NAT 与迁移的证明边界

`ScheduleRecord.Windows` 保存绝对区间，`WeeklyPeriod` 保存可选起止界限和星期/日内时间窗口。绝对区间和各周期段取并集，周期段内部的日期界限与周窗口取交集；所有内部区间采用半开语义。ASA 的 absolute/periodic 交集、SRX 的具体星期覆盖 daily，以及 Fortinet 的跨午夜行为由原生解析器归一化。

时钟证据绑定设备、软件、上下文、采集时刻和源码摘要，独立说明时区、端点精度及 civil calendar。配置中出现 timezone 不能替代这些证据。未来证明划分绝对边界、周相位及 IANA 时区转换，不能以“未来七天”或固定采样期限冒充完整证明。缺少日历证据、混用周期时区或无法精确表达的原生组合会被拒绝，不会退化为 always。这里建立的是新连接的策略准入，未建立存量会话终止行为。

迁移输入保留源/目标 chain、安全域、接口、VRF 和目标时钟映射；接口与路由必须已存在。空 NAT 列表表示从选定规则的实际包路径推导依赖；显式列表必须包含完整依赖。静态地址原值不因设备迁移而改写。编译器返回声明，随后由独立证明检查：

1. 源的选定有效流量在所有未来时间分区上保留动作、日志与匹配结果。
2. 包路径使用实际路由选出的 egress，而非 NAT 表中假设的接口组合。即使源不做 NAT，只要目标有 NAT，也必须检查其是否改变迁移流量。
3. 转换比较保留原始到转换后关系、端口、分配模式和池范围；相同投影集合不能证明地址映射是恒等。0–65535 与 1024–65535 的 PAT 分配域不能互相替代。
4. 只允许改变选定原始流量及其准确时间相位。规则 A 的依赖不能授权修改未选规则 B；周期 NAT 的某一活动相位不能授权永久转换。
5. 目标其余规则的有效归属、既有 NAT 声明和域外转换关系保持不变。独立原生回读再次验证完整声明与这些证明。

不能证明的选择返回 `MigrationResult.Issues` 且 `Plan == nil`；预算耗尽、取消和无效输入仍是错误。回读不使用生成命令作为配置输入。ScreenOS 先匹配设备分配的策略编号，再严格匹配策略所属 NAT 的派生 ID/名称、作用域与引用；其他原生命名校验保持严格。

## Perl 参考与保留的差异

实际参考根目录为 `/Users/crate/Works/perl/algosec/backend/lib/Firewall`，不是对旧设计的猜测，也没有复制私有源码进入本仓库。

| Perl 参考 | 业务含义 | Go 对应与差异 |
| --- | --- | --- |
| `Config/Content/Static.pm`、各 `Config/Parser/*.pm` | 多阶段扫描、游标、对象和配置来源 | `Content`/`Builder`/事务；对象草稿和消费跨度一起提交，未支持的语法保持 pending/unknown |
| `Policy/Searcher.pm`：`search`、`divideIntoGroups`、`searchFw`、`getZoneFromRoute` | 分组、设备与安全域定位、按路由求上下文 | 保留业务分解，通过 frozen inventory、显式上下文及 packet view 建立证据；未知路由不推断 any |
| `Policy/Searcher.pm`：`getValidRuleSign`、`searchPolicy`、`selectAModifyPolicy`、`createMainAddr` | 复用、修改候选和对象创建 | 精确覆盖、确定性代价排序和整批安全证明；不复刻依赖真值或计数捷径的历史缺陷 |
| `FireFlow/RuleOtimize.pm`：`optimizeRule`、`changeRuleToSet`、`optimize` | 需求集合化及固定点合并 | 保留配对关系与上下文，索引七维矩形并做精确并集；集合等价可由独立小域枚举核对 |
| `Policy/Designer/Srx.pm`：`createSrc`、`createDst`；各厂商 Designer | 原生地址簿作用域、对象/服务/时间表/规则生成 | scope-aware 对象复用，声明边界计数，厂商独立渲染；地址池只能复用相同完整范围 |
| 各 `Config/Element/Schedule/*.pm`：`createTimeRange`、`isEnable` | 时间表端点及活动判断 | 使用绑定采集的时钟与日历；不使用进程本地时区，不丢失重复原生条目 |
| `Config/Ruleopti.pm`、`Config/Audit.pm` | 收敛与风险业务分类 | 维持声明/有效区分、三值证据及全规则库证明，保留来源和坐标信息 |
| `Config/Policytranf.pm`、`Config/Policytranf/Fortinet.pm` | 迁移插件边界 | Fortinet 的 `createAddress/Service/Schedule/Rule/NatPool/StaticNat/DynamicNat/Route` 等方法为空；不能宣称 Go 迁移算法与 Perl 已有实现逐项等价 |

实施时重新核对 [source-references.json](../analysis/testdata/perl-business/source-references.json) 的 31 个实际源文件哈希，全部一致。使用只读挂载、无网络容器重新执行 `optimizer.pl` 与 `schedule_boundaries.pl` 两个合成 Oracle，输出分别与仓库结果一致，标准错误为空。其他历史 Oracle 记录没有在本次全部重跑。Perl 的包含端点和进程时区行为与 Go 的半开区间及外部时钟证据有意不同。

已有差异继续保留：不采用 Perl 空集合真值造成的 OR 误判，不复用比意图更宽的 Fortinet NAT 池，不遗漏 ASA /32 PAT 的 network-object host 声明，也不以日期名称或命中计数捷径建立变更授权。

## 清理与版本

- 删除厂商 package-level `Parse` 和 Fortinet `ParseVDOM`，所有实际调用迁移到 `Parser.Parse` 与 `Metadata.Context`。
- 删除 `operations.EncodePlan`、重构错误别名等转发接口，调用方直接使用 `plan` 的定义。
- 删除旧 approval/intent 兼容字节 fixtures 和旧快照格式测试，保留并补强行为、篡改、预算及重建证明测试。
- Snapshot semantic **10**、reconstruction **2**、approval **4** 是当前合同。快照加载不重新解析配置，不查数据库，不猜旧格式；没有自动删除用户存储文件。
- 资源限额在复制大声明之前检查。Resolver 通过只读迭代处理大型服务/对象组，缓存命中仍计费；目录调用同时受当前剩余访问额度约束。

## 本地验证

最终集成在本机 Go 1.27.1 / darwin arm64 上通过下列检查：

| 验证 | 结果与含义 |
| --- | --- |
| 主模块 `GOWORK=off GOPROXY=off go test ./...`、`go vet ./...`、`go build ./...`、`go test -race ./...` | 全部通过，包含七厂商、CLI、存储、分析、规划、operations 和模拟部署 |
| `adapter/netconnector` 的 test / vet / build / race | 全部通过；使用临时 go.work 配对当前 core，不改其发布依赖，不等于新发布版本的独立消费者验证 |
| 七厂商基础策略迁移 | 42 个有向跨厂商组合，通过完整迁移、独立原生回读和请求范围检查；不代表所有原生策略形态均支持 |
| 周期时间迁移 | 七个目标原生语法，检查未来周和一年后的边界；缺少 clock、原生组合不支持及遗漏前序时间遮蔽均拒绝 |
| NAT 迁移 | 16 个完整 Migrate + 独立 Verify 正例，其中 12 个跨厂商；另 5 个 DNAT 编译/查询正例仅证明目标表达，不等同跨厂商完整包证明 |
| 反例 | 端口分配域、地址池端点、接口地址、NAT owner、引用、时间相位、未选策略、source identity/target NAT、快照与审批漂移、取消和预算检查通过 |
| 定时 fuzz | 五个目标各运行 10 秒、2 workers，全部通过；flow 167,591 次，Content ownership 72,253 次，Fortinet 33,064 次，Huawei 57 次，ScreenOS 17,618 次。执行数差异很大，这不是穷举或解析器性能比较 |
| Perl | 31 个实际源码哈希一致；两个只读 Oracle 重新执行并与记录相等 |
| 静态收尾 | 改动 Go 文件 gofmt、`git diff --check`、本次相关文档相对链接检查通过 |

主模块的普通测试与 race 都在合入全部组件后执行。临时 workspace 只包含主模块与 adapter；没有通过 `replace` 冒充已发布依赖。CI、发布制品与真实设备没有在本次执行。

可重复执行的 fuzz 入口为 `flow/FuzzTrafficAgainstPacketOracle`、
`config/FuzzContentSourceOwnership` 和
`vendors/{fortinet,huawei,netscreen}/FuzzScopedCapture`，使用
`go test <package> -run '^$' -fuzz '^<name>$' -fuzztime=10s -parallel=2`。

[性能记录](2026-11-07-domain-benchmarks.md) 保存相同工具链和合成输入的六次基准原始结果、源码哈希及中位数。需求聚合的本次四类样本耗时降低约 22%–56%，分配量同时降低；完整规划的对象复用基准没有一致 CPU 收益，增加了作用域和完整集合检查。不要将其外推为生产配置性能或全局最优规划证明。

## 后续建议与验收方式

| 优先级 | 建议 | 原因与可验证的交付条件 |
| --- | --- | --- |
| P1 | 完成 DNAT 后混合策略归属的精确逆像算法，再扩展组合/反向 NAT 迁移 | 当前对整块同效果可证明，混合归属或 reverse composition 保守拒绝。实现应对每个选定 native-policy 分区求原始流量逆像，并用地址置换、端口偏移、前序 deny、部分选择反例验证，不能只比较投影并集 |
| P1 | 按业务需求补 ASA 与 Hillstone 的目标 NAT 编译器 | 两者已有 native creation，但当前迁移入口对所选 NAT 明确拒绝。复用现有声明验证，逐个建立源输入、目标独立原生 capture、域外保持和重建测试；不要补一个“通用 NAT 转字符串”接口 |
| P1 | 为 wire/real/translated 风险增加独立的包风险分析入口 | 当前风险已诚实标注 native-policy 坐标。新入口应组合 QueryPacket 分区，区分可能的动态分配与确定映射，同时保留未知路由、未匹配策略和来源；不能靠字段改名转换坐标 |
| P1 | 建立受控实验环境的原生接受测试 | 本地证明尚不能保证某固件接受命令、时钟端点、会话行为及保存流程。按能力矩阵固定版本，独立采集 before/after 和 clock evidence，逐项核对并保留失败证据；设备操作需要另行授权 |
| P2 | 根据 profile 优化候选发现与对象目录 | 候选搜索虽用有界 heap，仍会为合格 append 候选构造图。先测大规则库的 allocation/CPU，再考虑廉价草稿筛选、延迟建图；同时维持确定性代价、预算及最终完整证明 |
| P2 | 扩充日历表达能力 | Huawei absolute+periodic、不同周期时区、节假日例外、PAN 非默认 vsys 命令等仍有明确限制。每项先取得版本定义与端点证据，再补 gap/fold、跨周、日期终点及独立回读；不要增加模糊字符串逃生口 |
| P2 | 增加可分发的合成样本分层与成本监测 | 以规则数、组深度、服务片段、时间边界、NAT 阶段建立固定样本，记录耗时、分配、MaxVisits/MaxRegions/MaxCombinations。性能阈值应来自稳定重复测量，不能把当前几项本机中位数当 SLA |
| P2 | 在正式发布时完成独立消费者验证 | 本次 adapter 以临时 workspace 配对当前 core 验证；发布后须移除本地替换，以版本化 core 依赖重新构建/测试，并分别记录同提交 CI、制品与真实设备证据 |

现有原生规则拆分、整网接口/路由生成和数据库持久化不是本次范围。若以后引入，应作为明确业务能力设计，避免通过迁移请求的隐含副作用扩张。
