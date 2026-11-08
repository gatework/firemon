# 配置解析基础与 Hillstone 组件重构

本轮接入正式发布的 `github.com/gatework/parser v0.1.0` 和
`github.com/gatework/set v0.1.0`，没有本地 replace 或依赖源码副本。
两项依赖自身均只使用标准库，项目仍要求 Go 1.27。

## 职责与接口

| 组件 | 职责 |
| --- | --- |
| parser.Content | 原始文本、物理行索引、字节定位、缓存摘要 |
| config.Content / Builder | 采集上下文、来源证据、类型化记录、原子提交与阶段回滚 |
| Hillstone document | 原生作用域、声明重开、语句顺序 |
| Hillstone catalog | 地址与服务引用类型、外部服务目录、对象草稿 |
| Hillstone topology | 区域与 VRF 关系、接口绑定、直连与静态路由草稿 |
| flow.AddressSet | 不可变地址集合；IPv4 委托整数集合，IPv6 与差集保留精确区间算法 |

解析入口仍为 `Parser.Parse`，阶段顺序仍为结构、区域、接口、对象、路由、规则、NAT、
封存。规则通过目录与拓扑解析选择器；NAT 使用阶段内的不可变图解析地址和服务，
继续产生独立的 StaticNAT、DynamicNAT。公开 Parser 不保存跨次调用的构造状态。

删除了本地 `config.Line`、Peek/NextPending/Rewind/Checkpoint/Restore、
事务中的读位置回退及无实际调用者的 NewFragmentContent。`Content.Lines()` 现在返回
`[]parser.Line`，Text 只移除行结束符，保留缩进。Hillstone 在语法识别处显式处理空白。
没有保留兼容别名、转发层或第二份 parsed 标记。

CLI 的证据按物理行提交，XML 按字节片段提交。同一物理行上的已知与未知 XML 内容
可以保留不同状态。读取不修改证据，失败提交、取消及嵌套阶段回滚恢复对象与证据。
快照格式和解析器版本保持不变，加载快照仍直接恢复图。

IPv4 范围先验证再交给 set：反向范围仍然拒绝。IPv4 映射的 IPv6 保持 IPv6 身份，
地址族之间不会合并。源端口和目的端口继续属于同一 ServiceTerm，未拆开归并。

资源边界有一项收紧：XML 的 MaxLines 现在严格统计物理行，包括末尾未带换行的行；
原来的换行计数可能在限额处额外接受一行。XML token 限额、深度限额、UTF-8 校验、
服务项限额与取消检查继续保留。

## Perl 业务参照

参照 `Firewall/Config/Parser/Hillstone.pm` 的 `parse` 两阶段组织，以及
parseZone、parseInterface、parseAddress、parseService、parseServiceGroup、
parseSchedule、parseRoute、parseRule、parseNat、addRouteToInterface、addZoneRange。
`Parser/Role.pm` 和 `Parser/Elements.pm` 提供了内容、对象目录与报告的职责参照。

Go 保留类型化对象、作用域内路由绑定、明确执行顺序和未知条件，不移植动态类分发。
Perl 的预定义服务优先查找与现有 Go 行为不同：Go 继续让配置中的显式声明优先，
由调用者提供的服务目录仅补齐缺失定义。未按常见端口猜测未定义服务。

## 验证结果

- 重构前后只读回放同一批 20 份 Hillstone、2 份 Palo Alto 配置；22 份图的
  SemanticDigest 和完整 Export JSON 的 SHA-256 全部相同。这同时核对了对象、
  来源原文、证据、顺序、诊断和元数据。采集失败的另一条 Palo Alto 记录仍单独报告。
- 七厂商现有冻结图、查询、NAT、迁移及快照回归通过。没有重设冻结预期摘要。
- 根模块及配对当前核心的 netconnector 适配器通过普通测试、竞态测试、go vet、
  构建和模块校验。Staticcheck、含测试入口的 deadcode、Go 1.27 只读 modernize
  分析通过。
- 新增或扩展行为覆盖：混合换行与原文摘要、XML 同行未知片段、物理行限额、
  未初始化输入、声明与证据原子性、共享 Parser 的目录/拓扑隔离、IPv4 极值、
  反向范围拒绝、映射 IPv6 和值复制隔离。
- 既有来源所有权 fuzz 完成 706,707 次执行；地址集合逐点 oracle fuzz 完成
  1,976,696 次执行，均无失败。

所有真实配置和服务目录均留在原位置，仓库只保存合成测试和汇总结果。
22 份图依然是不完整图：本轮没有扩大业务语法覆盖，也没有消除原有 unknown。
后续能力缺口仍见[配置回放报告](2026-11-07-parser-corpus.md)。

## 本地性能观察

使用现有合成基准，同机执行重构前后各三次，每项 100ms；下表为中位数。
这些短测量用于发现明显退化，不作为统计显著的性能承诺。

| 场景 | 时间变化 | 每次分配字节：前 → 后 |
| --- | ---: | ---: |
| Hillstone 1,000 条规则 | -3.3% | 31,627,204 → 28,569,785 |
| XML 1,000 个地址 | -3.9% | 15,338,535 → 13,882,498 |
| 多行语句扫描 | -8.0% | 105,793 → 68,600 |
| 单条长字符串扫描 | +9.9% | 3,243,270 → 3,276,027 |

长字符串扫描现在包含依赖创建索引时计算摘要的工作；原先摘要在 NewBuilder 时计算，
扫描基准不包含该步骤。完整解析使用缓存摘要，避免重复计算。
原始数据：[重构前](benchmarks/2026-11-07-parser-foundation/before.txt)、
[重构后](benchmarks/2026-11-07-parser-foundation/after.txt)。复现命令：

```sh
GOWORK=off GOFLAGS=-mod=readonly go test ./benchmarks -run '^$' \
  -bench '^(BenchmarkScan|BenchmarkParseXML|BenchmarkParse)/' \
  -benchtime=100ms -count=3 -benchmem
```
