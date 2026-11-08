# 核心算法优化与业务边界

本轮修改位于 `refactor/idiomatic-go` 工作树，继续保留此前改动。
以修改前的完整本地源码快照为基线，先剖析、再修改、串行测量。
没有提交、推送、发布或执行设备操作。

## 领域实现

| 模块 | 实际修改 | 保留的业务条件 |
| --- | --- | --- |
| `flow` | 增加 `Traffic.Clip`，直接与单个区域求交；`AddressSet.All` 按值遍历规范化区间 | 源、目的、协议、源目端口和 ICMP 维度保持关联；IPv4/IPv6 不混淆；结果不可变 |
| `policy` | 共享不可变通配地址集；不为未命中组合构造临时集合；用标量访问器筛选规则、zone 与 Fortinet VIP | 每个组合仍计费；先解析未知条件，再计算流量；原生顺序、有效期及首条命中语义不变 |
| `analysis` | 同一个防火墙图和查询上下文内惰性复用有效分区；去掉 Effective 路径重复 Record 和证据 Spans 二次复制 | 每份风险标准独立评估、计费与持有证据；跨时间、跨图和后续调用不复用判定 |
| 复制预算 | `Rule.DeclarationSize()` 在复制前提供非分配计数；策略查询、风险分析和收敛累计限制实际复制 | 巨大成员列表和来源跨度不能绕过预算；超限丢弃部分结果；不因未访问规则而拒绝已完整命中的查询 |
| `inventory` | `Cache.Index(ctx, revision, fw)` 使用已加载的不可变图；查询批次持有该 revision 的图及索引 | 加载从快照恢复；不重解析、不查数据库；传入图不能污染来源缓存 |
| `operations` | 修复小缓存导致重复加载、缺少接口遗漏声明、显式 Real/Translated 视角被忽略 | 声明与报文路径分开；缺少入口、zone 或 NAT 证明时只给条件性证据，不授权设计 |

`Record` 仍是显式取得可变副本的接口。算法只需要 ID、VIP、停用状态、
未知标记或时区时，使用已有领域访问器；需要遍历时返回值迭代器。
没有增加通用缓存框架、全局判定缓存、对象池或过渡兼容接口。

策略查询保留原来的规则访问计数，另用同等 `MaxVisits` 额度约束累计复制。
风险与收敛将实际复制成本记入各自的累计工作预算。大型调用应由服务侧明确
设置额度，不能以缓存命中、未知结果或提前返回来跳过计费。

## Perl 对照

| 原实现与调用方 | 采用的业务职责 | Go 中保留的差异 |
| --- | --- | --- |
| `Firewall/Policy/Searcher.pm:1285` `searchSrc`、`:1303` `searchDst`、`:1323` `searchSrv` | 分别归一化源、目的、服务集合并比较规则 | Go 使用完整流量元组、首条有效命中和明确通配符；协议 0 仍是协议 0 |
| `Firewall/Config/Audit.pm:67` 准备规则集合，`:95` `_audit` 逐项评估标准；`FirewallManager/RuleMan.pm:32` 调用 | 实际策略范围准备一次，多份审计标准独立应用 | 有效分区按 graph/context 隔离，保留有效期、未知值和独立证据；不复制旧数据库访问方式 |
| `Firewall/Config/Ruleopti.pm:31` 成对比较，`:45–63` 分类包含/合并；`FirewallManager/RuleMan.pm:120` 调用 | 按安全域、源目与服务关系寻找收敛候选 | 继续检查精确联合与完整策略保持证明，不能只凭两个维度相等批准合并 |

上述引用对应本地 `/Users/crate/Works/perl/algosec/backend/lib/` 源码。
本轮读取了实际实现和调用方，没有把历史维度比较当作 Go 精确报文证明的替代。

## 测量

环境为 Go 1.27.1、darwin/arm64、Apple M5、GOMAXPROCS=10。
每项 6 次、每次 300 ms，解析和夹具构造不计时；没有同时运行其他基准。
新旧使用相同基准源，`benchstat` 的下列差异均为 `p=0.002`。
风险批查明确设置 `MaxVisits=1000000`，新旧额度一致。

| 合成负载 | 修改前 | 修改后 | 耗时变化 | 分配次数变化 |
| --- | ---: | ---: | ---: | ---: |
| Huawei 策略查询，1000 规则，命中最后一条 | 1.033 ms | 0.529 ms | -48.8% | 21033 → 8033 |
| Huawei NAT 查询，1000 规则 | 1.148 ms | 0.628 ms | -45.3% | 28040 → 15040 |
| Huawei 完整报文路径，1000 规则 | 3.140 ms | 1.695 ms | -46.0% | 约 70250 → 31230 |
| Fortinet 策略查询，1000 规则 | 1.098 ms | 0.885 ms | -19.4% | 约 27070 → 18070 |
| 稀疏匹配，16 源 × 16 目的 × 4 服务 | 121.47 µs | 52.77 µs | -56.6% | 2134 → 35 |
| 风险批查，100 规则 × 4 上下文 × 30 标准 | 17.10 ms | 3.74 ms | -78.1% | 395980 → 76370 |

稀疏匹配每次分配字节从 279.81 KiB 降为 7.18 KiB；最大风险批查从
35.57 MiB 降为 14.23 MiB。前者主要消除了未命中时的临时集合和区间副本，
后者同时受益于查询优化、分区复用和证据复制减少，不能全部归因于缓存。

重复加载使用计数存储验证：两份快照的同批次关联查询，在不保留图时原来
加载 10 次，在单条目 LRU 下加载 8 次；两种情况现在都只加载 2 次。
这是 I/O 次数证明，不作为真实设备延迟测量。

可复现命令：

```sh
go test -run '^$' -bench 'Benchmark(Query|NAT|Packet)$/huawei/rules=1000$' -benchmem -benchtime=300ms -count=6 ./benchmarks
go test -run '^$' -bench 'BenchmarkQuery$/fortinet/rules=1000$' -benchmem -benchtime=300ms -count=6 ./benchmarks
go test -run '^$' -bench '^Benchmark(Match|RiskBatch)$' -benchmem -benchtime=300ms -count=6 ./benchmarks
benchstat docs/benchmarks/2026-11-07-core/before.txt docs/benchmarks/2026-11-07-core/after.txt
```

原始测量报告保存在 [before.txt](benchmarks/2026-11-07-core/before.txt) 和
[after.txt](benchmarks/2026-11-07-core/after.txt)。完整源码基线和剖析文件保存在本机临时目录
`/var/folders/1w/b2h7_3sn6733tshd4w6_vvnc0000gn/T/firemon-algorithms-20261107-b25flrn7/`。
这组数据说明合成负载下的本地变化，不代表真实配置、固件或设备的完整表现。

## 验证与后续改进

回归已观察到修改前失败、修改后通过：大型单条声明复制、重复风险证据累计
超预算、小缓存重复恢复快照、缺少接口时的声明遗漏，以及显式 NAT 视角混淆。
`Clip` 加入独立的 128 个报文枚举 oracle；另外覆盖无部分结果、无效区域、
混合地址族、迭代提前停止、输出所有权和精确复制额度。

最终代码的本地验证全部通过：

- 根模块 `go test -race -count=1 ./...`、`go vet ./...`、`go build ./...`、
  `staticcheck ./...`、格式及 `git diff --check`。
- `FuzzTrafficAgainstPacketOracle` 运行 15 秒、4 个 worker，457161 次执行通过；
  其中包含新的 Clip 运算和现有联合、差集、求交、相等性 oracle。
- 独立的 `adapter/netconnector` 模块经临时外部 Go workspace 接入当前核心，
  完整 race 测试及 vet 通过。没有修改其发布依赖或把 workspace 测试称为发布验证。
- 分别核对 `flow`、图与快照、七厂商解析器、`policy`、`plan`、`analysis`、
  `inventory`、`operations`、`deploy` 和 CLI 的现有可执行覆盖。全量成功包含
  策略设计/聚合/迁移的拒绝反例，不表示所有原生组合都可以生成。

| 优先级 | 下一步 | 验收条件 |
| --- | --- | --- |
| P1 | 隔离 SRX DNAT 端口迁移被原生等价检查拒绝的差异 | 生成配置独立回读后，选定流量与外部流量均通过原生效果证明；不放松现有拒绝条件 |
| P1 | 扩充脱敏的七厂商原生语法及有效期边界夹具 | 对照 Perl 方法和原生证据；新语法在取得定义前保持 pending/unknown；不提交生产备份 |
| P2 | 测量多区域报文中的路由表准备成本 | 若排序/前缀转换仍占热点，只在当前图及 VRF 内复用准备结果；保持 LPM、歧义、PBR 未知和逻辑计费 |
| P2 | 测量收敛候选与证明之间重复的声明匹配 | 只复用当前候选、图和上下文的匹配结果；合并后图、全局保持及独立回读仍完整执行 |
| P2 | 增加独立的 wire/real/translated 报文风险入口 | 当前风险明确为 native-policy；新入口组合原生报文分区并保留动态分配与未知路由，不能靠改字段名转换坐标 |

配置解析、设计/拆分/聚合、迁移和下发的已有行为继续由全量测试覆盖。
本轮没有扩展厂商范围、声称完整固件语法覆盖、重跑生产备份解析或执行真实下发。
