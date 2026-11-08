# Hillstone / Palo Alto 配置解析演进

本轮对本地 2026-10-14 备份进行只读回放。仓库只保留合成测试、实现和汇总数字；
实际配置、设备名称、地址、凭据及服务目录均未复制进仓库。结果是离线解析证据，
不是设备下发或完整厂商功能验收。

## 接入与结果

采集清单为 schema 2：Hillstone 有 20 份可用文件；Palo Alto 有 2 份可用文件，
另有 1 条采集失败记录。22 份文件的长度和 SHA-256 均通过校验。

| 项目 | Hillstone | Palo Alto |
| --- | ---: | ---: |
| 本轮开始时可生成图的文件 | 14 / 20 | 2 / 2 |
| 本轮完成后可生成图的文件 | 20 / 20 | 2 / 2 |
| 规则记录 | 4,009 | 312（含 4 条原生默认规则） |
| 接口 | 766 | 224 |
| 区域 | 198 | 20 |
| 直连与静态路由记录 | 250 | 372 |
| 时间表 | 41 | 10 |
| 动态 NAT | 18 | 68 |

Hillstone 原有 6 个致命重复时间表错误来自 QoS 中的 `schedule` 引用被当成全局声明。
按命令上下文隔离后，这些错误消失。进一步修复空子块、无缩进上下文，以及 SCVPN
导出中的非结构缩进，最终没有 `unclosed-block` 或 `unexpected-exit` 诊断。
Palo Alto 原有的接口、区域悬空引用已消除。

所有图仍为不完整：清单中的 `backed_up` 只证明采集任务成功，不能证明配置完整性；
同时仍有无法表达的原生命令和条件。生成图成功不表示所有策略已获得精确查询或变更证明。

## 业务抽象与实现

- `cmd/firemon/backup.go` 负责采集清单边界、目录约束和完整性校验；`parse.go` 负责
  解析入口与脱敏报告。`os.Root` 将读取约束在指定目录内。异机绝对路径只在
  vendor、host、name 与 `plan.json` 唯一匹配且文件名一致时重定位；读取后仍校验摘要。
  未匹配路径和越界符号链接不会被读取。每份失败独立报告，批次继续处理。
- Hillstone 扫描器按原生命令上下文组织块。未知嵌套内容保留 pending，不允许其内部的
  `rule`、`interface`、`schedule` 等同名成员创建全局对象。缩进只提供辅助证据；
  QoS、接口组、隧道的真实成员语法优先。
- Hillstone 的 `Any` 按保留字处理，普通对象名称保留大小写。`src-ip`、`dst-ip`、
  地址范围成为规则拥有的匿名 Address，使用现有精确区间代数；没有设备声明名称。
  规则 ID 与显示名称分开。对象重开和时间表重开由同一份草稿合并。
- PAN 的物理接口、聚合接口、子接口、tunnel、loopback、vlan 共用接口草稿和绑定阶段。
  先完成 zone/VRF 绑定，再生成直连路由和解析静态路由。冲突绑定保留未知。
  IPv6 接口开关和地址开关分别记录；只有两者启用才形成有效直连地址。
  静态路由身份包含 VRF、地址族、名称，避免 IPv4/IPv6 的同名路由覆盖。
- PAN 服务草稿集中拥有协议和源/目的端口。`override no` 不改变选择器；冲突协议、
  自定义会话超时保留未知。HIP/category 的 `any` 和 negate 的 `no` 可识别为中性值；
  非中性值继续保留证据。`application-default` 是尚未解析的应用条件，不是服务对象。

解析器版本为 `hillstone-go-7`、`paloalto-go-6`。没有增加依赖、兼容转发层或数据库读取。
配置草稿与行证据仍通过 Builder 事务一起提交，已保存快照仍直接恢复图而不重新解析。

## Ruby 服务目录

按用户提供的线索，核对了 algosec-rb 中已有的规范化服务目录：106 个服务、135 个服务项。
原始采集摘要、规范化文件摘要与来源 sidecar 一致；规范化文件 SHA-256 为：

`b7166f2bfdb9e2c517a8cd64986f41ec84e647013f8872f88d9bc5c6073ccbb7`

Go 通过 `hillstone.ReadServices` 显式读取规范化格式，并通过 `Parser.Services` 注入。
CLI 的 `--services` 会将目录摘要写入报告。定义顺序为配置内服务/服务组优先，
外部目录补齐缺失项。超量、无效协议、截断名称、反向端口范围和非传输协议上的受限端口
均拒绝。ICMP 单独映射 type/code；PING 精确保留 type 8/code 0。

完整回放中的缺失服务引用由 555 次降为 6 次，剩余为 2 种名称，目录中没有对应定义，
也不是单纯大小写差异。未根据常见端口猜测。早期回放的 529→4 发生在修复 SCVPN
作用域之前；这里使用恢复全部配置之后的最终统计。

该目录是一次实际采集的服务表，不包含足以证明所有设备型号/版本一致的资料。
因此它是调用者显式选择的参考目录，没有成为 Go 内置的通用 Hillstone 默认表。
目录中的截断名称也没有补造。保存在图中的已解析服务项可以随快照独立恢复。

## 剩余能力及改进顺序

1. **VRF 默认值与策略作用域。** Hillstone 仍有 80 个路由接口绑定诊断、17 个下一跳
   无法解析诊断。前者已确认是显式 `trust-vr` 路由与未声明 VRF 的接口之间的作用域差异。
   厂商资料定义三层区域的默认 VRF 为 `trust-vr`；下一步应统一区域、接口、规则、NAT
   与渲染器的默认作用域契约，区分全局策略和 VRF 策略，再验证读取、查询、迁移、渲染
   往返一致性。不能仅在路由绑定处绕过 VRF 检查，也不能将默认值按样本名称补入。
2. **服务目录适用性。** 为目录增加型号、软件版本、采集命令与来源绑定，再按设备显式
   选择；补齐剩余 2 种服务需要定义证据。保留当前严格加载入口，无须新增服务查询数据库。
3. **应用与策略附加条件。** Hillstone 的聚合规则、host/domain-book、服务规则、VLAN
   约束和安全配置文件，以及 PAN 的应用默认服务、否定选择器、HIP、URL 类别、安全配置
   文件，仍应使用有类型的条件或效果对象逐项建模。先验证声明、查询、拆分和迁移语义，
   再允许消除 unknown；不能只为降低未解析行数而忽略这些字段。
4. **拓扑与 NAT 证据。** PAN 仍有 10 个缺少目的网段的路由草稿、48 个未解析下一跳、
   10 个显式接口 NAT 地址选择诊断；Hillstone 有 2 个出口接口地址分配缺口。
   需要结合原生路径和接口有效地址来完善，不从接口前缀中任取主机地址。
5. **时间表与运行条件。** 无可靠设备时区、采集时钟或动态对象资料时，继续保持未知。
   时间表能形成结构记录不等于已建立所有时刻上的策略等价证明。

这些问题均有诊断保留，本轮未宣称完整厂商等价。

## 参考与验证

业务参照：Perl `Firewall/Config/Parser/Hillstone.pm` 的 `parseInterface`、`parseZone`、
`parseService`、`parseSchedule`、`parseRoute`、`parseNat`、`parseRule`，以及
`Firewall/Config/Dao/PredefinedService/Hillstone.pm`。Ruby 参照
`lib/algosec/config/predefined_services.rb`、`lib/algosec/vendors/hillstone/predefined_services.rb`、
`lib/algosec/vendors/hillstone/parser/document.rb` 和服务项规范化实现。
这里保留源/目的端口配对、原生命名和执行顺序；没有复制旧实现中宽泛的 Any 正则、
丢失未知条件或掩盖错误的行为。

厂商资料：[Hillstone 服务目录](https://www.hillstonenet.com/support/5.0/en/SG/obj_servbook_intro.html)、
[Hillstone CLI 5.5R5](https://kb.hillstonenet.com/en/wp-content/uploads/2017/11/StoneOS_CLI_User_Guide_Complete_Book_5.5R5-1.pdf)、
[PAN 三层接口及 IPv6 开关](https://docs.paloaltonetworks.com/ngfw/networking/configure-interfaces/layer-3-interfaces/configure-layer-3-interfaces)、
[PAN 自定义服务](https://docs.paloaltonetworks.com/network-security/security-policy/administration/objects/services/create-a-custom-service-pm)。

合成回归覆盖：QoS/未知作用域不泄漏、空嵌套块、隧道成员缩进、地址区间与首次匹配、
服务目录优先级和 ICMP 精度、图不可变性与无目录快照恢复、接口绑定、IPv6 双开关、
双地址族路由、XML/set 路由查询一致性、协议冲突、非中性条件、目录路径约束、
清单迁移与摘要、脱敏和取消。七厂商原有冻结图摘要继续通过，无须修改期望摘要。

最终本地验证通过：根模块 `go test -count=1 ./...`、`go test -race -count=1 ./...`、
`go vet ./...`、`go build ./...`、`go mod verify`；配套适配器使用当前核心的临时
Go workspace 通过相同检查。Staticcheck、含测试入口的 deadcode 和 Go 1.27
modernize 只读分析也通过。未改动 go.mod/go.sum，没有发布或真实设备操作。

最终回放中仍有 Hillstone 25,144、PAN 7,555 条 pending 证据。报告保留逐样本
诊断代码与有限行号，不输出原始诊断消息或设备对象名称。Hillstone 批次退出 0；
PAN 批次因那条采集失败记录退出 1，2 份已有文件均解析成功。
