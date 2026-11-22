# Glossary

| Term | 中文 | Meaning in firemon |
|---|---|---|
| Address object | 地址对象 | Named set of hosts, subnets, ranges or domain names (`firemon.Address`). |
| Address group | 地址组 | Named collection of address objects and groups (`firemon.AddressGroup`). Hillstone expresses it as an address with `member` lines. |
| Service object | 服务 | Named set of protocol and port tuples (`firemon.Service`). |
| Service group | 服务组 | Named collection of services (`firemon.ServiceGroup`). |
| Schedule | 时间表 | Absolute windows and weekly recurrences restricting a rule. |
| Security zone | 安全区域 | Group of interfaces that security rules are written between. |
| Virtual router | 虚拟路由器 | Routing context (Hillstone vrouter, PAN-OS virtual-router). |
| Static route | 静态路由 | Route declared in a virtual router; connected routes come from interface addresses. |
| Security rule | 安全策略 | One ordered entry of the rulebase (`firemon.SecurityRule`). |
| Static NAT | 静态 NAT | One-to-one bidirectional mapping (Hillstone bnatrule, PAN-OS bi-directional static-ip). |
| Source NAT | 源 NAT | Dynamic rule rewriting the source address (snatrule, source-translation). |
| Destination NAT | 目的 NAT | Dynamic rule rewriting the destination address (dnatrule, destination-translation). |
| Space | 流量空间 | Product of source addresses, destination addresses and services (`traffic.Space`). |
| Region | 流量区域 | Union of disjoint spaces (`traffic.Region`). |
| Hit | 命中 | Part of a request a rule decides. |
| Shadowing | 遮蔽 | An earlier rule decides traffic a later rule also matches. |
| Undecidable rule | 不可判定规则 | Rule whose match cannot be computed offline; evaluation reports `Indeterminate`. |
| Intent | 访问意图 | Requested access: sources, destinations, services. |
| Plan | 变更计划 | Vendor-neutral list of changes that realizes an intent. |
| Baseline fingerprint | 基线指纹 | Digest of the configuration a plan was designed against. |
| Redundant rule | 冗余策略 | Rule fully covered by earlier rules with the same action; safe to remove. |
| Shadowed rule | 被遮蔽策略 | Rule fully covered by earlier rules, at least one with the opposite action. |
| Snapshot | 配置快照 | Stored raw text, parsed configuration and fingerprint of one device. |
| Inventory | 防火墙清单 | Set of firewalls a flow is located across. |
| Owner | 归属防火墙 | Firewall with the most specific non-default route to an end of a flow. |
| Crossing | 经过防火墙 | Part of a flow one firewall routes between two of its interfaces. |
| Predefined service book | 预定义服务表 | Built-in service names and ports of a vendor or device (`firemon.ServiceBook`). |
| Protected network | 受保护网段 | Network a firewall protects behind a zone, declared in the inventory. |
| Cluster | 集群 | HA members evaluated and planned once. |
| Excluded traffic | 剔除地址 | Traffic whose ends no firewall owns. |
| Full match / partial match / need new | 完全命中 / 部分命中 / 需要新增 | Report classification of access control on one firewall. |
| Candidate rule | 候选修改策略 | Existing permit rule that could carry the remaining traffic. |
| Domain target / application target | 域名目标 / 应用目标 | Request part matched by domain pattern or application name. |
| Policy route | 策略路由 | Ordered PBR entry that chooses the egress before the routing table (`firemon.PolicyRoute`). |
| NAT intent | NAT 需求 | The translation asked with an access intent: source, destination (published port) or static (`design.NATIntent`). |
| Incomplete rule | 不完整策略 | A rule missing its action, an address or its service; the device ignores it (`SecurityRule.Incomplete`). |
| Live object | 有效引用对象 | An object reachable from a rule, NAT rule, policy route, interface, route or external construct through group membership (`firemon.References`). |
| Finding tier | 收敛层级 | Safe (a change keeping the effective policy exists and is verified) or Review (advice) (`converge.Tier`). |
| Evidence | 证据 | What a convergence finding rests on: the configuration, hit counters, or both (`converge.Evidence`). |
| Fidelity | 翻译保真度 | Exact, approximate (stated difference) or untranslatable (carried over disabled) (`migrate.Fidelity`). |
| Premise | 前提 | Assumption a determinate result rests on, stated in the report: the inferred application, or a user, URL-category, domain or schedule criterion taken not to hold (ADR 0017). |
| Inferred application | 推断应用 | Application family a firewall identifies on the standard ports of the requested service (`firemon.AppGuess`). |
| Flow | 流 | One source item to one destination item of a request, followed through every firewall it crosses (`report.Flow`). |
| Hop | 跳 | One firewall on a flow's way and the rules deciding the flow there (`report.Hop`). |
| Strict reading | 保守判定 | Evaluation without premises: application, user, URL and domain rules stay possible matches (`--strict`). |
| Hand-off | NAT 接力 | Traffic one firewall's NAT translates, evaluated as translated on the next firewall its routes reach (`inventory.Upstream`). |
| Change risk | 变更风险 | Grade of what a planned change opens or bypasses (`design.Risk`): any address, wide network, any service, sensitive service across zones, bypassed isolation deny. |
| Temporary access | 限时开通 | Access that ends at `--until`: a rule validity window or a one-time schedule. |
| Batch ticket | 批量工单 | One row of `--file`, designed on the changes of the rows before it. |
| Device view | 设备视图 | What one firewall does to a request: the existing rules permitting and denying its flows, the rules to add or modify, their risks (`report.DeviceView`). |
| Health score | 健康分 | 100 less stated deductions: rules that never take effect, broad and unlogged permits, unused objects, unreadable configuration (`health.Assess`). |
| Ineffective rule | 不生效策略 | A rule that never decides traffic: redundant, shadowed, disabled, expired, incomplete or never matching. |
| Conditional rule | 按条件匹配的策略 | A rule unresolved only by application, user, URL category or domain criteria, which a query settles under premises (`Rule.Conditional`). |
