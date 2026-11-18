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
