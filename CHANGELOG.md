# Changelog

## Go v0.1.0 - 2026-11-07

First versioned release of `github.com/gatework/firemon`. Requires Go 1.27 or newer.
The earlier Ruby gem has a separate repository and version history.

- Provide a concrete immutable firewall graph, separate StaticNAT/DynamicNAT,
  staged parsers, snapshot persistence, exact first-match policy and packet
  evaluation for Palo Alto, SRX, Huawei, Hillstone, Fortinet, Netscreen and ASA.
- Add typed absolute/weekly calendars with capture-bound clock evidence, civil
  timezone/DST handling and exact future proof partitions across seven drivers.
- Support exact business-request decomposition/coalescing, scoped complete-object
  and group reuse, bounded candidate selection, declared/effective risk evidence,
  convergence and evidence-bound reclamation.
- Compile atomic policy/NAT migrations with explicit context mappings, selected
  dependency closure, source packet equivalence and target outside preservation.
  Bind source and target snapshots into approval, reconstruction and independent
  native readback. Unsupported selected effects return issues without a plan.
- Provide offline CLI commands with consistent help, checked output, cancellable
  input and exit codes, plus embeddable collection/design/deployment orchestration
  with durable receipts and independent recovery without uncertain write replay.
- Remove package-level native parser conveniences, forwarding APIs and historical
  approval encodings. Current formats are snapshot semantic 10, reconstruction 2
  and approval 4; older formats are rejected instead of silently upgraded.
- Validate 42 directed basic policy migrations, seven recurring schedule targets
  and 16 complete NAT migration/readback cases with synthetic captures. These do
  not establish unrestricted vendor parity or real-device acceptance.

The optional connector adapter is a separate Go module. Native capabilities and
remaining refusals are documented in the [implementation report](docs/2026-11-07-domain-improvements.md),
[schedule matrix](vendors/SCHEDULES.md) and [migration matrix](vendors/MIGRATION.md).
The [performance report](docs/2026-11-07-domain-benchmarks.md) records measured
benefits and costs without claiming production workload performance.

## Ruby 0.1.0 - 2026-10-17 (separate project history)

- 初始化 gem 命名空间、版本常量和基础异常。
- 集成 Ruby 3.3、3.4、4.0 CI、gem 隔离安装验证和 GitHub Release 自动发布。
- 当前版本为项目骨架，尚未实现设备连接或命令操作。
