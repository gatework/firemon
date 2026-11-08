# Changelog

## Go v0.2.0 - 2026-11-08

Requires Go 1.27 or newer. Public API changes are intentional during development;
see the [migration guide](docs/refactoring.md). The connector adapter is released
separately as `adapter/netconnector/v0.2.0`.

- Reduce policy/NAT matching allocations and reuse effective partitions within
  each risk-analysis context. Synthetic benchmarks report about 49% lower Huawei
  policy-query time and 78% lower batch-risk time; see the
  [measurements and verification](docs/2026-11-07-core-algorithms.md).
- Bound cumulative nested declaration and evidence copies before allocation,
  including unknown risk findings, and return no partial result on budget failure.
- Avoid repeated snapshot loads when cache retention is disabled or entries are
  evicted. Keep conditional declarations when interface/zone evidence is missing,
  and honor explicit real/translated views with native forward verification.
- Preserve inline source/destination literals when rendering Palo Alto NAT
  additions, while rejecting inconsistent or unowned inline address records.
- Split scheduled NAT aliases before discovery for real/translated queries with
  pinned topology. Preserve exact active windows, unknown calendars and copy limits.

- Add simple source/destination/service requests, row-local input errors and
  independent `Searcher.Query`; remove the mixed `BatchDesigner.Query` facade.
- Cache immutable graphs and address indexes with bounded LRU and merged loads.
  Discover both endpoints and reversible static NAT aliases while preserving
  conditional ingress, scopes, time windows and incomplete evidence.
- Separate native declarations from first-match hits, restore exact original
  policy traffic through NAT, and partition finite policy/NAT schedules exactly.
  Finite business designs require explicit services and capture-bound clock evidence.
- Reuse exact policy pullbacks in migration ownership proofs; support reversible
  service-port aliases and verified Huawei DNAT-port migration. Unproved native
  inverses and SRX DNAT-port migration remain refused.

- Isolate migration compiler/renderer ownership and reject cancellation after
  rendering. Charge nested declarations before graph copies and enforce input
  region limits consistently across public queries.
- Use ordered interval scans for address subtraction, IPv6 intersection and
  containment. Remove redundant Huawei/ScreenOS transaction forwarding methods.
- Add caller contexts to `operations.DecodeBatchRequest` and `DecodeTopology`;
  bounded JSON reads stop between reads on cancellation or repeated no progress.
- Separate raw response history from save-result interpretation. Accept error
  words in verified prompts and Fortinet configuration values while retaining
  rejection evidence and requiring a complete, unambiguous automatic-save setting.

- Integrate published `gatework/parser v0.1.0` for immutable text indexing and
  `gatework/set v0.1.0` for IPv4 interval sets. Separate Hillstone document,
  catalog and topology responsibilities while preserving parsed graphs.
  Remove duplicate line/cursor APIs and transaction reader state. XML retains
  fragment evidence and now enforces its physical line budget exactly.

- Add bounded `firemon parse` inspection and collector backup replay with path,
  size and checksum validation, anonymous reports and explicit service catalogs.
- Evolve Hillstone block scopes, inline policy selectors, object headers and
  schedule reopenings. Load observed algosec-rb service definitions without
  embedding a device catalog or broadening ICMP type/code matches.
- Unify PAN logical interface and route parsing for set/XML, bind topology before
  routes, separate IPv4/IPv6 route identity, and retain IPv6 activation and service
  protocol constraints. Unsupported application-default semantics remain unknown.
  See the [offline corpus report](docs/2026-11-07-parser-corpus.md).
- Rename `analysis.RequestOptimizer` to `analysis.Optimizer` and
  `analysis.PolicyMigrator` to `analysis.Migrator`, without compatibility aliases.
- Accept only `paloalto`, `srx`, `huawei`, `hillstone`, `fortinet`, `netscreen`
  and `asa` at the vendor registry and connector adapter boundaries. The adapter
  maps canonical names to connector profiles internally.
- Remove unreachable helpers and forwarding wrappers; share bounded, strict JSON
  I/O and native schedule preparation. Shorten internal names and use standard
  library comparison and typed error inspection.
- Separate declared object/policy names from internal IDs. Remove name-to-ID
  fallbacks in command rendering, exclude unnamed values from named-object reuse,
  and reject a PAN insertion whose existing ordering anchor has no name.
- Check rule collisions using vendor policy identity: retain SRX zone pairs and
  separate numbered policies/ASA ACL entries from their display labels.
- Preserve snapshot format 10, reconstruction format 2 and approval format 4,
  including existing JSON output, unknown evidence, exact traffic proofs and
  durable deployment recovery. See the [module audit](docs/2026-11-07-go-cleanup.md).

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
