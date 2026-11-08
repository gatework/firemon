# Changelog

## Unreleased — Go implementation

- Require Go 1.27 and concentrate target provenance and native declaration
  ownership in private business modules. Preserve command, approval and snapshot
  formats; add bounded service-term expansion and manifest persistence, explicit
  completion facts, evidence retention after cancellation and validated NAT time
  identities. See [migration and verification](docs/2026-11-07-go127-verification.md).
- Give the offline CLI consistent help, checked output, cancelable input and
  exit codes 0/1/2/130/143. Scripts can distinguish invalid input, execution
  failures and SIGINT/SIGTERM; successful JSON output remains compatible.

- Share candidate discovery, cost ordering and bounded attempts between access
  and policy-batch planning while preserving their proof, refusal and digest
  contracts. Migrate the optional adapter to go-net-connector v0.2.0 and
  go-expect v0.4.0, retaining failed capture evidence and configuration isolation.
  CI covers the core, the versioned adapter and the current-core pairing on Go
  1.27.0 and 1.27.x. See [integration verification](docs/integration-verification.md).

- Add Perl-grounded business request batches with independent input dispositions, frozen topology/revisions, exact whole-device policy/NAT proofs, 20 native NAT creation forms, four-vendor finite schedules with verified capture clocks, native usage evidence and offline lifecycle reports/plans. Persist explicitly selected device plans for exact reconstruction and no-write recovery through the existing deployment engine. See [business contracts and verification](docs/business-lifecycle.md).

- Rewrite seven-vendor parser construction around Content, one typed ordered Builder and explicit phases. Validate identities before claiming source, support atomic replacement/rollback, remove duplicate accepted graph copies, and cache immutable intermediate graphs. Preserve native semantics, business Parse APIs and snapshot format 9; low-level Cursor/Session/Stage APIs are replaced. See [migration and evidence](docs/parser-design.md).

- Refine Hillstone parsing around ordered named definitions: retain reopened object members, forward group identity and unsupported block-header evidence; make service/group lookup follow Perl's explicit precedence. Separate native structure/network/object/policy responsibilities and remove an unused full draft copy. The preceding refinement used `hillstone-go-3`, superseded by the rewrite; see [parser design and migration](docs/parser-design.md).
- Replace the Ruby gem skeleton with a Go module and offline CLI.
- Add the immutable firewall graph, separate StaticNAT and DynamicNAT catalogs, staged configuration parsing, exact policy and NAT evaluation, snapshot persistence, change proofs, deployment orchestration and lifecycle analysis.
- Add staged implementations for Hillstone, Palo Alto, ASA, SRX, Netscreen, Fortinet and Huawei with synthetic tests. See [implementation status](docs/status.md) for supported behavior and remaining work; this is not a release or full vendor parity.
- Preserve inline address/service ownership through lifecycle deletion and independent readback.
- Preserve PAN interface NAT host selection and independent static-route names in each virtual router; snapshot semantic format 8 rejects older graphs that could retain widened allocations or merged routes.
- Add the seven-vendor performance matrix and avoid fully proving append candidates that already violate outside-request ownership.
- Complete the nine-task requirement audit and independent whole-branch review, fix both Important findings, and verify the optional adapter against the published corrected core.

## 0.1.0 - 2026-10-17

- 初始化 gem 命名空间、版本常量和基础异常。
- 集成 Ruby 3.3、3.4、4.0 CI、gem 隔离安装验证和 GitHub Release 自动发布。
- 当前版本为项目骨架，尚未实现设备连接或命令操作。
