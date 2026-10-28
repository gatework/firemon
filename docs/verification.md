# Implementation verification

This records the requirement audit, independent review and verification of the approved [specification](spec.md) and nine-task [plan](plans/go-firewall.md). The final core correction is [`49b866f`](https://github.com/gatework/firemon/commit/49b866f6aa3cac32dbcfa355fad7450de15b4bd7). The supported vendor boundary is Palo Alto, SRX, Huawei, Hillstone, Fortinet, Netscreen and ASA. Capability-based implementation does not imply complete native grammar or firmware parity.

## Requirement audit

| Plan task | Implemented contract and executable evidence | Current result |
| --- | --- | --- |
| 1. Exact traffic | `flow` uses IPv4/IPv6 intervals and paired multidimensional boxes. Tests cover maximum IPv6, mixed families, protocol zero, cross-pair preservation, budget failure and an independent byte-universe fuzz oracle. | Local race/vet passed; algebra measurements recorded |
| 2. Immutable graph | Typed tables and two-pass sealing, shared reference identity, copied containers, route longest-prefix/VRF/ambiguity, group cycles and distinct static/dynamic NAT catalogs. `firewall_test.go`, `inline_test.go`, `snapshot/codec_test.go`. | Local race/vet passed; semantic format 8 |
| 3. Cursor and stages | Pending skip/rewind, exact consumed spans, transactional draft/evidence rollback, dependency validation, native opaque blocks and bounded XML fragments. `config/cursor_test.go`, `config/xml_test.go`. | Local race/vet passed |
| 4. Persistence and projection | Snapshot restoration without parsing, corruption/version rejection, CAS, separate-process reservation, incomplete-live invalidation, archive and outbox retry. `snapshot`, `inventory`, `projection` tests. | Local race/vet passed |
| 5. Hillstone vertical slice | Native scoped graph/query/NAT/plan/rendering, bounded live Perl oracle comparison and offline CLI snapshot reload. `vendors/hillstone`, `policy/hillstone_nat_test.go`, `plan/oracle_test.go`, `cmd/firemon`. | Local race/vet passed; four Perl oracle cases retained |
| 6. PAN and ASA | PAN set/XML scopes, explicit interface host allocation, per-virtual-router static routes and original-address/post-DNAT-zone evaluation; ASA native sections, real-address/service ACL paths and inverse mappings; independent native readback. `vendors/paloalto`, `vendors/asa`, packet tests. | Local race/vet passed, including final review regressions |
| 7. Online orchestration | Exact authorization, operation lock and durable reservation, command/save receipts, independent running/saved readback, recovery without replay and five actual subprocess exit boundaries. Optional adapter has native ASA/Hillstone/PAN transcript tests. | Root and current-core adapter race/vet passed; no device validation |
| 8. Lifecycle | Exact optimizer, convergence with whole-plan proof, explicit-zone translation, declared/effective risk and revision-bound contiguous usage observations. `analysis` tests cover deny/cross-pair preservation and missing/reset counters. | Local race/vet passed |
| 9. Remaining vendors and delivery | SRX/Netscreen/Fortinet/Huawei staged native slices, independent readback, CLI reload, selected parser fuzz runs, 75-case benchmark matrix and independent whole-branch review. | Local checks and review fixes passed; publication evidence recorded in status |

Unrecognized or unmodeled input remains pending, unknown or an explicit error. The [capability matrix](status.md) lists grammar, firmware, NAT, schedule and deployment limits. Native fixtures establish only the behavior they exercise. Huawei follows the local Ruby/Perl references, with primary Huawei documentation corroborating the DNAT-before-policy/SNAT-after-policy view. Its original command-reference URL still redirected to a portal shell; broader native syntax, reverse mappings and version behavior remain unverified. See the [native evidence](native-semantics.md).

## Verification commands and boundaries

The final core, including both review corrections, passed the following on Go 1.27.1, macOS arm64:

```sh
GOWORK=off GOPROXY=off go test -count=1 -race ./...
GOWORK=off GOPROXY=off go vet ./...
git diff --check
```

There were 19 successful root packages. The adapter also passed race tests and vet using an isolated workspace containing the current root and the nested adapter. That workspace check is distinct from testing the adapter's pinned published dependency; the corrected-core pin and its separate-module verification are recorded in [status](status.md).

Selected parser fuzz evidence accumulated during this implementation: ScreenOS 165,040 executions; Fortinet 725,187 executions over 20 seconds; Huawei 1,038,728 executions over 45 seconds. No failure was reported in those runs. Ordinary `go test` continues to run their seed corpora. See [benchmarks](benchmarks.md) for raw measurement artifacts, workload sizes and allocation limits.

The root has no external module dependency and public CI does not access the adapter's private connector dependency. No real firewall, SQL database, release package, tag or deployment was validated or created. Local tests, GitHub publication, CI, optional adapter consumers and real devices are separate evidence boundaries.

## Independent review and correction

One fresh reviewer inspected the whole implementation range `d187915..fdcec7b` against the specification, plan and review focus, and independently ran the root tests and vet. The first reviewer dispatch failed before reviewing because of workspace credit exhaustion; its replacement completed the review. Two Important findings were accepted and corrected in one author fix pass. There were no Critical findings or deferred Minor findings, and no second review was substituted for regression evidence.

| Finding | Reproduction and correction evidence |
| --- | --- |
| PAN interface SNAT widened a selected address-object prefix or included secondary interface addresses. | `TestInterfaceNATRetainsSelectedHostThroughSnapshot` and `TestInterfaceNATRejectsUnassignedOrAmbiguousSelection` failed before the fix and passed afterward. Numeric, prefix and object selectors now retain one configured host through `QueryNAT`, `QueryPacket` and snapshot restoration. XML and invalid sealed-graph cases are covered too. |
| PAN static routes with the same native name merged across virtual routers. | `TestStaticRoutesKeepVirtualRouterNamespaceThroughSnapshot` failed before the fix and passed afterward. Same-named defaults retain independent next hops, VRFs and interface identity, including overlapping connected networks and snapshot restoration. |

`TestSelectedInterfaceAddressMustBelongToItsAllocationInterface` and `TestGobRejectsVersionSevenWithoutInterfaceSelectionSemantics` also failed before their corresponding validation/version corrections. The complete root race suite and vet then passed. Older semantic snapshots are rejected explicitly; original captures must be reimported into a new store.

## Recorded implementation decisions

The following preserves all execution-ledger rulings and their consequences, including superseded sequencing decisions:

1. Initially retain uncommitted work until commit authorization. The user's subsequent instruction to commit/push and create public `gatework/firemon` superseded that restriction; the Ruby remote remains untouched.
2. Keep `StaticNAT` and `DynamicNAT` as independent concrete catalogs, as the user required. Consumers must preserve native interleaving without a unified NAT domain object.
3. Leave unspecified Hillstone SNAT allocation unknown. Supplying an unverified default could falsely prove a mapping; the cost of conservatism is rejection of otherwise valid native configurations.
4. Use standard-library `flag` for the offline CLI. A larger future command tree may need a framework; the current commands do not need configuration layering.
5. Begin PAN/ASA work while the Hillstone extended slice was still open, because their NAT stages needed a common executable core. This changed sequencing and did not waive either task's tests.
6. Obtain an early independent core safety review before online orchestration. That review did not substitute for the final whole-branch review.
7. Require explicit StoneOS 5.5R8 version evidence for mixed regular NAT chains. Unverified versions return `ErrNAT`; broader acceptance requires native version/device evidence.
8. Qualify Hillstone NAT IDs by VRF and SNAT/DNAT/BNAT chain because native numeric IDs can repeat. Consumers use qualified typed IDs; `Object.Name` retains the native name.
9. Begin injected deployment orchestration while broader native grammars remained open. This established crash/ownership behavior with synthetic sessions, not device interoperability.
10. Take the durable journal operation lock before reservation/capture. A crashed process releases its OS lock, never the persisted device reservation; uncertain operations may require explicit recovery.
11. Require fresh independent running and saved-state evidence during uncertain recovery. A matching running configuration or prompt alone cannot prove persistence; insufficient evidence stays pending without write replay.
12. Begin lifecycle algorithms once immutable graph/query/proof contracts were executable. This changed sequencing, not the required adapter/vendor verification.
13. Normalize Junos readback rule positions independently within each exact zone pair, retaining its global default. Independent pair-block ordering may differ; changing order inside a pair still fails proof. Unmodeled interface/instance precedence remains unsupported.
14. Reject append candidates proven to change effective ownership outside the request before viable-combination counting. Preserve earlier-rule shadowing and the candidate-visit limit; dimension-only pruning could lose the cheapest valid plan. Full target/outside/native proofs remain mandatory.
15. Retain the approved capability-based contract where the reviewer declined full native grammar/version parity. Unsupported syntax remains unknown/error; broader configurations may be rejected until native evidence is added.
16. Do not infer device acceptance or persistence from transcript tests, or comprehensive Huawei command accuracy from policy-view documentation. The reviewer declined these claims; live compatibility remains unverified and requires device evidence.
17. Treat fsync/rename, injected failures and five subprocess-exit tests as evidence of the tested crash boundaries. The reviewer declined physical power-loss/storage guarantees; actual controller/filesystem durability needs separate validation.
18. Report serial synthetic measurements without a production capacity/SLA claim, which the reviewer declined. The 100-rule create case still allocates about 625 MiB cumulatively; large or concurrent workloads require separate capacity work.
19. Accept a missing PAN interface selector only when one established interface address exists. Normalized graph order cannot prove the native primary IP; otherwise valid multi-address configurations without an explicit selector stay incomplete.
20. Reject semantic snapshot formats before 8 rather than restore potentially unsafe old PAN graphs. Loading never reparses; callers must reimport original captures, at the cost of invalidating older stored graphs.

The two Important findings are fixed. No minor review findings were deferred. These decisions and the explicit capability limits are part of the delivered contract, not claims of untested parity.
