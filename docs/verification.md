# Implementation verification

This records the requirement audit, independent review and verification of the approved [specification](spec.md), original [plan](plans/go-firewall.md) and subsequent operations remediation. The original core correction was [`49b866f`](https://github.com/gatework/firemon/commit/49b866f6aa3cac32dbcfa355fad7450de15b4bd7). The supported vendor boundary is Palo Alto, SRX, Huawei, Hillstone, Fortinet, Netscreen and ASA. Capability-based implementation does not imply complete native grammar or firmware parity.

## Operations remediation on 2026-10-29

The user requested execution of the review remediation and uniform cross-vendor
business contracts. The active [remediation plan](plans/2026-10-29-operations-remediation.md)
and [contract notes](contracts.md) extend the original audit below.

| Requirement | Regression and implementation evidence |
| --- | --- |
| Preserve effective NAT during policy design/transfer | `plan/transfer_test.go` reproduced a permit transfer removing Fortinet SNAT while claiming NAT unchanged. `policy/nat_preservation.go` now checks catalog dependencies, activation and effective translation partitions. ScreenOS ownership, future schedule boundaries, unchanged/disjoint changes and cancellation are covered. A disjoint Fortinet transfer independently reparses native readback and rejects a capture that loses the existing SNAT. |
| Typed VIP graph relations | Root and Fortinet tests reproduced ordinary `vip` scope misclassification, incorrect VDOM scope and acceptance of old snapshot semantics. Explicit `NATRef` and `SourceVIP` survive snapshot restoration and independently renamed IDs; ordinary planner addresses cannot reuse VIP selector semantics. Semantic format is now 9. |
| Explicit migration contexts | Fortinet root/security and explicit ASA ingress ACL mappings generate commands that independently reparse and pass `Plan.Verify`. Missing/ambiguous mappings fail. |
| Compound compliance predicates | `analysis/risk_test.go` covers typed per-dimension predicates, All/Any, five relations, unknown propagation, service tuple pairing and retained legacy paired-traffic behavior. |
| Member usage and convergence discovery | Member identity includes rule, role, typed object, revision/digest and nested reference paths. Window/reset/partial evidence stays unknown; coarse positive hits outside the window do not prove in-window use. Deterministic bounded candidate discovery retains whole-rulebase proof and rejected candidates. |
| Uniform native/application selection | `vendors/registry_test.go` exercises all seven native parsers/renderers, aliases and selected Fortinet context. CLI and `operations` reuse this boundary; `policy/semantics.go` composes native policy/NAT/packet behavior. |
| Capture/design/deployment composition | `operations` tests cover stale/reserved preflight, incomplete/fatal parse evidence, identity/raw/firmware/time substitution, cancellation, idempotency and native capture/design/apply/readback/publication with host authorization. |
| Configuration isolation and persistence | Device sessions explicitly implement begin/end. Exact-plan authorization precedes reservation, session creation and native isolation; the journal retains ownership through release failures and recovery. Parser firmware/time substitution was reproduced through Apply reaching device execution; capture identity checks now reject it before writes. Adapter coverage includes owned PAN locks/queued commits, exclusive Junos candidate mode and seven native profiles, with lost-save recovery and no configuration replay. |

The tests above include observed failing-then-passing regressions. Fortinet
manual/revert/unknown save modes originally reached 28 native script steps before
persistence failure; preflight now rejects them before capture or policy writes.

Current-root validation passed on macOS arm64, Go 1.27.1:

```sh
GOWORK=off GOPROXY=off go test -count=1 -race ./...
GOWORK=off GOPROXY=off go vet ./...
```

All 21 root packages passed again after the review corrections, including the
deployment suite (7.553 seconds). The optional adapter passed its complete race
suite and vet against this root through a temporary external Go workspace.
These workspace results are distinct from the published dependency-pin
verification recorded at delivery. Local transcripts are separate from
real-device evidence.

The simplification pass retained behavior tests and shared the policy/NAT
partition comparison. Full `ce-code-review` run
`20261029-085656-c6ae2761` completed all nine Codex review lenses and a separate
validator (`status: complete`, pre-fix verdict `Ready with fixes`). Five candidate
reports reduced to three confirmed findings. The caller applied #1 and the core
capture correction directly; the device worker applied #2/#3 to the adapter.

| Finding | Reproduction and correction |
| --- | --- |
| #1, P1: native configuration isolation preceded authorization | A denied request opened a session and acquired a token; a failed baseline skipped the authorization callback entirely. `TestDeniedAuthorizationCannotAcquireConfigurationLock` failed in both cases, then passed after exact-plan authorization moved before reservation/session creation. Locked fresh-baseline verification remains mandatory. |
| #2, P2: interrupted native capture lost received configuration | Native SRX/Fortinet EOF, rejection and output-limit cases persisted an empty source; generic paths could substitute pager or PAN diff output. Capture extraction now binds accepted steps or bounded failed-attempt bytes to the configuration command. Collector tests retain incomplete evidence and retry without reconnecting. Core deployment EOF/cancel tests also reproduced lost baseline/readback source; bounded local persistence now retains that observation and its reservation, followed by fresh recovery without write replay. |
| #3, P2: unimplemented context labels were accepted | Non-Fortinet tenant labels passed session construction and reached dialing. Seven-vendor context cases now reject unsupported labels before dialing, parsing or publishing. Fortinet still requires an explicit VDOM; other native profiles use empty context for the default domain. |

All three findings are addressed. Both testing gaps were added: independent
native readback of a Fortinet transfer with retained SNAT, and future scheduled
policy changes to NAT ownership. No review finding was rejected or deferred.

The published core is [`af1f854`](https://github.com/gatework/firemon/commit/af1f854b08e6b5117a43d137c91408af3e91d7de);
its [exact-commit CI](https://github.com/gatework/firemon/actions/runs/40801906537)
passed vet and race tests. The adapter's final current-core workspace race suite
passed in 6.526 seconds. After pinning the published core, its independent
`GOWORK=off GOPROXY=off` race suite passed in 7.097 seconds, together with vet and
module verification. `go list -m -json` confirmed the published versions without
replacement. See [delivery status](status.md) for pins and migration requirements.

## Original requirement audit

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


## Domain refactor verification (2026-10-29)

The [module audit and API migration](refactoring.md) and
[implementation plan](plans/2026-10-29-domain-refactor.md) cover this iteration.
Perl/Ruby references and real devices were not modified or executed.

- Core `GOWORK=off GOPROXY=off go test -race ./...` and `go vet ./...` passed.
- Native fixture exported data and semantic digests match e9e9b96 across all
  seven vendors. Three baseline approval digest goldens cover reuse, append and
  create plans. Snapshot format 9, journal records and approval encoding remain.
- New regressions cover resolver cancellation/budgets/nil input, immutable rule
  and NAT views, ordered iteration, transaction ownership and nested rollback,
  native parser limits/context selection, incomplete capture/error preservation,
  durable write failures and cross-process locks, outbox retry and historical CLI
  inspection. Independent packet-oracle fuzzing covers all seven traffic axes.
- Final bounded fuzz runs passed: flow 209,323 executions in 10 seconds; Huawei
  26, Fortinet 17,589 and Netscreen 50,983 executions in five seconds each. The
  low Huawei count reflects the retained complex corpus, not broad grammar
  coverage; none of these runs establishes full native syntax coverage.
- Scoped parser, integration and lifecycle reviews passed. The independent final
  Codex source review approved the integrated core through b47e97e, including
  exact difference/union budget and ordering, bounded cache recharging, candidate
  visibility and digest compatibility. It intentionally did not run tests during
  the serial measurement window. No unresolved correctness findings remain.
- Source evidence too large to retain safely and untrusted session identity are
  rejected before publication. Parser substitution instead retains the original
  trusted bounded capture as incomplete evidence. These are distinct boundaries.
- Speculative cross-vendor features and unsupported native migration remain in
  the existing capability backlog. No new concurrency, runtime dependency,
  database or approval platform was introduced.

Final remote commit, CI and separately pinned adapter evidence are recorded in
[delivery status](status.md). Local tests alone do not establish those results.

## Contract and ownership verification (2026-10-29)

The [contract plan](plans/2026-10-29-contracts.md) is implemented with intentional
Go API changes described in the [migration guide](refactoring.md). The new
`device.Reader` supports standalone collection; shared parsing lives in `config`.
Application dependencies are private and validated by constructors. Lifecycle
evidence, selections, mappings and proof times belong to individual calls.

- Root race tests and vet cover the complete integration, including cursor
  ownership/rollback, shared native parser limits, nil/typed-nil providers,
  independent collection, request reuse/concurrency, route budget/cancellation,
  approval golden digests, snapshots, CLI and process-exit deployment recovery.
- Native fixture exported data and semantic digests match frozen baseline
  `dd15031` across all seven vendors. Snapshot semantic format 9, persisted
  records, CLI fields and approval encoding are unchanged.
- Five-second bounded fuzz runs passed: traffic packet oracle 54,019 executions,
  Fortinet 50,174, Huawei 62 and Netscreen 30,904. The low Huawei count reflects
  the retained complex corpus; these runs do not establish grammar parity.
- Task reviews and the final independent Codex source review passed with no
  unresolved findings. Corrections cover cancellation through route sorting and
  equal-route groups, nil/zero runtime delegation, inventory/projection invalid
  error classification, and reclamation cancellation priority. Targeted failures
  were reproduced before correction and passed afterward.
- The first final-review dispatch failed before reviewing due to a model usage
  limit; its replacement completed the same source review. It ran no tests or
  builds during the controlled benchmark window. The import-grouping cleanup
  afterward changes no runtime behavior.
- The [87-case benchmark comparison](benchmarks.md) records counterbalanced
  serial samples, the final route follow-up and its remaining small-input
  allocation cost. It does not imply every metric improves.

The optional adapter passed current-core workspace race/vet checks before
publication. Its final published pin and standalone checks, SSH readback and exact
GitHub CI are recorded separately in [delivery status](status.md). Source review
did not judge those delivery outcomes or measured speedups. No live firewall,
SQL database, private dependency source publication, new vendor, broader native
syntax, NAT/schedule migration, tag or release is included.

The execution decision was to retain the existing isolated Go worktree and use
the user's authorized SSH delivery directly to `gatework/firemon`, preserving
separate reviewable commits. A separate PR/merge approval cycle was not added;
reversal would require reverting those public commits. The Ruby worktree remains
unchanged.

## Boundary contract verification (2026-10-29)

The [boundary plan](plans/2026-10-29-boundary-contracts.md) adds shared strict native
rendering, request-local usage indexing and persistence input/failure contracts.

- RED regressions demonstrated cancellation misclassification on all seven direct
  and registered renderers, undeclared Preserve renames and hidden renderer errors.
  Additional native regressions cover discarded creation conditions, explicit
  Hillstone any members and unsupported insertion order. Existing independent
  readback, native fixtures, whole-rulebase proofs and approval goldens remain green.
- Rule/member evidence uses a shared evaluator. Existing lifecycle tests and a
  deterministic 250-case discrete coverage oracle check tri-state evidence;
  cancellation during interval sorting, incomplete graph traversal, budget
  exhaustion and unchanged request data are covered.
- Codec tests first reproduced accepted short writes, discarded I/O causes and
  nil-stream panics. Store tests verify invalid inputs create no lock/manifest
  artifacts. Journal tests distinguish corruption from ownership conflicts and
  reject overwriting corrupt records. Existing cross-process reservation, CAS,
  outbox and deployment recovery tests remain green.
- Root `go test -race ./...`, `go vet ./...` and diff checks passed after all three
  batches. Current-core adapter workspace race/vet passed separately (6.194s).
  Final standalone published-pin and remote CI evidence is recorded in delivery
  status after publication.

Serial local benchmarks ran six samples per case on Go 1.27.1, darwin/arm64,
Apple M5, using 100ms measurement windows. The 1000-rule/16-sample workload fell
from 95.541ms to 1.882ms (-98.03%); its allocated bytes increased 11.37% for the
bounded request-local index. The 10-rule/2-sample timing difference was not
statistically significant; bytes increased 24.92%. Raw
[before](benchmarks/2026-10-29-usage-before.txt),
[after](benchmarks/2026-10-29-usage-after.txt) and
[comparison](benchmarks/2026-10-29-usage-comparison.txt) reports retain the complete
matrix. These measurements do not establish real-device or production throughput.

Independent source review of `b506b54..afb43b4` found four Important rendering
contract gaps: native name collisions, missing PAN wildcard selectors, accepted
empty selectors, and inconsistent position-tie ordering. Its orphan-inline finding
was raised from Minor to Important because the specification explicitly permits
that semantic no-op. All five were reproduced with failing regressions and fixed
in one pass; native identity checks also reject newly declared objects that cannot
roundtrip their graph identity. Tests cover named groups, independent PAN parsing,
ScreenOS top ordering, SRX/Huawei/Fortinet anchors and inline declaration omission.
No minor findings were deferred. The reviewer did not certify firmware behavior,
remote CI, adapter pins or benchmarks; those remain separate evidence categories.

The completion audit additionally reproduced malformed persisted head revisions
being reported as caller errors and mismatched manifest digests being accepted.
Current now checks head revision syntax and binds its semantic/source digests to
the loaded immutable graph, returning `snapshot.ErrFormat` on disagreement.

## Computation and scanner contracts (2026-10-29)

The [computation plan](plans/2026-10-29-computation-contracts.md) implements the
approved breaking API cleanup and layered resource model. Delegated public
queries/proofs retain independent limits; each parent algorithm accumulates its
own private work across contexts, rules and candidates.

- Limit defaults and O(1) graph counts/window iteration have ownership and
  exact-boundary tests. Context generation charges windows without cloning full
  schedule records. Incomplete risk rows cannot bypass the visit limit.
- Convergence and migration regressions reproduced private work escaping
  cumulative visit limits; batch planning reproduced the fixed 4,096-region
  fallback ignoring the caller's smaller cap. Configured regions now reach
  union, equality, universe and independent readback proofs.
- Risk preparation has an independent finite-set oracle (256 cases in each
  declared/effective mode), paired service tuple and first-match checks,
  request-local concurrent reuse, aggregate standard regions, per-node cumulative
  budgets and short circuit boundaries. The oracle passed before and after the
  performance change; the aggregate retained-region regression failed first.
- Scanner regressions failed first for canceled empty/long input, nil callbacks,
  invalid stages and cancellation after classification. Current tests cover
  UTF-8 chunk boundaries, split-rune byte fragments, CRLF multiline quotes,
  exact physical spans, cancellation during indexing/XML text and atomic rollback.
  All seven native approval/semantic fixtures remain unchanged.

Root `GOWORK=off GOPROXY=off go test -count=1 -race ./...` and `go vet ./...`
passed on macOS arm64 with Go 1.27.1. The nested adapter passed race/vet using a
separate temporary workspace against the current core (race suite: 12.681 s).
This workspace result does not establish the published dependency pin or remote
CI; delivery evidence is recorded separately in [status](status.md). Synthetic
performance and scanner overhead are reported in [benchmarks](benchmarks.md).

The fresh independent review found two resource-bound gaps. Both were reproduced
before correction: a zero-rule graph with 100 unreferenced addresses produced a
plan despite `MaxVisits: 32`; an oversized transfer allocated about 499 KB per
rejected call, and risk rejection allocations grew with input size. Candidate
export/catalog/visibility/collision work now shares the parent counter, while
constant-time range/region counts reject oversized inputs before copying. The
regressions check rejection without partial plans and bounded rejection
allocation, alongside adequate-budget success. No semantic or evidence-corruption
finding was reported; no minor findings were deferred.

After those review corrections, all 23 root test-bearing packages passed a fresh
uncached race run; root vet and formatting also passed. The adapter's final
current-core workspace race suite passed in 12.068 seconds, followed by vet.
Risk controls were remeasured after the correction, and the planner stress
benchmark was smoke-tested with its now-explicit visit allowance.

## Core policy algorithm reference and evidence (2026-10-29)

The [algorithm plan](plans/2026-10-29-policy-algorithm-contracts.md) separates test
reference, public naming, structural changes and the unknown-action behavior fix.
Perl Searcher supplies reuse/append/create intent and append-member cost; Ruleopti
supplies containment/merge candidate intent; Cleaner supplies observational usage.
Hash iteration, protocol-zero wildcard encoding and independent-axis cross-pair
expansion are not carried into the Go algorithms.

The test-only packet reference in `analysis/packet_oracle_test.go` compares raw
DTO fields directly and independently sorts rule position/ID. Expected outcomes
never call production set algebra, matching or preservation helpers. Its finite
IPv4/IPv6 domain covers addresses, protocol 0/1/6/17, both ports and ICMP type/code.
Query tests check all four result partitions and per-rule ownership/known status.
Plan and lifecycle checks enumerate packets before/after changes, including
cross-pair requests, earlier deny, logging, deterministic cost ties, future
schedule boundaries, whole-batch reclamation and empty declarations. Native
renderer syntax remains covered separately by seven-vendor fixtures.

Controlled mutations to deny classification and request union failed the new
reference tests; restored code passed. Unknown and invalid actions each reproduced
`Known: true` for unknown traffic before correction, in both address families.
The correction makes decision evidence depend on the action as well as matching
and schedule evidence, without changing conservative unknown coverage.

A frozen synthetic v9 gob created at `bc15a8b` still decodes with the original
semantic digest, and CLI query JSON retains its exact keys, field structure and
null empty partitions. Existing vendor/approval fixtures remain unchanged. Shared
algebra tests cover full IPv4/IPv6 endpoints, protocol/port maxima, equality
short-circuit direction, empty sets and budget failure. A 30-second packet-algebra
fuzz run completed 1,290,834 executions without failure.

Local root build, race tests and vet passed; the optional adapter passed build,
race tests and vet through the current-core workspace (race suite: 6.003 seconds).
These are local/offline checks; published dependency and exact-commit CI evidence
is tracked separately in [status](status.md). Benchmarks are recorded in
[the measurement log](benchmarks.md).

Final independent review of `bc15a8b..6ec81b0` found zero Critical, Important or
Minor issues, with no declined-to-judge behaviors. Its separate uncached
analysis/flow/policy/plan/snapshot/CLI tests passed. Final local uncached root
race tests passed all 23 test-bearing packages, alongside build/vet/formatting;
current-core adapter workspace checks passed separately (10.813 s). The published
core pin then passed standalone adapter build/race (5.880 s)/vet/module verification
with GOWORK disabled and no replacement. Exact core CI and delivery are linked
from [status](status.md). No execution rulings or minor findings were deferred.

## Candidate coverage, native identity and search (2026-10-29)

The [candidate plan](plans/2026-10-29-candidate-contracts.md) was implemented in
`e8dafac`, with final renderer-boundary corrections in `9294f45`. Perl Searcher
supplies union containment and uncovered-member cost intent; the Go implementation
retains all five service dimensions and exact ordered-policy proofs.

Before correction, tests reproduced redundant service appends for union-covered
TCP ranges, duplicate generated service/rule IDs from reverse collision order,
service/group native-name conflicts, Huawei creation targeting an existing aliased
rule name, and candidate-limit errors despite a safe low-cost append. All now
pass. Name tests also retain global/local shadow avoidance, pending reservations,
ASA object/group distinction, Fortinet context and SRX native chain separation.

An independent five-dimensional packet enumeration compares service containment
and projection membership without using production set operations for expected
results. Its 20-second fuzz run passed 3,521,078 executions. The existing traffic
packet oracle passed 908,775 executions in 20 seconds. Snapshot v9, CLI JSON,
approval digests, seven-vendor fixtures and independent readback tests pass.

A fresh independent review of `bfc5f25..e8dafac` found no introduced defect, but
identified existing Transfer renderer argument aliasing and cancellation gaps.
The fix pass first reproduced sealed changes mutating through retained renderer
arguments, and successful Transfer/Preserve results after cancellation. Shared
renderChanges now copies nested inputs and returned commands and rejects canceled
completion across all three planning entries. These regressions and the complete
uncached race suite passed after the fix, with 25 successful root package rows;
build, vet, formatting and diff checks also passed. No minor findings were deferred.

The reviewer separately passed uncached plan/analysis/native-name/service-coverage
and vendor contract tests. Real-device/firmware interoperability and unrelated
unsupported native features remain unverified. Benchmark evidence is reported
separately in [benchmarks](benchmarks.md), including the measured creation overhead.
Publication, exact-commit CI and the standalone adapter pin are tracked in
[status](status.md).

## Lifecycle algorithm contracts (2026-10-29)

The [lifecycle plan](plans/2026-10-29-lifecycle-contracts.md) follows Perl
`Config/Ruleopti.pm` containment and `FireFlow/RuleOtimize.pm` fixed-point union
intent, while retaining Go's multidimensional traffic, ordered policy, logging,
future schedule and NAT proofs. Perl usage flags do not replace revision-bound
Go evidence or authorize deletion.

Failing-then-passing regressions establish:

- Low-budget equivalence, NAT preservation, convergence and reclamation reject
  unused catalogs before export. The original lifecycle cases allocated about
  14 MB despite MaxVisits=32. Allocation guards now reject well before that copy.
- Creation, transfer, unchanged preservation and already-covered requests check
  minimum readback capacity before rendering. Independent oversized captures
  fail their own visit limit before normalization or identity matching.
- Ordinary renderer failures, wrapped business errors and missing renderers abort
  convergence instead of becoming three successful rejection rows. Structured
  foreign refusals, including ones caused by ErrRender, remain fatal. Mixed
  ErrRender/budget or cancellation failures abort both candidate pipelines.
- Packed and split requests consistently reject oversized input regions. The
  oversized-traffic case formerly copied 123,056 bytes and failed the comparison
  budget; it now returns flow.ErrBudget before copying. Adequate-budget union
  equality, input association and existing cross-pair tests pass.

The new rejection stages are additive; method signatures, snapshot v9, native
renderer interfaces and the seven-vendor boundary remain unchanged. Visits are
record units, not a byte limit. Minimum readback preflight is necessary capacity,
not an assurance that arbitrary later captures or all proof work fit the budget.

The fresh independent review found one Important pre-existing accounting gap:
Equivalent rebuilt the dynamic NAT ownership index in every context without
charging those private scans. A 10-zone/100-disabled-NAT fixture returned success
across 100 contexts with all 220 visits already spent on graph preparation.
The failing regression now rejects that limit; 420 visits suffice because each
ownership index is charged and built once, eliminating 20,000 repeated NAT
visits in that fixture. Rule-effect decision scans also share the remaining
proof budget. No Critical or Minor findings were reported. Live devices,
publication and arbitrary future readback capacity were outside source review;
local tests and remote CI are recorded separately.

After the review correction, uncached `GOWORK=off GOPROXY=off go test -race
-count=1 ./...` passed all 25 root test-bearing packages on macOS arm64,
Go 1.27.1. Vet, build, formatting and diff checks passed separately. No minor
findings were deferred. No real-device or firmware interoperability was tested.

Published core `0d50959` passed its [exact-commit Go CI](https://github.com/gatework/firemon/actions/runs/40881901589)
after SSH push to `gatework/firemon` main. The adapter pins this published core
and passed standalone uncached race tests (5.588 s), vet, build and module
verification with GOWORK disabled, GOPROXY off and no replacement. Its connector
pin is unchanged. See [delivery status](status.md) for the exact module versions.
