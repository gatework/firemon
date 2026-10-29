# Implementation status

The approved implementation, domain refactoring and contract/ownership plans have passed their local checks and independent reviews. The [requirement audit](verification.md) records the evidence and implementation decisions. The capabilities below define the delivered scope; broader native grammar and firmware parity remain unproven. No real device, SQL database or release validation has been performed.

| Area | Current evidence | Explicit limits and future coverage |
| --- | --- | --- |
| Concrete graph | StaticNAT and DynamicNAT catalogs, typed VIP associations; shared references, sealed copies, scoped routes; local tests | Broader native fields and lifecycle dependencies |
| Exact traffic | IPv4/IPv6 interval and multidimensional algebra; fuzz/race tests and paired-region benchmarks | Further adversarial limits and larger workloads |
| Cursor | Pending skip, rewind, transactional drafts/evidence and stage rollback; bounded XML fragments with original byte spans | Additional native grammar recovery |
| Persistence | Semantic-format-9 gob envelope; shared graph restored without raw parse; CAS, reservation, outbox, projection retry; separate-process reservation and injected publication failures | Physical power-loss/filesystem validation, store growth/compaction policy |
| Hillstone | Scoped parser, exact policy query, independent plan/readback proof and rendering; 4 verified Perl oracle cases; BNAT inverse and per-direction priority; version-gated original-packet DNAT/SNAT composition | Extended syntax and broader native fixtures; mixed-chain behavior needs real-device verification |
| Palo Alto | Native set/XML graph parity and byte evidence; explicit interface NAT host selection; static routes scoped by virtual router; implicit same-zone/cross-zone rules; distinct log-start/log-end; original-address/post-DNAT-zone packet tests; native rendering and independent readback | Multi-vsys/central management rules, application conditions, reverse static NAT, unselected multi-address interface allocation and wider version coverage |
| ASA | Interface/ACL binding, full service protocol/port pairing, native NAT section priority and exact auto-NAT cardinality/name sort; static and twice-NAT forward/reverse address/port evaluation; real-address packet path; new ACL rendering/readback | Additional ACL/time syntax, global/same-security rules, legacy NAT and wider version matrix |
| SRX | Staged display-set parser; logical interfaces and VRF routes; attached/local/global address-book identity and lookup; application term pairing; zone-pair policy identity/order; static address/port inverse, destination pool translation, source pool/PAT and off; post-DNAT routing/policy then permitted SNAT; create/append/delete rendering and independent readback; CLI import/NAT/plan | Hierarchical input, groups/inheritance, predefined applications, schedules/global policies, interface/instance NAT rule-set precedence, interface allocation, non-singleton destination pools, additional native/version coverage |
| Netscreen | Scoped ScreenOS passes; VRF/interface route binding; zone/global addresses and paired service groups; policy continuations, top placement, disable and intrazone block/bypass; separate MIP/VIP/DIP/policy NAT with owning-rule identity; original-address/port packet policy; independent create/append/delete readback and CLI snapshots | Virtual systems, Global policies, schedules/predefined services, PBR/route leaks, DIP address shifting, loopback groups/multi-interface NAT, mixed opposite-direction interface/policy translation and edits to NAT-owning policies; broader native/version fixtures |
| Fortinet | Selected-VDOM scoped config/edit parser; interface/zone/route dependencies; address/group and paired service terms with global source-port defaults; separate fixed VIP, port forwarding, pools and policy-owned source NAT; VIP policy lookup, reverse VIP source priority, original-wire query traces and post-DNAT packet routing; native create/append/delete rendering with independent readback; VDOM-aware CLI snapshots | Central NAT, policy-based NGFW, IPv6 native syntax, schedules, PBR/SD-WAN, additional VRFs/secondary interfaces, non-overload pools, port-forward source forcing, partial-zone interface selectors, unresolved one-sided translated service checks, declared VIP risk, local VIP/pool behavior, native NAT edits; broader fixtures/version evidence |
| Huawei | Scoped USG sections and indexed object reopening; interface/VPN/route binding; address/service groups and paired ports; separate server maps, source/destination pools and whole policy NAT actions; post-DNAT routing/service policy and permitted source allocation; native create/append/delete with independent readback and offline CLI snapshots | Wider native/version evidence, schedules/time zones, predefined services, IPv6 native syntax, virtual systems, secondary/dynamic interfaces, route leaks/PBR, static policy NAT, multi-address destination allocation, protocol-specific reverse server maps, server-map/policy composition and NAT edits |
| Embedded operations | Shared seven-vendor parser/renderer registry; standalone read-only capture; validated private service dependencies; revision-bound design/deployment; live incomplete-evidence invalidation and idempotent publication | Host inventory, credentials, authorization and projection remain injected |
| CLI | Offline import/inspect/query/nat/plan; selected Fortinet VDOM survives reload after original file removal | Broader commands, help ergonomics and export contracts |
| Online | Injected deploy engine, exact-plan authorization, durable operation journal/receipts, reservation, save confirmation, new-session readback, incomplete-live publication and no-write recovery; process-exit tests at five write/save/publication boundaries; mandatory isolation lifecycle, owned PAN lock/queued commit handling, exclusive SRX candidate, selected Fortinet VDOM; separate seven-vendor adapter with native deployment/recovery transcript tests | Real-device interoperability and additional native save/commit response formats |
| Lifecycle | Request-local evidence, time and mappings with concurrent reuse regressions; exact fixed-point request optimizer; all-zone/future-boundary equivalence; bounded convergence discovery and batch reclamation plans; revision/graph-bound rule/member usage evidence; compound declared/effective risk; explicit zone/chain translation preserving action/logging; optimizer/planner benchmarks | Broader native rendering and schedule migration; native schedule/NAT migration and lifecycle CLI coverage |

Unrecognized source and unsupported semantics remain incomplete; do not describe that as vendor parity. A successful offline proof is not real-device interoperability or permission to deploy.

The user-confirmed scope is Palo Alto, SRX, Huawei, Hillstone, Fortinet, Netscreen and ASA. H3C, Topsec, Neteye and other vendors are deferred.

## Lifecycle contract delivery (2026-10-29)

Core [`0d50959`](https://github.com/gatework/firemon/commit/0d50959d0a4d12b543fac8a3c1a5a52a02dd663c)
implements the [lifecycle plan](plans/2026-10-29-lifecycle-contracts.md).
SSH publication to public `gatework/firemon` main completed; its
[exact-commit CI](https://github.com/gatework/firemon/actions/runs/40881901589)
passed formatting, vet and race tests. Final local uncached race tests passed
all 25 root test-bearing packages; vet, build and formatting passed separately.

Lifecycle graph copies and independent observations are charged before export;
all plan creation paths preflight minimum readback capacity. Convergence and
access-request candidates preserve fatal error provenance; expected refusals
carry declaration, preservation or representation stages. Request optimization
checks input regions before grouping. The independent review's one Important
private NAT accounting gap was reproduced and fixed: ownership indexes are now
built once per equivalence proof. No Critical or deferred Minor findings remain.

The optional adapter pins published core `v0.0.0-20261029132556-0d50959d0a4d`;
connector remains `v0.0.0-20261026235641-c68c42b4bbcf`. Standalone
`GOWORK=off GOPROXY=off` uncached race tests passed (5.588 s), together with vet,
build and module verification. Module lookup confirms the published core cache
entry with no replacement. Public CI excludes this private-dependency adapter.

[Contracts](contracts.md) describe stricter low-budget rejection and additive
`RejectionError` diagnostics. Snapshot v9 and method signatures remain unchanged.
Minimum readback preflight is necessary capacity, not guaranteed future proof
completion. No release or real-device validation is claimed.

## Previous candidate contract delivery (2026-10-29)

Core [`9294f45`](https://github.com/gatework/firemon/commit/9294f4532eb246c057e0465ec6ff570c5f670bc2)
implements the [candidate plan](plans/2026-10-29-candidate-contracts.md), including
the final ownership/cancellation corrections. SSH push to public `gatework/firemon`
completed, and its [exact-commit Go CI](https://github.com/gatework/firemon/actions/runs/40873825279)
passed formatting, vet and race tests. Local uncached race tests passed 25 root
package rows; build, vet, formatting and diff checks passed separately.

Planning now compares service union coverage, allocates collision-free graph/native
identities, and ranks bounded candidate attempts before constructing creation
fallbacks. Huawei rejects aliased native rule names. Plan, Transfer and Preserve
share renderer input/output ownership and cancellation handling. The public
`MaxCandidates` field now counts full proof/render attempts (default 128); visit
and region limits still bound discovery and proofs. Snapshot v9, CLI JSON,
approval goldens and seven-vendor tests remain stable.

The optional adapter pins published core `v0.0.0-20261029122754-9294f4532eb2`;
connector remains `v0.0.0-20261026235641-c68c42b4bbcf`. Standalone
`GOWORK=off GOPROXY=off` build, uncached race tests (5.735 s), vet and module
verification passed after tidy. Module lookup confirms the published cache entry
with no replacement. Current-core workspace race/vet passed separately (5.783 s).
Public CI excludes this private-dependency adapter.

The [verification record](verification.md) includes independent review and
3,521,078 service / 908,775 traffic fuzz executions. Alternating benchmarks show
roughly 4–5% creation overhead; reuse and risk controls remain stable. See
[measurements](benchmarks.md). No release or real-device validation is claimed.

## Previous core policy algorithm delivery (2026-10-29)

Core [`6ec81b00be2a02ce0ab1f378c9bcaf1361c6399f`](https://github.com/gatework/firemon/commit/6ec81b00be2a02ce0ab1f378c9bcaf1361c6399f)
implements the [algorithm plan](plans/2026-10-29-policy-algorithm-contracts.md).
SSH publication to public `gatework/firemon` main and exact remote SHA read-back
succeeded. Its [exact-commit CI](https://github.com/gatework/firemon/actions/runs/40861058742)
passed formatting, vet and race tests on Ubuntu with Go 1.26.

The independent final source review found no Critical, Important or Minor issues
and declined no behaviors. Local uncached root build, race tests across 23 packages,
vet and formatting passed. A 30-second flow-algebra fuzz run passed 1,290,834 cases.
The independent packet reference, unknown-action correction, future-context and
whole-batch proofs are detailed in [verification](verification.md).

The optional adapter pins published core `v0.0.0-20261029104925-6ec81b00be2a` and
connector `v0.0.0-20261026235641-c68c42b4bbcf`. After tidy, standalone
`GOWORK=off GOPROXY=off` build, uncached race tests (5.880 s), vet and module
verification passed. Module lookup confirmed published cache versions with no
`Replace`. Public root CI excludes the private-dependency adapter.

The Go API rename is deliberate and has no legacy aliases; see
[the migration table](refactoring.md#policy-algorithm-domain-names). Frozen v9
snapshot decoding, its original semantic digest, CLI JSON and seven-vendor
fixtures remain stable. Six serial benchmark samples per case show unchanged
allocations and small timing increases; no speedup is claimed. Real-device and
broader firmware compatibility remain unverified.

## Previous computation and scanner delivery (2026-10-29)

Core [`2e301195fa86c0a93bef9276f71ef6855b11a4cb`](https://github.com/gatework/firemon/commit/2e301195fa86c0a93bef9276f71ef6855b11a4cb)
implements the [computation plan](plans/2026-10-29-computation-contracts.md),
including both independent-review corrections. Its [exact-commit CI](https://github.com/gatework/firemon/actions/runs/40853833066)
passed formatting, vet and race tests. SSH publication and exact remote main SHA
were verified separately from local tests.

The breaking API changes are `MaxRegions`/`MaxVisits`/`MaxCombinations`,
`Limits.WithDefaults()`, and context-first cursor constructors; see the
[migration guide](refactoring.md). Candidate/catalog work, lifecycle proofs and
unknown findings now obey layered budgets. Risk expressions prepare standards
once per call and cache projections only for the current rule. Seven-vendor
scope, separate StaticNAT/DynamicNAT and staged evidence remain unchanged.

The adapter now pins published core
`v0.0.0-20261029095830-2e301195fa86`; connector remains
`v0.0.0-20261026235641-c68c42b4bbcf`. After tidy, its standalone
`GOWORK=off GOPROXY=off` race suite passed in 6.140 seconds, with vet and module
verification. `go list -m -json` confirmed module-cache versions without
replacement. Current-core workspace race/vet passed separately. Public root CI
does not test this private-dependency adapter; no private source is published.

Synthetic complex-risk time fell about 72.5% in the largest declared-mode case,
while cancellable scanning has documented overhead; see [measurements](benchmarks.md).
This delivery does not establish hardware/firmware certification or perform a
release or real-device operation. The older deliveries below are historical.

## Boundary contract delivery (2026-10-29)

Core [`f85f9d6737f9d0fffcee801c58314c803ff9ac2b`](https://github.com/gatework/firemon/commit/f85f9d6737f9d0fffcee801c58314c803ff9ac2b)
was pushed by SSH to public `gatework/firemon` on `main`; exact remote SHA readback
matched. Its [Go workflow](https://github.com/gatework/firemon/actions/runs/40843009590)
passed formatting, vet and race tests on Ubuntu. Local final
`GOWORK=off GOPROXY=off go test -count=1 -race ./...` passed all 23 root test
packages, and vet/format/diff checks passed. Independent review findings and the
completion audit's additional persisted-head check are recorded in
[verification](verification.md); all identified findings are fixed.

Seven native renderers now enforce complete declared deltas, native identity,
explicit wildcard/empty semantics and deterministic order. Lifecycle usage shares
bounded request-local evidence indexing. Snapshot/journal input, corruption and
I/O failure classifications are separate. See the [migration notes](refactoring.md)
for custom renderer error handling and stricter evidence budgets. Snapshot
semantic format 9, journal encoding and existing approval golden digests remain
compatible; this iteration requires no snapshot reimport.

The optional adapter pins published core
`v0.0.0-20261029083333-f85f9d6737f9`, with connector
`v0.0.0-20261026235641-c68c42b4bbcf` unchanged. After tidy, standalone
`GOWORK=off GOPROXY=off go test -count=1 -race ./...` passed (7.012s), followed by
vet and module verification. Module metadata confirms both published versions and
no replacement. Current-core workspace checks passed separately. Public root CI
does not test this private-dependency nested module, and no private source is
published.

Six-sample serial benchmarks reduce the 1000-rule/16-observation case from
95.541ms to 1.882ms (-98.03%), while allocated bytes increase 11.37% for the index.
The smallest case has no significant timing change and uses 24.92% more bytes.
The [complete comparison](benchmarks/2026-10-29-usage-comparison.txt) reports all
cases; these are synthetic local measurements, not production capacity claims.
Real-device/firmware behavior, release publication and SQL integration remain
outside this iteration's evidence.

## Contract and ownership delivery (2026-10-29)

Core [`ed34cf431f3a459e3602a45a796768a45945b1ca`](https://github.com/gatework/firemon/commit/ed34cf431f3a459e3602a45a796768a45945b1ca)
was pushed by SSH to public `gatework/firemon` on `main`; remote SHA readback
matched. Its [Go workflow](https://github.com/gatework/firemon/actions/runs/40818572566)
passed formatting, vet and race tests on Ubuntu. Final local root
`GOWORK=off GOPROXY=off go test -count=1 -race ./...` passed all 23 test packages;
`go vet ./...`, formatting and diff checks passed. The independent integrated
source review approved the final route/capture changes with no open findings.

The optional adapter pins core `v0.0.0-20261029043441-ed34cf431f3a`; connector
`v0.0.0-20261026235641-c68c42b4bbcf` and its dependencies are unchanged. After
`go mod tidy`, its independent `GOWORK=off GOPROXY=off go test -count=1 -race ./...`
passed (7.382 seconds), as did vet and module verification. `go list -m -json`
confirmed the published core and connector versions in the module cache without
`Replace` fields. This is separate from the earlier current-core workspace check;
public root CI does not test the private connector dependency.

Breaking Go API changes include canonical `device.Reader`/capture types,
`config.Parser`, checked private service construction, session cursor ownership,
`Engine.ResolveRoutes`, and per-call lifecycle request objects. See the
[migration guide](refactoring.md) before updating a host. Snapshot semantic format
9, record/CLI fields, native fixture exports, semantic digests and baseline
approval goldens are unchanged; existing v9 snapshots need no reimport for this
iteration. Broader native syntax and real-device behavior remain unverified.

The [benchmark record](benchmarks.md) separates the full 87-case comparison from
the final route/packet follow-up. The final 1,000-route case reduced time about
25% and allocations about 45%, while the 10-route case still allocates 64 extra
bytes. Retained-capture validation eliminates the full-graph clone; it excludes
parsing and device I/O. No production capacity claim is made.

## Previous domain refactoring delivery (2026-10-29)

Core [`c9d9f251ed20cd35ed9fd75743740dab96683b45`](https://github.com/gatework/firemon/commit/c9d9f251ed20cd35ed9fd75743740dab96683b45)
was pushed through SSH to public `gatework/firemon` on `main`; the remote SHA was
read back and matched. Its [Go workflow](https://github.com/gatework/firemon/actions/runs/40811038503)
passed formatting, vet and race tests on Ubuntu. Local root race/vet passed
across 23 tested packages. The independent final source review found no unresolved
correctness issues.

At that checkpoint, the optional adapter pinned core `v0.0.0-20261029031126-c9d9f251ed20` and connector
`v0.0.0-20261026235641-c68c42b4bbcf`. After `go mod tidy`, its standalone
`GOWORK=off GOPROXY=off go test -count=1 -race ./...` passed (5.604 seconds), as did
`go vet ./...` and `go mod verify`. `go list -m -json` confirmed both published
module-cache versions without a `Replace` field. Its profile alias regression
covers the seven supported vendors and rejects H3C. Public root CI does not test
this nested module's private dependency.

The [module audit and API migration](refactoring.md) describe the shared domain
contracts, parser ownership and lifecycle naming changes. Snapshot semantic
format remains 9; this refactor does not require reimporting an existing v9 store.
Native fixture exports, semantic digests and baseline plan approval goldens remain
unchanged. The [benchmark record](benchmarks.md) includes serial before/after
samples, counterbalanced controls and the small snapshot decoding allocation cost
of the shared match view. These are synthetic measurements, not device or
production-capacity evidence.

## Previous operations remediation delivery

The following records the earlier operations remediation, before the domain
refactor and adapter pin above.

The operations core [`af1f854b08e6b5117a43d137c91408af3e91d7de`](https://github.com/gatework/firemon/commit/af1f854b08e6b5117a43d137c91408af3e91d7de)
was pushed to public `gatework/firemon` on `main`. The remote SHA was read back
and matched, and its [Go workflow](https://github.com/gatework/firemon/actions/runs/40801906537)
passed vet and race tests on Ubuntu. Local root race/vet passed across 21 packages.
The completed full Codex review and all three corrected findings are recorded in
[verification](verification.md).

The optional adapter pins core `v0.0.0-20261029014108-af1f854b08e6` and connector
`v0.0.0-20261026235641-c68c42b4bbcf`, with no local replacement. After `go mod tidy`,
`GOWORK=off GOPROXY=off go test -count=1 -race ./...` passed (7.097 seconds), as did
`go vet ./...` and `go mod verify`. `go list -m -json` confirmed the published
module-cache versions without a `Replace` field. The separate current-core
workspace check passed earlier (6.526 seconds). Public root CI does not test this
nested module's private dependency; no private connector source is included.

Snapshot semantic format 9 requires reimporting original captures into a new
store. Complete pending device recovery with the prior binary and retain its
journal/store before upgrading. Custom `deploy.Session` implementations must
implement the configuration begin/end contract. These migration requirements
are detailed in [contracts](contracts.md).

## Previous delivery verification

The following exact-commit results predate the operations remediation. They are retained as historical evidence, not verification of subsequent changes. Current remediation evidence is recorded separately in [verification](verification.md).

The seven-vendor implementation, planner correction and both final PAN review fixes passed `GOWORK=off GOPROXY=off go test -count=1 -race ./...` across 19 root packages and `GOWORK=off GOPROXY=off go vet ./...` locally on macOS with Go 1.27.1. A 45-second Huawei parser fuzz run completed 1,038,728 executions without failure. Root has no external module dependency. The final [benchmark matrix](benchmarks.md) passed 75 cases with six serial samples each. The independent whole-branch review found two Important defects; both were reproduced before correction and passed their regressions and the full race suite. No minor review findings were deferred.

The final core commit [`49b866f6aa3cac32dbcfa355fad7450de15b4bd7`](https://github.com/gatework/firemon/commit/49b866f6aa3cac32dbcfa355fad7450de15b4bd7) was pushed to public [gatework/firemon](https://github.com/gatework/firemon) on `main`; its [Go workflow](https://github.com/gatework/firemon/actions/runs/40788048682) passed vet and race tests on Ubuntu. The remote SHA was read back and matched. This CI evidence applies to that exact core commit; the subsequent adapter-pin/documentation commit has its own workflow result.

The adapter pins core `v0.0.0-20261028233205-49b866f6aa3c` and connector `v0.0.0-20261026235641-c68c42b4bbcf`, with no local `replace`. After `go mod tidy`, its transcript/integration tests passed with `GOWORK=off GOPROXY=off go test -count=1 -race ./...` (2.332 seconds), as did `go vet ./...` and `go mod verify`. `go list -m -json` confirmed the published module-cache versions without a replacement. The current-core workspace race/vet check passed separately. Public root CI does not test the nested adapter; its private dependency requires authenticated Git access, and no private source is included.

The final [verification record](verification.md) preserves all execution decisions and reviewer limitations. Local/offline, public CI, optional adapter and real-device evidence remain separate. The existing Go and Ruby worktrees are retained; the Ruby reference repository was not changed.
