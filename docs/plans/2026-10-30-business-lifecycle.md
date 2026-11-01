# Perl-grounded Firemon business lifecycle implementation

Approved 2026-10-30. Spec: ../spec.md, extended by this approved plan for partial
business results, multi-context plans, explicitly intended NAT changes and bounded
absolute schedules. Execute all tasks; first delivery priority is request-to-multiple-device
planning. Generate every safely provable plan and report the other problems.

## Global constraints

- Preserve the existing uncommitted parser rewrite. Baseline is a full working-tree copy, not HEAD.
- Seven vendors only: Hillstone, Palo Alto, ASA, SRX, Netscreen, Fortinet, Huawei.
- Consult the real Perl Firewall implementation whenever business meaning is uncertain; follow callers.
- Keep concrete immutable graphs and separate StaticNAT/DynamicNAT. Snapshot format 9 remains authoritative.
- Stdlib-first, Go 1.26, bounded work/context, consumer-owned small interfaces, no mutable global reports.
- First-match, unknown, exact paired traffic and outside-preservation proofs are mandatory.
- Per-item business failures do not erase safe sibling results. An unproven whole-device result has no executable plan.
- No database, web/approval platform, IPAM, real device operations, commits, pushes or release in this task.
- Synthetic fixtures only. Do not copy private sources/production configurations/credentials.
- Prior single-device APIs and approval digests retain compatibility; new report/plan formats are versioned.

## Review focus

Partial results hiding failed inputs; topology confused with default-route ownership;
cross-pair expansion during splitting/merging; cross-context object reuse and names;
whole-batch proof/readback; NAT view/ownership and unintended outside changes;
time zones and interval boundaries; usage revision/reset/window binding;
uncertain-write recovery, cancellation and materialization budgets.

### Task 1: Multi-context planning

Add `Planner.PlanBatch` with indexed per-input dispositions and one optional immutable
Plan. Normalize empty ruleset as security, combine compatible requests without losing
input provenance, use one baseline, deterministic candidate ordering and shared names.
Candidate rejection rolls back names/objects/changes; unrelated accepted inputs remain.
Final Plan proves all accepted targets jointly, retains ownership outside their union
across native chains/zones, preserves NAT, renders once from original to final, and
independently verifies readback. Covered requests remain represented. An incomplete
graph or failed final proof yields no executable device plan. Cancellation/budget/fatal
dependencies are never converted to expected candidate refusals. Preserve old Plan and
digest paths. Add bounded explanation of rejected attempts. Prefer candidate deltas
until materialization where compatible with existing proof gates; measure before any
performance claim. Tests: multi-chain requests, shared object/name collision, accepted
plus rejected input, deterministic ordering, pair preservation, whole-batch readback,
no alias, cancellation and budget. Gate: go test ./plan ./policy then full root tests.

### Task 2: Topology, batch business design and CLI

Add concrete versioned inventory.Topology: explicit device/context/VRF/zone network
bindings for protection and ingress, original/real/translated view evidence. No SQL.
Capture one manifest and load each selected revision once. Route reachability only
selects egress, never ownership/ingress. Split ranges without IP enumeration; preserve
unlocated and ambiguous fractions. Explicit device/zone selections work without topology.
Retain source requests and native wire/policy views; dynamic allocation stays possible,
reverse NAT candidates require forward proof. Use established vendor semantics; missing
Hillstone packet-path semantics is a localized unsupported result, not guessed.
Add independent operations.BatchDesigner, BatchRequest/AccessRequest, per-device plans,
per-request outcomes and typed Issue{input,device,stage,code,traffic,source references}.
Compile each device through PlanBatch; no concatenated independently proven scripts.
Add offline request-query/request-plan with bounded version-1 JSON, exact flow entries,
explicit topology input, no source reparse/DB. Preserve legacy CLI. Tests: mixed success,
ambiguous/default route, source/destination/same-device, overlapping VRF, stale topology,
missing/reserved/incomplete snapshots, shared revision load, NAT views and CLI reload.

### Task 3: Collection, inspection, changes and analysis reports

Add Collector.CollectBatch with default four workers, duplicate-device exclusion,
independent CAS/idempotency/timeouts and per-item outcomes. Failure does not cancel siblings;
cancellation stops scheduling, sessions close, incomplete live evidence is retained.
Add graph-based revision comparison (text/declaration/order/NAT changes separated from
proven behavior). Add analysis.Inspector for address/object/group paths, role-specific
rule references, containing ranges/any rules, static aliases and dynamic pool relations.
Declared reference vs effective first-match exposure stay separate. Add risk batch
preparation once per definition and convergence signature grouping before pair matching,
without weakening budgets or proof. Expose bounded reports through offline CLI. Tests:
failure isolation, max workers, revision drift, no alias, nested paths/cycles, wildcard
and ranges, NAT reverse validation, shadowed/disabled rules, compound risk and budgets.

### Task 4: Explicit NAT intent and proof

Add concrete static/dynamic/pool additions to a typed plan change set, preserving the
old rule renderer API through an additive native-change rendering boundary. Add explicit
NAT intents, never infer static semantics from cardinality or convert static to dynamic.
Only add/reuse equivalent NAT declarations, no existing NAT edit/delete. Prove intended
original-to-translated relation/mode, outside NAT relation preservation, policy+NAT
activation and native order; old policy-only plans still require NATUnchanged. Include
intents, resulting declarations and proof in a new versioned approval digest. Readback
checks full native declarations, typed created identity mapping, and repeats proof.
Dynamic allocations are possible sets, not observed sessions. Explicit bidirectional
effects are part of the requested NAT domain. Reject unknown representation/pipeline.
Tests: fixed offset/port mapping, pool possibility, prior no-NAT precedence, outside
changes, ownership, name collision, reverse direction, unknown firmware, full readback.

### Task 5: Six native NAT creation paths

Use actual Perl Designer/Searcher algorithms as reference, preserving Go semantics.
Hillstone: BNAT, directional DNAT, explicit pool/interface source PAT with version gates.
SRX: static prefix, singleton destination pool, source pool/PAT.
ASA: current modern object static/source PAT; no legacy NAT expansion.
Netscreen: MIP/VIP/DIP and newly created policy-owned NAT.
Fortinet: VIP/port forwarding and newly created policy source NAT/pool.
Huawei: server-map and current simple USG source/destination pool forms.
Palo Alto keeps existing query/policy scope, no new NAT creation this round.
Create dependencies in native order; no random names, inferred allocation or IPAM.
Each supported form requires synthetic before/commands/independent native after parse,
snapshot roundtrip, expected relation and outside proof. Record native limitations.

### Task 6: Absolute temporary policies

Add typed finite schedule intent and one-time native parse/render/readback for Hillstone,
Fortinet, Huawei, Netscreen based on Perl createSchedule and native parser code. Require
explicit verified device timezone; do not use host local time. Half-open UTC windows and
native precision must agree. Prove pre-start, active and post-end behavior; no expansion
of a permanent/shared policy into temporary semantics. Recurring schedules and new
ASA/SRX/PAN schedule writing remain unsupported. No root snapshot format change.
Tests: timezone missing, invalid/ambiguous times, boundaries, existing schedule reuse,
same-day naming collisions, outside time preservation and native readback.

### Task 7: Native usage evidence and lifecycle entrypoints

Implement bounded streaming ASA ACL counters, SRX session logs and ScreenOS session
logs using actual Cleaner::AnalyzeLog reference. Preserve timestamp/source/completeness,
unrecognized records, paired tuple evidence. Counters use two same-revision samples;
reset/missing window/identity drift stays unknown. ASA line numbers are never persistent
identity. Bind complete native declarations to rule/graph revision. A rule hit does not
imply all members hit, nor do independent members imply observed cross-products.
Feed existing UsageObservation/MemberUsageObservation. Missing logs do not imply unused.
Expose risk/convergence/reclamation/migration reports and existing safe plans via CLI;
migration retains explicit chain/zone effective-partition algorithm, no NAT migration.
Tests: resets, duplicate/out-of-window records, missing timezone, revision drift,
ambiguous identifiers, unsupported protocols and no evidence-based automatic deletion.

### Task 8: Selected multi-device apply and recovery material

Execute only explicitly selected valid per-device plans, preserve unresolved application
items, report device success/failure/uncertain independently. Reuse deploy.Engine for
every device; no cross-device atomicity/automatic rollback/uncertain command replay.
Persist bounded versioned reconstruction material containing original baseline,
normalized intent, planner version/digest. Restore from exact snapshots and re-prove;
digest mismatch stops, never redesign against current state. Reports alone are not
executable plans. Selected operation identity/digests are explicit and durable.
Test process recovery, same selection idempotency, independent failures, baseline drift,
corrupt/tampered material, authorization binding, partial results and no-write recovery.

### Task 9: Oracle, measurements, docs and final gate

Extend real isolated Perl oracle (six vendors where real methods exist); record function
and source hashes and intentional stronger-Go differences. Use synthetic fixtures and
read-only/no-network Perl containers. Preserve existing parser evidence.
Benchmark serial before/after request batches, shared groups, sparse/dense candidates,
1000/10000 rules, record allocations and raw repeated outputs, no unmeasured claims.
Run full root race/vet/build, Go floor checks and pinned/current optional adapter checks.
Complete independent final review, document public API/migration/capability limits,
local vs CI vs device evidence, and verify no accidental baseline WIP loss.
