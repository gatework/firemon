# Domain contracts and module refactoring

Approved scope: quality refactoring and corrections to existing behavior, with
controlled Go API changes. Perl Firewall modules are read-only business references.
Specifications: `docs/spec.md`, `docs/contracts.md`, `AGENTS.md`. Keep seven vendors,
immutable graphs, separate StaticNAT/DynamicNAT, exact traffic algebra, unknown
evidence, native ordering, snapshot format 9 and durable recovery without replay.
Do not change persisted record fields, CLI JSON fields or plan digest encoding.

## Task 1: Domain, evaluation, planning and analysis

Own root Go files, flow, policy, plan, analysis, benchmarks and documentation.
Add PolicyChain and consistent scalar object accessors. Rule shares MatchObjects
with NAT. Retain defensive Record/Export, persistent fields and query wire shape.
Introduce Engine.ResolveAddresses/ResolveServices(ctx, fw, refs, any) returning
(value, known, error); errors and cancellation cannot become semantic unknown.
Update planner callers; Task 2 updates vendor callers. Guard nil firewall inputs.
Use cheap scalar reads, request-local expansion reuse and ordered policy views.
Split graph sealing/binding and planner responsibilities within existing packages.
Rename Optimizer to RequestOptimizer, Translator to PolicyMigrator and use shared
PolicyChain. Precompute convergence signatures and contexts without weakening
pair budgets, native order or whole-rulebase proof. Optimize measured planning
hot paths without changing cost preference, command output or approval digests.
Add contract/immutability/cancellation/budget regressions and lifecycle benchmarks.

## Task 2: Stateful configuration and seven native adapters

Own config and vendors (including tests); no edits to policy/root/plan.
Read the governing specs above and relevant Perl Content/Parser/Element roles.
Add uniform native Parser{Limits config.Limits}.Parse methods; keep Parse as a
default convenience and Fortinet ParseVDOM forwarding its explicit context.
vendors.Parser carries Limits; selected Fortinet context defaults to root.
Export the existing default source byte limit from config for other consumers.
Replace whole-stage Data clones with append-length checkpoints and evidence undo;
retain exact rollback of data, evidence and cursor on error/cancel. Transfer owned
transaction drafts only after validation, clear moved draft and reject closed
transaction effects. Retain copy isolation at Emit/Data boundaries.
Audit all seven vendor parsers/renderers, in order ASA, SRX, Palo Alto, Fortinet,
Huawei, Hillstone, Netscreen. Use native scope, pending state and dependency order;
interfaces precede route binding. Eliminate measured ASA operand full-directory
clones with a parser-local identity index including current draft. Reduce repeated
Session.Data full exports where typed local state suffices, without leaking aliases.
Migrate policy.Addresses/Services callers to Engine.ResolveAddresses/ResolveServices
with their actual ctx and propagate execution errors (never turn them into unknown).
Task 1 supplies the new methods; coordinate if needed. Preserve vendor semantics,
VIP relations, record order and digests. Add focused rollback/closed transaction,
config limit, cross-context and literal identity tests. Run config/vendors tests.
Report tests, issues/rulings and seven-vendor audit results. Do not benchmark while
the root is collecting serial baselines. Do not commit; root stages owned files.

## Task 3: Persistence, capture, operations and integration boundaries

Own internal, snapshot, inventory, projection, operations, deploy, adapter/netconnector
and cmd/firemon. No changes to root/config/vendors/policy/plan/analysis/docs.
Read governing specs above and preserve lifecycle ordering and persisted shapes.
Introduce consumer-owned ManifestReader/RevisionLoader and projection Outbox small
interfaces. Extract shared internal/durablefile replacement-write and locking
primitives; retain temp/fsync/close/rename/directory-fsync and context-aware locking.
Add failure-injection and cross-process tests; propagate close errors consistently.
Extract internal capture validation/sealing primitive shared by collector/deploy:
return an incomplete graph AND original error for parse/cancellation/identity/source
failures, retaining only fixed diagnostics on disk. Preserve original bounded source,
metadata and each caller's diagnostic codes. Incomplete capture must never become
complete. Do not merge upper-level state machines or replay device writes.
Use config.DefaultMaxBytes (Task 2 supplies it) for shared source ceiling, preserving
the distinction from cumulative adapter output. Make connector profile aliases an
explicit conversion to domain vendor names, with seven-vendor tests.
Fix inspect --revision returning an empty revision and add historical JSON test.
Add cancellation/partial evidence/metadata spoofing/error preservation and outbox
retry tests. Do not change nested module versions yet; root pins published core.
Run affected package tests and standalone adapter checks. Report tests and rulings.
Do not commit; root stages owned files.

## Task 4: Verification and delivery

Run independent review of each task and final integrated diff; fix correctness
findings with regression tests. Measure serial six-sample before/after benchmarks
using one toolchain/CPU setting. Cover parse/query/plan/NAT/packet/snapshot/flow and
new shared-group/convergence/risk workloads. Keep only reproducible optimizations.
Run gofmt, go test -race ./..., go vet ./..., bounded fuzz and process failure tests.
Update module audit, Perl mapping, contracts, migration table and benchmark evidence.
Commit structural, behavioral and performance work separately. Existing user
authorization covers shipping to GitHub gatework/firemon (remote go, not origin).
Publish core before pinning adapter; verify versioned GOWORK=off/no-replace consumer,
then push adapter/documentation and read back CI. Report local, remote and device
evidence separately. No real device operations.
