# Domain refactoring and API migration

## Computation limits migration

`policy.Limits` now uses `MaxRegions`, `MaxVisits`, and `MaxCombinations` in
place of `Regions`, `Rules`, and `Combinations`. Update keyed literals and field
accesses; no aliases remain. Visits already covered routes and usage evidence,
so the new name describes the actual work rather than only policy rules.
`WithDefaults()` returns a copy with nonpositive fields defaulted to 4096,
100000, and 4096 respectively. Algorithm-specific candidate/comparison caps
remain separate. These Go API changes do not change persisted graph formats.

Graph counts (`RuleCount`, `ZoneCount`, `ScheduleCount`) allow budget checks
without materializing lists. `Schedule.Windows()` yields absolute windows by
value in declaration order; `HasRecurrence()` reports recurring declarations.
Existing copied views and native `OrderedRules()` retain their ordering contracts.

The module audit implements the [domain review plan](plans/2026-10-29-domain-refactor.md)
and the subsequent [contract and ownership plan](plans/2026-10-29-contracts.md).
It refactors existing behavior; supported vendor syntax and lifecycle capabilities
remain those in [status](status.md). Only Palo Alto, SRX, Huawei, Hillstone,
Fortinet, Netscreen and ASA are enabled.

## Domain responsibilities and Perl references

The Perl tree is a read-only business reference, not a Go dependency. The useful
contracts are typed object identity, native scope, staged interpretation, exact
address/service sets, candidate cost and evidence-bound policy operations.

| Perl responsibility | Go owner and review outcome |
| --- | --- |
| Config::Element roles / Parser::Elements | Root concrete immutable graph. Shared Rule/NAT matching views; scalar identity access; binding, validation, digest and sealing have separate source files in one package. |
| Config::Content::Role / Parser::Role | config owns source, cursor, transactions and stage dependencies. Append-only drafts and evidence undo preserve rollback without full graph backups. |
| Native Parser and Designer modules | Seven native packages own grammar and rendering. Parser limits are uniform; native syntax, policy order and packet semantics stay explicit. |
| Policy::Searcher | inventory locates immutable revisions; policy resolves groups and evaluates rules, routes and NAT. Unknown semantics and execution failures are distinct. |
| Policy::Designer | plan owns candidate object reuse, cost ranking, renderability and independent traffic proofs. Proof, candidate construction and public contracts are separated. |
| Config::Ruleopti | analysis.Converger classifies containment/combination and proves whole-rulebase preservation. Pair comparison budgets and native order remain deterministic. |
| Config::Audit | RiskAnalyzer retains declared/effective modes, paired traffic and three-valued compound expressions. No unknown result becomes a clean risk assessment. |
| Policy::Cleaner::Flagger | Reclaimer evaluates request-local revision, graph, time-window and rule/member evidence. Missing logs and zero counters alone do not authorize removal. |
| FireFlow design/deploy | operations composes collection/design; deploy owns authorization, reservation, receipts, persistence and independent recovery. No uncertain writes are replayed. |
| DAO and reporting | snapshot remains authoritative; inventory/projection consume narrow interfaces. Host databases remain optional projections, not graph reconstruction dependencies. |

Go uses composition and consumer-owned interfaces instead of reproducing mutable
Moose inheritance or dynamic role loaders. The module does not add a database,
account service, workflow approval platform or new vendor family.

## Public API changes

| Previous usage | Current usage |
| --- | --- |
| `analysis.Optimizer` | `analysis.RequestOptimizer` |
| `analysis.Translator` | `analysis.PolicyMigrator` (policy-only migration; existing NAT/time restrictions remain) |
| `analysis.Chain` | `firemon.PolicyChain{Scope, RuleSet}` |
| `policy.Addresses(fw, refs, any)` | `engine.ResolveAddresses(ctx, fw, refs, any)` returning `(flow.AddressSet, bool, error)` |
| `policy.Services(fw, refs, any)` | `engine.ResolveServices(ctx, fw, refs, any)` returning `([]firemon.ServiceTerm, bool, error)` |
| Scalar reads through `Record()` | `ID()`, `Name()`, `Scope()`; rules also expose `Position()` and `Chain()` |
| Different rule/NAT relationship views | `Rule.Match()`, `StaticNAT.Match()`, `DynamicNAT.Match()` return `MatchObjects` |
| Fixed parser limits | `vendors.Parser{Limits: config.Limits{...}}`, or the same `Parser` shape in each native package |
| Concrete store arguments for inventory/projection | `inventory.ManifestReader`, `inventory.RevisionLoader`, `projection.Outbox` |

The subsequent contract migration deliberately removes the old Go APIs without
aliases. Update consumers together with the optional adapter:

| Previous usage | Current usage |
| --- | --- |
| `deploy.View`, `Capture`, `Running`, `Saved` | Same names in `device` |
| `deploy.Parser`, `ParseFunc` | `config.Parser`, `config.ParseFunc` |
| Public fields on `Collector`, `Designer`, `deploy.Engine` | `operations.NewCollector(CollectorOptions)`, `NewDesigner(DesignerOptions)`, `deploy.New(Options)`, each returning a pointer and error |
| `runtime.Collector.Collect`, component replacement | `runtime.Collect`, `Design`, `Apply`, `Recover`; dependencies are private |
| Collection through `deploy.Factory.Open` | `operations.ReadOnlyFactory.OpenReadOnly` returning `device.Reader` |
| `session := config.NewSession(cursor, metadata)` | `session, err := config.NewSession(cursor, metadata)`; access `session.Cursor()` |
| `policy.Routes(..., limit)` | `engine.ResolveRoutes(ctx, fw, vrf, addresses)` with `Engine.Limits` |
| `RuleOrder.Chain [4]string` | `policy.RuleChain{PolicyChain, FromZone, ToZone}` |
| `Reclaimer` evidence/time fields | `ReclamationRequest` passed to `Analyze`, `AnalyzeMembers` and `Plan` |
| `PolicyMigrator` mappings/time fields and selection arguments | `MigrationRequest` passed to `Plan(ctx, source, target, request)` |
| `Converger.From` | `Candidates(ctx, fw, from)` and `Plan(ctx, fw, ids, from)` |
| `RiskAnalyzer.Assess` | `RiskAnalyzer.Analyze` |
| Raw-source or flag reads through a full record clone | `Firewall.Raw`, `HasUnsupported`, `Disabled`, `Rule.Builtin`, `Rule.Action` as applicable |

`Reclaimer.Plan(ctx, fw, request, ids)` proves the selected batch using that call's
time and evidence. Reusing a service does not carry observations, mappings or
selections into a subsequent invocation. `Schedule.ActiveAt` and `ExpiredAt`
centralize domain time predicates; `Request.SameContext` centralizes evaluation
context equality. These APIs preserve unknown evidence and full-plan proof.

The old lifecycle type names and error-hiding resolver functions are removed.
`known=false, err=nil` means declarations cannot be fully interpreted. A canceled
context, exhausted budget or invalid graph is an execution error and must be
propagated. Resolvers use `Engine.Limits.MaxCombinations`; they never invent a
background context. `Match` and `Query` reject a nil firewall with `policy.ErrInvalid`.

Existing package-level native `Parse` functions remain convenient default entry
points. For Fortinet, `Parser.Parse` and the registry use `Metadata.Context`,
defaulting to root. The older package `fortinet.Parse` retains its root-only
behavior; `ParseVDOM` remains an explicit-context convenience. XML and CLI input
obey the same configured limits. `config.DefaultMaxBytes` names the existing
16 MiB source ceiling; cumulative transport output is a distinct adapter limit.

`Rules()` retains source declaration order. `OrderedRules()` is an `iter.Seq`
that visits shared immutable objects by native position then stable ID without
exposing the backing index. Collection getters and `Record`/`Export` still copy
mutable containers. Query memoization is invocation-local, graph-bound and
weight-bounded; cache hits charge the original traversal budget. Time, routing,
VIP selection and decisions are not cached.

## Compatibility and execution invariants

Snapshot semantic format stays at **9**; manifest and journal layouts are unchanged.
Request/record `Scope` and `RuleSet` fields retain their wire representation;
`Chain()` is a value view. No snapshot reimport is required solely for this
refactor. Older pre-v9 snapshots remain subject to the existing format rejection.
Native fixture exports and semantic digests were compared to e9e9b96 in the
first refactor and dd15031 in the contract iteration; reuse,
append and create approval digests are protected by baseline golden tests.

Configuration stages append accepted drafts and commit consumed evidence together.
Rollback restores data headers, claimed evidence and cursor position. A committed
transaction transfers its copied draft once, clears it and ignores subsequent
Emit/Parse/Ignore attempts; a second Commit returns ErrClosed. Unknown source stays
pending or diagnostic. Interfaces still precede route binding.

Failed parsing, parser substitution and cancellation retain the original bounded
capture as an incomplete graph together with the original execution error. Only
fixed diagnostics are persisted. Untrusted session identity or oversized captures
are rejected before publication. Storage errors after rename remain reported;
release/close errors are preserved. Sink commit still precedes outbox acknowledgement.
Historical `inspect --revision` now reports the requested revision.

## Development conventions

- Use domain nouns for types and business verbs for methods. Use MixedCaps and
  established acronyms such as ID, NAT, VIP and XML. Avoid Get-prefixed accessors.
- Keep native adapters separate from common algorithms. Share small proven
  primitives, not a universal vendor interface or generic service framework.
- Group standard-library imports before module imports and run gofmt. Add
  interfaces at consumers; retain concrete immutable domain objects.
- Pass context first through executing operations. Preserve errors with wrapping
  or errors.Join and inspect with errors.Is/As; never turn resource failure into
  semantic uncertainty or persisted success.
- Preserve exact paired traffic, source evidence and approval identity. New
  caches must have explicit ownership and resource bounds; deterministic native
  sequences are not parallelized with goroutines.
- Separate structural changes, behavior corrections and measured optimization.
  Regressions exercise public outcomes, failure recovery and independent oracles.
  Run root race/vet and the separately pinned optional adapter before delivery.

## Module review completion

All modules in the plan were reviewed. The seven native reviews retained their
existing grammar and renderer limitations. ASA literal indexing, Fortinet/Huawei/
Netscreen accepted-delta state, shared parser limits and cancellation propagation
were changed; other reviewed native behavior already met the contract.

Risk, reclamation and policy migration needed naming/contract integration rather
than semantic expansion. New lifecycle benchmarks cover convergence, declared and
effective risk and shared-group member usage. Whole-rulebase proof still applies
to each convergence candidate. Native NAT/schedule migration, broader firmware
support and real-device verification remain the explicitly documented backlog.

See [benchmark evidence](benchmarks.md) and [verification](verification.md) for
measured results and the distinction between local, remote CI and real-device proof.

## Boundary contract migration

The [boundary plan](plans/2026-10-29-boundary-contracts.md) keeps Render and lifecycle
method signatures. Direct native rendering now validates the complete declared
configuration delta, identity and completeness. Custom renderers must wrap
`plan.ErrRender` for unsupported representations if Planner should try another
candidate; all other renderer errors propagate. `plan.ValidateChanges` is available
to custom implementations. Preserve rejects unlisted deltas even for empty changes.

Snapshot callers should classify invalid arguments with `snapshot.ErrInvalid`;
`ErrFormat` describes persisted/decoded corruption, and lower I/O causes are
preserved. Journal callers distinguish `deploy.ErrJournalFormat` from operation
conflict. Empty roots and zero/nil store handles are invalid. These are error
contract changes, not a snapshot/journal format migration; existing semantic-v9
snapshots and operation receipts remain readable.

Usage analysis now applies the MaxVisits budget to observations and traversal,
so hosts submitting large evidence batches must set an adequate explicit limit.
Both evidence lists require a valid request window when present. Rule and member
analyses retain their distinct evidence and deletion-authority semantics.

## Cancellable scanner migration

`config.NewCursor(ctx, source, limits)` and
`config.NewFragmentCursor(ctx, source, spans, limits)` replace the signatures
without context. Pass the caller's context; `NewSession` is unchanged. Empty or
malformed input still observes an already canceled context first. Scanning checks
cancellation during bounded byte chunks and before returning success. XML also
checks between decoder calls; standard-library token decoding is not interruptible
inside an individual call. Structural scans return no partial document on error.

Nil cursors, classifiers and `ParseFunc` callbacks, and invalid stage declarations
use `config.ErrInvalid`. Malformed source retains `ErrSource`; invalid claims and
closed transactions retain `ErrClaim` and `ErrClosed`. These changes preserve exact
source spans, declaration order, staged interpretation and atomic rollback.

For bounded materialization, `Firewall.RecordCount()` counts top-level domain and
evidence records, `flow.AddressSet.RangeCount()` counts normalized address intervals and
`flow.Traffic.RegionCount()` counts disjoint traffic regions. Candidate object traversal now
shares the planner's visit allowance, so large catalogs may require a higher
explicit `MaxVisits` even when few rules participate in the requested change.

## Policy algorithm domain names

This is a deliberate Go API break, without compatibility aliases. Native fixtures,
CLI JSON fields and semantic snapshot format 9 remain unchanged. A frozen snapshot
from `bc15a8b` checks decoding and its original semantic digest.

| Previous API | Current API |
| --- | --- |
| `flow.Range` | `flow.AddressRange` |
| `flow.Set`, `flow.NewSet` | `flow.AddressSet`, `flow.NewAddressSet` |
| `flow.Box`, `Traffic.Boxes()`, `flow.ErrBox` | `flow.TrafficRegion`, `Traffic.Regions()`, `flow.ErrRegion` |
| `policy.Trace`, `Result.Trace` | `policy.RuleDecision`, `Result.Decisions` |
| `Trace.Certain` | `RuleDecision.Known` |
| `Reclamation.Redundant` | `Reclamation.Unreachable` |
| `Reclamation.Removable` | `Reclamation.RemovalCandidate` |

`Unreachable` includes rules with empty match domains and rules whose possible
traffic has already been consumed. `RemovalCandidate` is input to a selected
batch proof, not deletion authorization. `MemberUsage.Removable` was removed:
member observations report usage and cannot establish paired-flow preservation.

`RuleDecision.Known` now includes action validity. Unknown actions retain unknown
coverage and cannot produce a known decision. Shared `flow.AllTraffic` and
`Traffic.Equal` replace duplicate universes and equality helpers without changing
comparison direction or budgets.
