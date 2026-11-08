# Domain refactoring and API migration

## Candidate search ownership

`Planner.Plan` and `Planner.PlanBatch` share a private candidate-search module.
It owns rule eligibility, append construction, outside-target preflight, cost
ordering, attempt limits and lazy creation. Two internal adapters retain the
entry points' different rule-scan accounting, declaration refusals, proof and
reporting contracts. Batch attempts remain shared across groups and singleton
retries; rejected drafts do not reserve names or modify accepted changes.

Public methods, `MaxCandidates`, snapshot format 9, approval digests and
reconstruction encodings are unchanged. Existing proofs still run independently
for candidates and readback. The module does not merge access and batch intent
or cache a baseline across different immutable graphs.

The business reference remains Perl `Firewall/Policy/Searcher.pm`,
`selectAModifyPolicy`, and its caller in `searchPolicy`: member additions affect
candidate cost. Go retains deterministic cost ordering, exact paired traffic,
first-match ownership and outside-target/NAT proofs rather than adopting Perl
hash iteration or independent source/destination/service sets.

## Connector v0.2.0

The optional adapter now uses published go-net-connector v0.2.0 and go-expect
v0.4.0. Its Firemon factory/session methods remain unchanged. Hosts that directly
customize the returned `connector.Profile` must use `expect.Pattern` for prompts
and pagers; authentication and command-error expressions remain
`[]*regexp.Regexp`. Built-in profiles come from
`vendors.NewBuiltinRegistry().Lookup(key)` and `Platform.Profile()`.

Operation callbacks receive the operation's context. Step and attempt text is
read through `Response()` with explicit decoding errors; `op.Prompt()` also
returns an error. Raw responses continue to determine response digests, byte
limits and persistence failure history. Failed configuration reads retain
matching bounded evidence even if decoding fails. PAN/SRX configuration
isolation, Fortinet VDOM selection and no-replay recovery remain unchanged.

The adapter stays a separate module and uses a published core version without a
local `replace`. CI distinguishes that versioned consumer from a temporary
workspace pairing it with the checked-out core. See
[integration verification](integration-verification.md) for the versions and
evidence; older private-dependency delivery records describe their own dates.

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

The subsequent [configuration parser audit](parser-design.md) traces the actual
Perl Content and Parser implementations, records native vendor differences, and
implements the Content/Builder rewrite across all seven vendors, retaining the
preceding Hillstone object-reopening and source-evidence corrections.

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
| `session := config.NewSession(cursor, metadata)` | `builder, err := config.NewBuilder(content, metadata)`; access `builder.Content()` |
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

Native entry points are `Parser.Parse`; package-level `Parse` and `ParseVDOM`
were removed in the 2026-11-07 development cleanup. Fortinet uses
`Metadata.Context`, defaulting to root. XML and CLI input obey the same
configured limits. `config.DefaultMaxBytes` names the existing
16 MiB source ceiling; cumulative transport output is a distinct adapter limit.

`Rules()` retains source declaration order. `OrderedRules()` is an `iter.Seq`
that visits shared immutable objects by native position then stable ID without
exposing the backing index. Collection getters and `Record`/`Export` still copy
mutable containers. Query memoization is invocation-local, graph-bound and
weight-bounded; cache hits charge the original traversal budget. Time, routing,
VIP selection and decisions are not cached.

## Historical compatibility and execution invariants

The following format-9 compatibility statements describe the earlier refactor.
The [2026-11-07 implementation](2026-11-07-domain-improvements.md) supersedes them
with snapshot 10, reconstruction 2 and approval 4, removes parser/application
forwarding APIs and replaces old approval golden bytes with behavior tests.

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

`config.NewContent(ctx, source, limits)` and
`config.NewFragmentContent(ctx, source, spans, limits)` own native source evidence.
`NewBuilder(content, metadata)` replaces Session; `Builder.Begin` replaces
`Cursor.Begin`, and `Builder.Commit` validates records and evidence together.
`Builder.Phase(ctx, name, callback)` replaces Stage dependency declarations;
native entry points now express phase order directly. `Builder.Seal` replaces
`Seal(session.Data())`, avoiding a second whole-graph copy. `XMLDocument.Content`
replaces its Cursor field; XML node navigation and the XML function are unchanged.
These low-level APIs deliberately have no compatibility aliases. Parser, Source
and Limits retain their responsibilities; the current domain continuation uses
`Parser.Parse` and snapshot semantic format 10.

Empty or malformed input observes an already canceled context first. Scanning
checks cancellation during bounded byte chunks and before success. XML checks
between decoder calls; standard-library token decoding is not interruptible
inside an individual call. Structural errors return no partial document.
Invalid inputs retain ErrInvalid; malformed source, invalid claims and closed
transactions retain ErrSource, ErrClaim and ErrClosed respectively.

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

## Go 1.27 business module update

The core and optional connector module now require Go 1.27. CI checks the
minimum 1.27.0 and current 1.27.x in three configurations: core, separately pinned
adapter, and adapter paired with the checked-out core. The dependency pin is
unchanged; the paired check does not claim that unpublished core changes are
available to independent consumers. See [verification](2026-11-07-go127-verification.md).

### Public interface and behavior migration

| Interface | Contract |
| --- | --- |
| `config.Limits.MaxServiceTerms` | Total `ServiceRecord.Terms` in the accepted catalog; zero or negative uses `config.DefaultMaxServiceTerms` (100,000). Applies to all seven parsers. |
| `Content.Limits()` | Returns normalized parser limits by value. |
| `deploy.Result.Terminal()` | True for durably confirmed Published or Aborted. Inspect both result and error; session/lease close failures do not undo completion. |
| `operations.CollectResult.Published()` | Confirms publication independently of completeness and capture/close errors. Batch collection retains complete/incomplete status with its error. |
| `snapshot.ErrLimit` | A manifest exceeds the 128 MiB persistence limit. An already stored oversized manifest also matches `snapshot.ErrFormat`. |
| `Firewall.DeclaredRules()` | Visits shared immutable rules in source declaration order without allocating a rule slice; supports early stop. `OrderedRules()` retains native evaluation order and `Rules()` retains its owned slice. |
| `policy.Engine.NATContexts` / `ProveNATEffects` | Requested and derived times must support the existing `time.Time` JSON encoding, or fail with `policy.ErrInvalid`. Zero time remains valid outside the existing nonzero Window-start requirement. |

Service-term capacity counts builtins, repeated terms and terms retained on
unsupported records. It is a catalog capacity, not a cumulative work budget.
Replacement can release capacity. Each transaction bounds its pending new data
before cloning, then checks the final accepted size after replacements. Failed
or canceled phases restore both records and source evidence with the capacity
count. PAN also checks source/destination port products before allocation;
cancellation and capacity errors propagate instead of becoming unsupported
syntax or unrestricted traffic.

Deployment failure after observing running state retains that evidence through
a separate five-second local finalization context. Device operations still use
the caller's context. Uncertain evidence retains the reservation and recovery
never retries device writes. A Reserve error may occur after installation, so it
requires independent recovery rather than an assumed Aborted result. A known
Aborted journal record is terminal on retry, including after authorization refusal.
If an independent manifest has no reservation and the journal has neither a
configuration token nor write intent, recovery can abort even if a concurrent
publication advanced the head. A configuration token keeps that case pending.

Manifest size is checked before atomic replacement. The old manifest remains
unchanged after rejection, including its head, generation, reservation and
outbox. This bounds committed documents; JSON encoding itself still buffers the
value. Existing immutable blobs are compared in bounded chunks through real EOF.

### Business modules

`targetBatch` owns discovery, per-device planning and final report projection via
`resolve`, `plan` and `finish`. One target entry holds provenance, outcome,
planning input and packet/alias/lifetime proof. Device work references entries;
there is no mutable intermediate report or slice-length protocol to synchronize.
Unsupported outcomes keep their original positions, and fatal errors remove all
plans while preserving partial discovery. Business and topology sources retain
order and duplicates; topology sources do not enter native approval material.

`vendors/internal/render.NativeBuilder` validates a native delta once per render
and records typed owners, generated declarations and policy attachments. Claims
must name an actual new owner and an actual Match or typed VIP relationship.
Shared literals allow multiple owners; policy attachments require their new
DynamicNAT owner and reject duplicates. Prepared batches own changes, commands,
attachments and clock. Adapters retain their native syntax and order, including
ASA derived NAT order, StoneOS ordering, SRX pools and schedule prefixes.

The source references were `Firewall/Policy/Designer.pm:161-272`,
`Firewall/Policy/Designer/Fortinet.pm:198` and
`Firewall/Policy/Designer/Netscreen.pm:169` under the local Perl backend. They
establish device-grouped provenance and syntax-generated declaration ownership.
Go retains exact paired traffic, typed NAT, unknown conditions and independent
change/readback proof rather than reproducing dynamic dispatch or dimension-wise
merging. No Perl source is included in the Go module.

### CLI migration

Existing command names, flags and successful JSON fields/encoding are preserved.
`firemon --help`, `firemon -h` and command help list the actual supported commands
and flags on stdout. Errors go to stderr once. Output errors, including short
writes, are returned; bounded reports still encode completely before writing.
Input readers check cancellation between reads, and connected pipe reads are
interruptible, including stdin. A blocked ordinary filesystem syscall is still
subject to the operating system's behavior.
Pipes must have a connected producer; an empty FIFO is rejected without waiting
indefinitely for a writer. File open/read/close errors remain runtime failures.

| Exit code | Meaning |
| --- | --- |
| 0 | Successful command or help |
| 1 | Execution, storage or output failure |
| 2 | Invalid command, flags, arguments or input document |
| 130 | Interrupted with SIGINT or a canceled calling context |
| 143 | Interrupted with SIGTERM |

Scripts that previously treated every error as exit 1 should accept any nonzero
status, or distinguish usage from runtime failure. A deadline remains a runtime
failure. Existing CLI work ceilings remain separate from library defaults.

Snapshot semantic format 9, manifest/journal layouts, request and reconstruction
formats remain unchanged. Native command and approval fixtures pin valid inputs;
legal time offsets and raw empty rule-set names retain their previous proof
identities and sorting. JSON v2 interfaces, nil/empty changes and fixed random
samples were not migrated. Mechanical changes use selected standard-library
fixers; direct-local candidate rejection checks retain their original meaning.
