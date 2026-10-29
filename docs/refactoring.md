# Domain refactoring and API migration

This iteration implements the [approved module review plan](plans/2026-10-29-domain-refactor.md).
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
| Policy::Cleaner::Flagger | Reclaimer retains revision, graph, time-window and rule/member evidence. Missing logs and zero counters alone do not authorize removal. |
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
| `policy.Addresses(fw, refs, any)` | `engine.ResolveAddresses(ctx, fw, refs, any)` returning `(flow.Set, bool, error)` |
| `policy.Services(fw, refs, any)` | `engine.ResolveServices(ctx, fw, refs, any)` returning `([]firemon.ServiceTerm, bool, error)` |
| Scalar reads through `Record()` | `ID()`, `Name()`, `Scope()`; rules also expose `Position()` and `Chain()` |
| Different rule/NAT relationship views | `Rule.Match()`, `StaticNAT.Match()`, `DynamicNAT.Match()` return `MatchObjects` |
| Fixed parser limits | `vendors.Parser{Limits: config.Limits{...}}`, or the same `Parser` shape in each native package |
| Concrete store arguments for inventory/projection | `inventory.ManifestReader`, `inventory.RevisionLoader`, `projection.Outbox` |

The old lifecycle type names and error-hiding resolver functions are removed.
`known=false, err=nil` means declarations cannot be fully interpreted. A canceled
context, exhausted budget or invalid graph is an execution error and must be
propagated. Resolvers use `Engine.Limits.Combinations`; they never invent a
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
Native fixture exports and semantic digests were compared to e9e9b96; reuse,
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
