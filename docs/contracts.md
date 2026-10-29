# Cross-vendor business contracts

Palo Alto, SRX, Huawei, Hillstone, Fortinet, Netscreen and ASA share the contracts
below. Native syntax, ordering, packet views and persistence evidence belong to
their adapters. The host owns inventory, credentials, authorization and database
projection. No single vendor interface combines all these responsibilities.

| Boundary | Contract | Meaning of success |
| --- | --- | --- |
| Native selection | `vendors.Parser.Parse`, `vendors.Renderer` | One of the seven enabled implementations, with the selected native context retained |
| Configuration | `config.Parser.Parse(ctx, config.Source, firemon.Metadata)` | A sealed graph; `Complete()` additionally requires complete capture and established semantics |
| Domain | Concrete immutable objects, scalar behavior, `Record()` copies, typed references | Shared graph identity without mutable container aliases |
| Policy | `policy.Engine.Query`, `Match`, `QueryNAT`, `QueryPacket`, `ResolveRoutes` | Exact known partitions; unresolved traffic remains `Unknown`, independent of transport success |
| Design | `plan.Planner.Plan`, `Transfer`, `Preserve` | Renderable target and outside-traffic proof, with preserved translation behavior |
| Readback | `Plan.VerifyBaseline`, `Plan.Verify` | Independent parsed native configuration establishes the approved baseline/result |
| Lifecycle | `RiskAnalyzer.Analyze`, `Converger.Candidates`, `PolicyMigrator.Plan`, `Reclaimer.AnalyzeMembers` | Versioned findings or proven plans; findings alone never authorize changes |
| Collection | `operations.ReadOnlyFactory.OpenReadOnly`, `device.Reader` | Fresh owned reader with `Read` and `Close`, independent of deployment dependencies |
| Deployment | `deploy.Factory.Open`, `deploy.Session` | Fresh session, explicit configuration isolation, bounded capture/execution/persistence and closure |
| Publication | Snapshot CAS and durable operation reservation | Complete current state or explicitly unavailable state, never silent stale success |

The policy package selects a private native semantic strategy once at each
entry boundary. The strategy supplies policy/NAT/packet evaluation, native
transform details, activation and ordering. Planning consumes semantic methods;
it does not decide behavior by vendor name. Native parser and renderer selection
is shared by the CLI and embedded operations.

## Parser and evaluation ownership

`config.NewSession` rejects a nil cursor and returns `(*Session, error)`. The
session retains that cursor privately and exposes it with `Cursor()`. A commit
accepts only a transaction from that cursor; a rejected foreign transaction stays
usable by its owner. Closed commits return `config.ErrClosed`; invalid ownership
returns `config.ErrClaim`. Invalid session input returns `config.ErrInvalid`.
Stages retain dependency order and atomic draft/evidence rollback.

`policy.RuleChain` names the native chain and its zone pair; it replaces an opaque
array only in evaluation state. `Request.SameContext` normalizes omitted security
rule sets and compares time by instant. `Engine.ResolveRoutes` uses `Limits.Rules`
for selected-VRF candidates and `Limits.Regions` for output partitions. Sorting
preserves native ties and checks cancellation between bounded chunks and merges.
Invalid inputs, cancellation and exhausted budgets remain errors; unsupported
semantics remain unknown. The evaluation/planning and application boundaries
check cancellation before validation. Inventory/projection invalid dependencies
use their own `ErrInvalid`; malformed stored evidence remains `snapshot.ErrFormat`.

## Object identity and translation proof

`AddressRecord.VIP` is a typed `NATRef` to either `StaticNAT` or `DynamicNAT`.
`StaticNATRecord.SourceVIP` identifies its source VIP address. Scope always means
the native namespace; names and ID prefixes do not establish relationships.
Invalid explicit references retain diagnostics. Snapshot semantic format 9
persists these relationships and rejects older formats; reimport the original
capture into a new store.

Before upgrading an existing store, finish pending device recovery with the
previous binary and retain its journal/snapshots. Reimporting a capture does not
transfer an old operation's write receipts or reservation into the new format.

Policy-owned SNAT can disappear when an ordinary permit is inserted before its
owner. `Engine.PreserveNAT` therefore checks existing NAT dependencies, active
references and effective native translation partitions, including the intended
target traffic. Disjoint changes can pass. Query and readback invoke the same
semantics, and readback reruns the proof. Native NAT creation/migration remains
outside the policy-only migrator's supported contract.

## Lifecycle evidence

Reusable services retain their planner and configured limits. `ReclamationRequest`
provides the current time, revision, observation window and rule/member evidence
for each `Reclaimer` call. `MigrationRequest` provides time, zone/chain mappings,
pairs and selected rules for `PolicyMigrator.Plan`. `Converger.Candidates` and
`Plan` receive the proof start time per call. Inputs are read without retention or
mutation; callers must not mutate them while a call is in progress.

`Schedule.ActiveAt` and `ExpiredAt` return `(value, known)`. Absolute windows are
half-open; recurrence, unsupported declarations, missing windows or absent time
remain unknown. Unknown activity stays possibly active; unknown expiry never
authorizes removal. `HasUnsupported` describes local unmodeled declarations,
not graph completeness or successful reference resolution.

Migration maps `firemon.PolicyChain{Scope, RuleSet}` independently from zones. A unique selected
security chain may be inferred. ACL or ambiguous targets require explicit chain
mapping. An explicitly empty destination-zone mapping, together with an explicit
chain mapping, represents an ingress-only target ACL; a missing map key is an
error. Source action and logging semantics remain part of the proof.

Compound audit definitions contain typed source, destination and service
predicates combined with `All` or `Any`. Relations are intersects, contains,
within, equal and not equal. Services retain protocol/port/ICMP tuples. Unknown
dimensions use three-valued logic; partial evidence does not become unrestricted
traffic. Existing paired-traffic definitions retain their contract.

Member observations bind rule identity, member role/kind/ID, revision, graph
digest, source and contiguous time window. Results retain nested group paths.
Rule totals cannot establish individual member usage. Missing/reset/stale or
out-of-window evidence remains unknown, and member non-use does not prove safe
removal. Convergence discovery returns deterministic bounded candidates; every
candidate needs the same whole-rulebase proof as explicit convergence. Separate
candidate plans must not be concatenated without a new combined proof.

## Session and application ownership

A `device.Reader` implements only `Read(ctx, device.View)` and `Close()`.
`device.Capture` retains the source and metadata. `device.Running` and
`device.Saved` select the view. The connector adapter returns a fresh reader from
`OpenReadOnly`; opening it does not enter configuration mode.

A `deploy.Session` embeds `device.Reader` and additionally implements
configuration begin/end, execute and save.
Host-defined session implementations must add `BeginConfiguration` and
`EndConfiguration`; no-op implementations are valid only for native devices
whose edits immediately affect running state and require no candidate isolation.
The deployment engine authorizes the exact operation, device, baseline revision
and plan digest before reservation or session creation. It then journals an opaque
ownership token before acquiring isolation and captures and verifies its fresh
baseline only afterward. Immediate-running devices
explicitly implement the isolation lifecycle without a native candidate lock.
PAN uses an owned configuration lock and requires a dedicated automation admin;
Junos uses exclusive configuration mode. Fortinet verifies automatic persistence and the selected existing VDOM before baseline or policy writes. Close releases transport resources and
is not proof of administrative lock cleanup. Recovery verifies ownership and
state independently without replaying configuration or save commands.

Failed running captures retain the received bounded source as incomplete
evidence. Deployment keeps its reservation and publishes that observation even
when cancellation requires a separate bounded local persistence context; recovery
uses a new session and never replays the failed operation. Collector retries use
the existing publication ID instead of reconnecting.

`operations.NewCollector`, `operations.NewDesigner` and `deploy.New` validate
option structs once and keep dependencies private. Typed-nil dependencies and
negative bounds are invalid. Zero timeout retains the five-minute default.
`operations.New` returns a runtime exposing `Collect`, `Design`, `Apply` and
`Recover`; it does not expose replaceable components. A standalone collector
requires only a capture store, read-only factory and `config.Parser`, without a
journal, authorizer or write-capable session.

`operations.Collector` collects running configuration and publishes with live CAS
semantics; partial evidence invalidates stale current state. `Designer` loads a
current revision and returns a plan bound to that revision. `Runtime` composes
these use cases with the existing deployment engine and host dependencies.
Algorithms remain reusable directly; the runtime does not duplicate the graph,
analysis or authorization layers.

Tests establish supported fixture and transcript behavior. New native syntax or
firmware behavior requires evidence and a regression at its owning boundary;
unsupported cases continue to return unknown/error. Live-device compatibility is
separate from offline, synthetic transcript and CI evidence.

## Native rendering boundary

`plan.ValidateChanges` validates a complete before/after delta without granting
traffic or device-write authority. Every native `Renderer.Render` calls it even
when used outside a planner. Device, vendor, software, parser version and selected
context must agree. Every rule addition, member addition and removal must be
listed exactly once; shared declarations and unrelated catalogs cannot change.
Only referenced new address/service declarations are accepted. Native relative
order is preserved across source position renumbering. Successful no-op rendering
returns no commands; failed rendering never returns a partial script.

Cancellation precedes validation. Invalid deltas use `plan.ErrInvalid`, incomplete
graphs use `plan.ErrUnsafe`, and unsupported native expressions use `plan.ErrRender`.
Vendor-specific rendering errors wrap the common sentinel. A custom renderer must
use that sentinel for a retryable representation rejection: Planner propagates all
other errors instead of silently trying another candidate. Preserve also validates
an empty change list. Native creation supports front insertion (ASA supports ACL
line placement); an unsupported destination position is rejected, never guessed.

Rule and member usage share request validation and an identity-indexed interval
assessment. An observation's identity, revision, digest and nonempty source must
match before it contributes evidence. Positive hits wholly inside the requested
window override uncertain zero counts. Invalid/reset/incomplete or boundary-spanning
hit evidence cannot establish non-use. Only continuous complete zero-hit coverage
establishes non-use, which still does not authorize deletion.

Each call charges its consumed observation list and rule/member traversal against
`Engine.Limits.Rules` (default 100000); rule analysis also charges every rule in
each policy context and its result pass. Both request lists require a window if
present, although each analysis consumes only its own evidence. Budget exhaustion
and cancellation return no partial results. Interval sorting uses bounded chunks
and cancellable merges. Request data is neither retained nor mutated.

## Persistence input and failure contracts

Snapshot codec/store invalid inputs use `snapshot.ErrInvalid`; stored envelope,
graph or manifest corruption uses `snapshot.ErrFormat`. Revision mismatches remain
`ErrConflict`, ownership mismatches remain `ErrReserved`, and a well-formed missing
revision remains `ErrNotFound`. Empty store/journal roots and nil/zero store handles
are invalid. Context cancellation precedes argument validation and file access.

Snapshot encoding detects short header/body writes with `io.ErrShortWrite` and
does not continue after failure. Decoding retains underlying I/O errors through
`errors.Is` while classifying corrupt/truncated input as `ErrFormat`. Typed-nil
readers/writers are rejected before invocation. The envelope and semantic version
remain unchanged.

Journal corruption or unsupported encoding uses `deploy.ErrJournalFormat`;
invalid inputs use `deploy.ErrInvalid`, while lease ownership, closed leases and
sequence conflicts remain `deploy.ErrJournalConflict`. Corrupt journals are never
replaced by a fresh operation. These classifications do not release reservations,
change write receipts, or permit replay during recovery.

Rendering also verifies native namespace identity: a new rule or declaration
cannot reuse a native name that targets a different existing object. Global
object declarations must retain the identity reconstructed by the native parser;
scoped adapters validate their own native identity scheme. Empty selectors are
rejected when no native empty representation exists; wildcard selectors are
explicit. Position ties use the graph's position-plus-ID order for creation and
surviving-rule insertion anchors. Unreferenced supported inline values remain
semantically inert and never become standalone native declarations.
