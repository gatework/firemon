# Cross-vendor business contracts

## Layered computation limits

`policy.Limits.WithDefaults()` resolves `MaxRegions`, `MaxVisits` and
`MaxCombinations` once at an algorithm boundary. Nonpositive values retain the
defaults 4096, 100000 and 4096. Each analysis or planning algorithm accumulates
visits across its own passes, contexts and private proof helpers. Delegated
public policy queries and equivalence proofs independently receive the same
maxima; this is not a global deadline or a shared whole-operation work quota.
Candidate and pair-comparison limits are separate from visits.

Graph collection counts are charged before copied views are materialized.
Context enumeration charges rules, zones, schedules and each absolute window;
risk findings remain bounded even when incomplete evidence returns unknown.
Planning algebra and independent readback use the configured region limit,
including the two-region IPv4/IPv6 universe. Budget/cancellation failure returns
no partial rows or plan. Stricter accounting can reject a previously accepted
low-budget request; raising an explicit limit does not bypass semantic proof.

Lifecycle graph preparation follows the same rule: equivalence and NAT proofs,
convergence, reclamation, preservation and readback charge `RecordCount()` before
exporting each owned configuration view. A graph materialization includes its
normalization; explicit identity scans and private proof passes also accumulate
visits. NAT activation uses the enclosing proof's remaining visits. Dynamic NAT
owner indexes are charged and built once per equivalence proof, then reused
across all zone/time contexts; effect partitioning charges each decision. The scalar
`StaticNATCount()` and `DynamicNATCount()` checks avoid allocating views merely to
detect an empty translation catalog. Standalone `ValidateChanges` remains a
semantic validator; bounded planning charges its graph inputs before calling it.

Every plan creation path, including an already-covered request or unchanged
preservation, preflights minimum normal-readback capacity before rendering.
Baseline verification needs two baseline views; result verification needs a
baseline view, an expected-result view and an observed-result view. This check
does not spend current-operation visits and does not guarantee actual readback
success: changed captures and later proof work still consume runtime budgets.
Insufficient minimum capacity returns `policy.ErrBudget`; increase `MaxVisits`
and replan. Snapshot format and public method signatures are unchanged.

`RequestOptimizer` checks each input's `RegionCount()` before grouping or copying.
`MaxRegions` bounds input and intermediate traffic, even when fixed-point
coalescing could reduce the final result below the cap. Packed and split inputs
cannot bypass this check; oversized traffic returns `flow.ErrBudget` with no
partial groups. Exact traffic pairing and the comparison budget are unchanged.

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
rule sets and compares time by instant. `Engine.ResolveRoutes` uses `Limits.MaxVisits`
for selected-VRF candidates and `Limits.MaxRegions` for output partitions. Sorting
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
`Engine.Limits.MaxVisits` (default 100000); rule analysis also charges every rule in
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

## Risk preparation and scanning

Compound risk standards are compiled once per analysis call. `MaxRegions` bounds
the aggregate normalized regions retained across all predicate leaves, as well as
each algebra operation. `MaxCombinations` independently bounds validation nodes
and evaluated nodes across rules. Short circuit order is unchanged; cached
per-rule dimension projections do not refund node visits. Service comparisons
retain protocol/port/ICMP pairing. No state or caller-owned input is cached across
calls, so an analyzer can be reused concurrently with immutable inputs.

Cursor constructors take the caller context. UTF-8 validation, line/fragment
indexing and statement scanning check cancellation in bounded byte chunks;
XML checks between decoder calls and byte-span scans. Cancellation precedes
entry validation, and errors return no partial cursor/document. Stages validate
all names and dependencies before running any callback; failed or canceled stages
restore their data, source claims and cursor position. `NewSession` remains a
synchronous constructor with the same signature.

Candidate construction shares the planner's counter through object-catalog,
visibility and collision scans. `Firewall.RecordCount()` counts top-level domain
and source-evidence records before candidate graph export; it is a visit unit,
not a byte or nested-member count. `flow.AddressSet.RangeCount()` and
`flow.Traffic.RegionCount()` permit rejection of oversized standards and transfer
partitions before copied views are created. Native source-size limits and region
limits retain their separate meanings; visits are not a peak-memory guarantee.

## Ordered policy decisions and reclamation evidence

`policy.Result.Decisions` contains `RuleDecision` entries for traffic consumed by
each native rule. `Known` requires a resolved match, an established active schedule
and a valid action. Unknown actions still consume possible matching traffic and
produce unknown coverage; a later permit cannot establish that traffic as allowed.

`flow.AddressRange`, `AddressSet` and `TrafficRegion` name the domain directly.
`flow.AllTraffic` owns the two-family universe used by query and lifecycle proofs.
`Traffic.Equal` checks receiver-minus-other first, then the reverse, retaining
short-circuit and region-budget errors. Empty traffic is a valid set, not a reason
to bypass an invalid budget.

Reclamation keeps `Disabled`, `Expired`, `Unreachable` and `Unused` independent.
`RemovalCandidate` selects a rule for a whole-batch preservation proof; it does not
make member counters or absent logs a removal authorization. Empty declarations
can be unreachable without an earlier shadowing rule. Future absolute schedule
boundaries and NAT-owning rules still participate in proof. Member usage has no
removal flag.

## Candidate coverage, identity and attempt limits

`Planner.Plan` reuses existing effective coverage, then considers single-rule
member additions, then exact new rules. Service additions compare the union of
complete protocol/source-port/destination-port/ICMP-type/ICMP-code tuples. Members
already covered by that union add neither a reference nor a cost. Partial coverage
still adds the requested whole term. `internal/servicecoverage` shares this
projection with service risk predicates; protocol zero remains a concrete protocol.
Risk relation direction, empty exposure and unknown evidence semantics are unchanged.

`MaxCandidates` now bounds full proof/render attempts (default 128), rather than
the total number of viable alternatives discovered. Discovery still scans all
eligible rules within `Engine.Limits.MaxVisits`; a bounded max heap retains only
the cheapest N append drafts. Full proofs run in the established lexicographic
`Cost` order. A rejected prefilter consumes visits but not an attempt. Proof or
`ErrRender` rejection consumes an attempt. Creation is built only after append
alternatives fail and an attempt remains. Remaining untried alternatives at the
limit yield `policy.ErrBudget`, never a partial plan; complete unsuccessful search
yields `plan.ErrUnsafe`. Cancellation, region/visit budgets and fatal renderer
errors still propagate. `Transfer` has no candidate search and does not consume
this cap. Optimality is within the generated single-rule candidate space, not a
claim of globally minimal multi-rule or object-member combinations.

A candidate owns its name reservations, including pending declarations. Allocation
keeps existing unoccupied hash names and probes successive `-new` suffixes until
both graph identity and native name are available. Global address/service names
also avoid local object/group names across scopes, because native lookup can
shadow global names. Indexing, probes and reservations consume the same candidate
visit allowance. Plan and Transfer use this allocation contract.

`internal/nativename` supplies the actual namespace keys used by independent native
renderer validation: ASA separates objects from groups, Fortinet resolves the
selected context, and named rules retain their native chain. PAN, SRX and Huawei
reject creation that aliases an existing rule name even when graph IDs differ.
Numeric native rule allocation remains renderer-owned. Existing valid cross-scope
names remain loadable; this change does not add a blanket name restriction to Seal.
The public DTOs, snapshot v9 format, CLI JSON and Renderer signature are unchanged.

All three planning entries (`Plan`, `Transfer`, `Preserve`) pass detached nested
change slices to Render and own copies of returned commands. A renderer retaining
its arguments cannot alter a sealed plan or its approved digest. Cancellation
checked after rendering rejects commands even when the renderer returns nil error.

## Lifecycle candidate refusal and operational failure

`plan.RejectionError` carries a `RejectionStage` and underlying `Err`. Declaration,
preservation and representation stages identify incompatible declarations,
failed whole-rulebase equivalence and unsupported native commands respectively.
`Error` and `Unwrap` retain diagnostic text and `errors.Is` compatibility;
`errors.As` retrieves stage information. Native renderers still use `ErrRender`
as their explicit representation-refusal contract.

Convergence enumeration retains only refusals produced by the current attempt.
It checks the direct top-level type, never a nested diagnostic found by
`errors.As`. Preserve adds ordinary operation context to unexpected renderer
errors, so a renderer returning or wrapping `RejectionError` remains fatal even
when its cause is `ErrRender`. Both access-request and convergence candidates
prioritize cancellation and region/visit budget errors over representation
refusal. Unknown renderer errors and invalid dependencies stop enumeration with
no partial rows or plan. Empty native commands are an expected representation
refusal. Existing attempt limits and deterministic candidate order are unchanged.
