# Cross-vendor business contracts

Palo Alto, SRX, Huawei, Hillstone, Fortinet, Netscreen and ASA share the contracts
below. Native syntax, ordering, packet views and persistence evidence belong to
their adapters. The host owns inventory, credentials, authorization and database
projection. No single vendor interface combines all these responsibilities.

| Boundary | Contract | Meaning of success |
| --- | --- | --- |
| Native selection | `vendors.Parser.Parse`, `vendors.Renderer` | One of the seven enabled implementations, with the selected native context retained |
| Configuration | `Parse(ctx, config.Source, firemon.Metadata)` | A sealed graph; `Complete()` additionally requires complete capture and established semantics |
| Domain | Concrete immutable objects, `Record()` copies, typed reference accessors | Shared graph identity without mutable container aliases |
| Policy | `policy.Engine.Query`, `Match`, `QueryNAT`, `QueryPacket` | Exact known partitions; unresolved traffic remains `Unknown`, independent of transport success |
| Design | `plan.Planner.Plan`, `Transfer`, `Preserve` | Renderable target and outside-traffic proof, with preserved translation behavior |
| Readback | `Plan.VerifyBaseline`, `Plan.Verify` | Independent parsed native configuration establishes the approved baseline/result |
| Lifecycle | `RiskAnalyzer.Assess`, `Converger.Candidates`, `Translator.Plan`, `Reclaimer.AnalyzeMembers` | Versioned findings or proven plans; findings alone never authorize changes |
| Device | `deploy.Factory.Open`, `Session` | Fresh session, explicit configuration isolation, bounded capture/execution/persistence and closure |
| Publication | Snapshot CAS and durable operation reservation | Complete current state or explicitly unavailable state, never silent stale success |

The policy package selects a private native semantic strategy once at each
entry boundary. The strategy supplies policy/NAT/packet evaluation, native
transform details, activation and ordering. Planning consumes semantic methods;
it does not decide behavior by vendor name. Native parser and renderer selection
is shared by the CLI and embedded operations.

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
outside the policy-only translator's supported contract.

## Lifecycle evidence

Migration maps `Chain{Scope, RuleSet}` independently from zones. A unique selected
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

Every session implements configuration begin/end, read, execute, save and close.
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
