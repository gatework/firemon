# Firemon Go specification

Authority: approved design from the planning conversation, with the user's subsequent correction: firewall objects include **StaticNAT and DynamicNAT**, not a unified NATRule.

## Domain and ownership

A firewall owns a concrete immutable graph: Interface, Route, Zone, Address, AddressGroup, Service, ServiceGroup, Schedule, Rule, RuleBinding, StaticNAT, DynamicNAT, NATPool, context and evidence. Construction uses mutable DTO drafts; sealing validates and resolves typed IDs in two passes. Shared references retain pointer identity after snapshot restoration. Readers receive copies of mutable containers. Ordered slices describe execution; maps are indexes only. Unknown, any and empty are distinct. Protocol zero is a protocol, not a wildcard. Native NAT order may interleave both object types and may have multiple native stages.

StaticNAT retains explicit fixed mappings, original match context, direction, zones/interfaces/VRF, ports, stage/order and evidence. DynamicNAT retains original match conditions, pools/interface allocation, source/destination modes, exemption and native order. Do not infer mapping semantics from equal address counts or classify every policy-shaped NAT statement as a generic NATRule. Translation primitives may be shared internally without erasing these objects.

Inline address/service values have no independent native declaration. Unreferenced inline values may remain in immutable drafts, but do not affect semantic comparison; explicit declarations and values referenced by groups or NAT still do. Unknown inline evidence is retained.

## Parsing

Perl cursor behavior is deliberate: skip means pending for a later pass; rewind preserves committed state. Go uses `github.com/gatework/parser` for immutable source indexing, then a native structural scanner and targeted scoped stages. Reading never changes the Pending/Parsed/Ignored evidence ledger. Physical lines and XML byte fragments remain distinct. Transactions commit drafts together with actual consumed spans; rollback restores both. There is no shared mutable reader position or duplicate parsed-flag state. Only known irrelevant syntax may be ignored with a reason. Unknown nested blocks and quoted text cannot create domain objects.

Stages: native structure/context; zones/interfaces; address/service/schedule drafts; direct/static routes; VRF-scoped next-hop resolution and interface-route binding; zone networks; group references; rules/ACL binding; PBR and NAT; diagnostics; seal. Resolve next hops by longest connected prefix within VRF, preserving ambiguous and unresolved evidence.

## Snapshot and publication

Versioned bounded envelope and fixed concrete gob DTO tables, typed references, separate payload checksum and canonical semantic digest. Full raw text, source state, context, references and diagnostics retained. gob is trusted local storage, not a hostile network format. Load restores the graph without raw parsing, DB queries or device fallback. Unsupported versions fail explicitly.

Publish immutable blobs via temp/fsync/rename before atomically replacing a generation manifest under a stable sidecar lock. CAS, per-device durable reservations, idempotency, cross-process manifest reads and a projection outbox are required. Offline incomplete drafts cannot replace current; changed live state invalidates stale current and archives evidence. Projection consumes loaded published snapshots; failure does not roll back a good snapshot. No SQL schema or database adapter in this module.

## Evaluation and planning

IPv4/IPv6 interval algebra without enumeration. `github.com/gatework/set` integer sets implement IPv4 normalization, union, intersection and inclusion; IPv6 and exact subtraction remain domain interval operations. Range validation precedes integer normalization, and public address sets remain immutable. Exact multidimensional traffic union/difference preserves request pairs. First-match consumes known and potentially matching unknown traffic; conservative budgets prevent partial success. Scope, time, application/user, logging, route and NAT evidence participates.

Address subtraction and IPv6 intersection traverse normalized intervals in order;
containment does not materialize a difference. Public policy, NAT, packet and alias
queries bound input regions before any unknown/no-match shortcut. Match bounds
its explicit input, and route resolution bounds input address intervals.
`MaxRegions` remains 4096 by default. Graph-copy preflights use cached
`DeclarationSize`, including nested members, before allocating owned views.
Ordered policy evaluation keeps rule visits and owned declaration copies as
independent `MaxVisits` allowances. Only eligible, reached rules consume copy
capacity, measured by `Rule.DeclarationSize`; exceeding either allowance returns
no partial result. Risk and convergence also charge their actual nested copies
cumulatively, including evidence produced for unknown findings.

Business queries accept source/destination text and optional service. Normalize
formatting without guessing semantic errors; reject the invalid row while keeping
valid siblings. Within-row sets form a product; across-row associations stay exact.
Bare ports default to TCP; omitted services query all without authorizing an
unrestricted change. `Searcher` owns query composition and the local immutable
revision cache/index; `BatchDesigner` owns planning. No compatibility query facade.
Manifest state and time-dependent decisions are always fresh. Device associations
cover both endpoints and static NAT views without inventing ownership or ingress;
conditional and incomplete evidence cannot authorize changes. Finite windows split
at exact policy/NAT/calendar transitions. Native declaration matches, effective
first-match decisions and original wire pullbacks remain distinct.

Native NAT semantics govern selection: original match first; explicit identity/constant/offset/dynamic relations; no-NAT terminal; dynamic allocation is possible, not exact session state. Reverse inventory aliases require forward validation. PAN ordered NAT and ASA staged auto/manual semantics must not be conflated.

Reuse coverage, then append members, then create exact gaps. Perl candidate subset/equality conditions and append-member costs are retained, with deterministic lexicographic cost: new rules, appended members, new objects, modified rules, moves, position, ID. Every rendered candidate and batch merge needs exact-target and outside-preservation proof; try safe alternatives if rendering fails. Limits: 100 requests, 4096 combinations, 100000 candidate visits, 4096 regions, 128 complete candidate proof/render attempts; charge before expansion.

An append proven to change effective ownership outside the request is rejected before counting complete candidate attempts. Earlier-rule shadowing must be retained: declaration cross-products alone cannot establish a behavior change. Baseline evaluation may be shared only within one immutable graph and request context; candidate and independent-readback proofs still run in full.

## Lifecycle and online

Request optimization by exact fixed point; convergence with full-plan proof; translation by effective partitions and explicit zone mappings; declared/effective risk; separate unreachable/disabled/expired/unused reclamation with revision-bound contiguous hit evidence.

Validate stored revision, authorize exact plan, reserve, acquire native configuration isolation, capture and verify a fresh baseline, persist command receipts, confirm save/commit, independently read back, parse/prove, publish, project. No uncertain write replay; no expiry-based reservation release. Recovery reads state independently. Transport, authorization and journal are injected. The optional connector adapter belongs in a separate module; root offline builds remain independent. Its connector dependencies are now public and pinned to published versions. Implementation approval alone does not authorize private source publication, real-device access, push, commit or release. The user's subsequent explicit instruction authorized commits and pushes to the new public `gatework/firemon` repository; it did not authorize releases or device operations.

## Vendor and delivery sequence

The user narrowed the vendor scope on 2026-10-28 to Hillstone, Palo Alto, ASA, SRX, Netscreen, Fortinet and Huawei. H3C, Topsec, Neteye and other vendors are out of scope for now. The final vendor sequence added Fortinet, then Huawei. Each capability is supported only when fixture and semantic evidence establish it. Never advertise a parser stub as vendor parity. No web app/account/approval platform.

Validation includes independent small-domain algebra oracle, fuzz/race tests, native scoped fixtures, first-match/unknown behavior, NAT offsets/ports/stages, graph identity, atomic evidence rollback, crash/CAS/projection ordering, offline CLI and conditional adapter checks. Benchmarks report measurements separately from real-device/CI evidence.

## Operations remediation

The [2026-10-29 remediation](plans/2026-10-29-operations-remediation.md) strengthens
these contracts without widening vendor scope. [Cross-vendor contracts](contracts.md)
define shared parser/renderer selection, private policy semantic strategies,
typed VIP associations, effective NAT preservation, explicit migration chains,
compound audit predicates, member usage, candidate discovery and reusable
capture/design/deployment composition. Device sessions explicitly implement
configuration begin/end; PAN/SRX isolation is established before baseline capture.
Snapshot semantic format 10 rejects older graphs lacking the current typed calendar model.

## Typed calendar and migration continuation

The [2026-11-07 plan](plans/2026-11-07-domain-migration.md) keeps absolute windows
and weekly civil-time periods as typed values. Exact future context partitioning
includes bounded periods, weekday transitions and IANA timezone offset changes;
an arbitrary sample horizon cannot establish equivalence. Missing clock/calendar
evidence remains unknown. Source captures remain the authority for native syntax.

Migration compiles the selected effective rule and NAT dependency closure through
the target driver. Source packet effects, original traffic, allocation modes,
target outside behavior and independent native readback must all pass. Unsupported
selected effects return structured issues without an executable partial plan.
Explicit zone, chain, interface and VRF mappings describe existing target topology;
the compiler does not generate that topology. Native rule splitting is outside
the business-request decomposition contract.

Migration owns compiler results after a bounded deep copy and uses the same
native rendering boundary as other plans. Rendering receives owned arguments;
returned commands are copied and cancellation is checked before a plan can be sealed.

Approval version 4 uses explicit intent kinds. Reconstruction version 2 binds
both immutable snapshots for migration and reruns the planner, renderer and
proofs. There are no compatibility decoders or forwarding parser/application APIs.
The [implementation report](2026-11-07-domain-improvements.md) records current
capabilities and limitations; earlier verification documents remain historical.
