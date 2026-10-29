# Domain contracts and object responsibilities

Approved baseline: dd15031. User approved direct public Go API changes and an
independently usable read-only collection contract. Follow docs/spec.md,
docs/contracts.md and AGENTS.md. Only Palo Alto, SRX, Huawei, Hillstone, Fortinet,
Netscreen and ASA. Immutable graph, separate StaticNAT/DynamicNAT, pending evidence,
staged parsing with interface-before-route binding, snapshot semantic format 9,
persisted fields, CLI wire fields and approval digest encoding remain unchanged.
Perl and Ruby references are read-only. No live devices, new vendors, runtime
dependencies or releases. Commits and SSH pushes to remote go are authorized.

## Task 1: Domain and evaluation contracts

Add Firewall.Raw and required scalar read methods; preserve defensive Record and
Export and shared immutable references. Move schedule ActiveAt/ExpiredAt predicates
onto Schedule, returning (value, known), preserving half-open windows and unknown
recurrence/unsupported/absent-time handling. Unknown activity stays possibly active.
Introduce policy.RuleChain with PolicyChain and FromZone/ToZone for native rule
ordering; no persisted field changes. Add Request.SameContext for default-security
chain normalization and time.Equal context comparison.
Move policy.Routes to Engine.ResolveRoutes. Use effective Rules for VRF candidate
count, Regions for output partitions. Check cancellation before validation and
through traversal/sorting; preserve longest-prefix/metric/ambiguous-route behavior.
Unify invalid input errors in policy and plan; distinguish unknown, unsupported,
budget, unsafe-plan and failed-equivalence results. Migrate callers and tests,
including native packet paths and Netscreen parser route lookup. All public API
changes need regression/contract tests. Preserve IDs and digests.

## Task 2: Stateful parser ownership

Own config except parser.go (Task 3 supplies shared Parser/ParseFunc), vendors,
and their tests. Session owns a private cursor exposed by Cursor(); NewSession
returns (*Session,error) and rejects nil; Commit rejects nil/foreign/closed
transactions with classified errors. Preserve closed no-op Parse/Ignore/Emit and
single ownership transfer, nested rollback, cancellation, pending evidence and
dependency order. Migrate all seven parsers and tests. Consolidate vendor lookup
to one definition carrying name, aliases/default context, parser constructor and
renderer. Keep native parser limits, Fortinet default/explicit VDOM behavior and
existing input/output semantics. Add substitutability/ownership regression tests.
Only migrate route/scalar calls agreed with Task 1. Do not commit or update docs.

## Task 3: Read-only device boundary and application construction

Own device, deploy, operations, adapter/netconnector, inventory, projection,
internal/capture, config/parser.go and related tests. Create device.View/Capture/
Reader (Read/Close) without transport implementation. Canonical Parser/ParseFunc
live in config. Remove old deploy aliases and update all owned callers.
Collector uses OpenReadOnly(context.Context,string)(device.Reader,error), independent
of journal, authorization or writes. Deployment Session embeds device.Reader and
retains configuration isolation, Execute and Save. Adapter Factory supplies both
Open and OpenReadOnly with shared private opening logic and fresh owned sessions;
read-only opening does not begin configuration. Keep adapter module pins unchanged
until root publishes the new core.
Collector, Designer, deploy.Engine privately own their dependencies/options;
NewCollector, NewDesigner, deploy.New return pointers with errors. Runtime hides
components and exposes Collect/Design/Apply/Recover delegation. Constructor option
structs remain public. Operations.Options.Sessions composes both factory contracts.
Guard nil/typed-nil injected interfaces and successful nil session/lease/graph
results before use; context cancellation precedes validation/dependency calls.
Typed-nil detection may use a tiny internal dependency-boundary helper; no DI
framework. Keep resource transfer, Close errors, partial evidence and exact
deployment/journal ordering. Check inventory/projection nil/context boundaries and
preserve idempotency/CAS. Use Firewall.Raw once Task 1 supplies it. Add read-only
integration, constructor validation, cancellation and broken-provider regressions.
Do not commit or edit docs/benchmarks; report structural vs behavioral changes.

## Task 4: Lifecycle requests and naming

Own analysis plus lifecycle benchmark callers. Reclaimer keeps only Planner;
ReclamationRequest owns At, Revision, Window, Observations, MemberObservations.
Analyze/AnalyzeMembers accept this request; Plan accepts request and selected IDs.
PolicyMigrator keeps only Planner; MigrationRequest owns At, Zones, Chains, Pairs,
Rules. Plan(ctx,source,target,request) reads without retaining or modifying inputs.
Converger keeps Planner/MaxComparisons; Candidates(ctx,fw,from) and
Plan(ctx,fw,ids,from) receive time per call. RiskAnalyzer.Assess becomes Analyze.
Use Schedule.ExpiredAt from Task 1; all unknown/reclamation/migration restrictions
and independent full-plan proofs remain. Use Request.SameContext in optimizer.
Regression tests reuse services with distinct requests, verify input isolation and
concurrent calls under race. Do not add shared caches or concurrency to algorithms.
Do not commit or update documentation.

## Task 5: Review, evidence and delivery

Separate structural/API commits, invalid-input behavior corrections, and measured
allocation optimizations. Review each task and final integrated diff. Verify full
race/vet, bounded fuzz, native exported data/digest and existing approval goldens,
snapshot restore, CLI output and deployment recovery. Freeze baseline benchmarks
before mutation; measure relevant parse/query/route/capture/planning/lifecycle
workloads serially with the same toolchain and six samples. Investigate regressions.
Document migration and per-module ownership. Publish core via SSH remote go, then
pin adapter to that published version and independently test with GOWORK=off and
no replace. Push adapter/docs, verify exact remote SHA and CI. Keep Ruby untouched.
