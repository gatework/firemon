# Computation and scanning contracts

Spec: ../spec.md and the user-approved conversation plan. Baseline: 45d937c.

## Global constraints

Seven vendors only; immutable graph, distinct StaticNAT/DynamicNAT, staged cursor
and source evidence. No new native grammar, wire format, dependency framework,
SQL, live device operations or release. Public API cleanup is approved, without
legacy aliases. Existing authorization permits commits and SSH push to remote
`go` main, never the Ruby `origin`. Keep other worktrees unchanged.

Budgets are layered: an algorithm owns cumulative work counters, its private
helpers share those counters, and delegated public queries/proofs independently
receive the same configured maxima. Candidate/comparison caps retain their own
meaning. Cancellation precedes validation; errors return no partial result.

### Task 1: Limits and bounded graph access

Rename policy.Limits fields to MaxRegions/MaxVisits/MaxCombinations. Add
WithDefaults() Limits, returning a copy with nonpositive fields defaulted to
4096/100000/4096. Migrate callers before behavior changes. Add constant-time
Firewall.RuleCount/ZoneCount/ScheduleCount, Schedule.Windows() iter.Seq[TimeWindow]
in declaration order and HasRecurrence() bool. Iteration returns values, supports
early exit, and exposes no mutable graph storage. Retain existing Rules order.
Tests: default/custom limits, immutable counts/windows, early exit and reuse.
Verification: go test ./...; go vet ./...

### Task 2: Layered computation budgets

Use effective limits in convergence, migration, risk, planner algebra/proofs and
Engine.Contexts. Charge list counts before materialization; charge traversal and
windows before work, including incomplete/unknown output paths. Private helpers
share each algorithm's remaining visits across contexts and candidates. Existing
lower-level Query/Match/NAT counting changes only in field naming. Preserve 100
requests/intents, default 128 candidates, 64 expression depth and optimizer 20000
comparisons. Transfer expansion uses MaxRegions. Universe/equality/outside proof
take explicit region limits and propagate errors. No swallowed cancellation or
partial results. Readback uses the plan's configured engine.
Tests: exact/over budget, low/high/custom defaults, incomplete risk, cancellation,
contexts/windows, convergence/migration cumulative visits, planning/readback
regions, existing seven-vendor approval goldens and proofs.
Verification: go test ./...; go vet ./...

### Task 3: Prepared risk expressions

Prepare each predicate standard once per Analyze call. Private typed expression
state owns its compiled values; validation and evaluation node budgets remain
independent. Retained standard regions in aggregate are bounded by MaxRegions.
Reuse dimension match/projection only within the current rule; each evaluated
node still consumes budget. Preserve declaration order, tri-state and short
circuit order, declared/effective modes and paired service terms. No cross-call
cache, retained caller input, goroutines or pools.
Tests: independent small-domain oracle, unknown/short circuit, input immutability,
concurrent reuse, aggregate retained-region and per-node budgets. Before changing
the hot path add expression benchmarks; profile, then compare six serial samples
against the corrected-contract baseline. Keep a performance optimization only if
complex risk time or allocations improve without significant paired-risk
regression; report the separate correctness overhead against the original base.
Verification: go test ./...; go vet ./...; serial targeted benchmarks

### Task 4: Cancellable scanning

NewCursor(ctx, source, limits) and NewFragmentCursor(ctx, source, spans, limits)
replace existing signatures. Update seven vendors, XML and nested adapter tests.
NewSession remains unchanged. Validate cancellation at entry, during bounded
byte chunks and before success, including empty input. Statements/Blocks reject
nil cursor/classifier with ErrInvalid; ParseFunc rejects nil. Invalid stage names
and dependencies wrap ErrInvalid. Preserve ErrSource/ErrClaim/ErrClosed roles,
line/fragment spans, pending/rewind semantics and atomic stage rollback. XML
checks between decoder calls and scanner chunks; no interruptibility claim for
stdlib internals. No grammar expansion or streaming rewrite.
Tests: canceled empty/malformed/long source, fragments, quoted multiline input,
nil callback/classifier, invalid stage and cancellation rollback; unchanged
seven-vendor native semantic digests. Benchmark short/long scanner input and
representative CLI/XML parsing with six serial samples.
Verification: go test -race ./...; go vet ./...

## Review Focus

Budget checks after expensive copies; private helper counter resets; unknown
results bypassing limits; compiled-risk short circuit/tuple/alias differences;
scanner cancellation changing evidence or XML byte/line spans.

## Delivery

Keep structural, behavioral and performance commits distinct. Fresh independent
whole-diff review, then fixes with RED/GREEN evidence. Root race/vet and current
adapter workspace checks, then published core pin with GOWORK=off and no replace.
SSH push, exact remote SHA readback and exact-commit CI. Update current contract,
migration, verification and performance documentation; retain historical records.
