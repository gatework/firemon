# Candidate coverage, identity and search contracts

Approved implementation plan from the 2026-10-29 review. Baseline: bfc5f25.
Reference: spec.md and Perl Policy::Searcher searchSrv/selectAModifyPolicy.

## Constraints

Keep reuse, single-rule append, then exact creation. No multi-rule combination
search. Keep seven vendors, separate StaticNAT/DynamicNAT, snapshot v9 and public
DTOs. Unknown evidence cannot authorize a change. Immutable input graphs and
complete traffic/native proofs remain mandatory. Standard library only.

### Task 1: Native identity and allocation

First reproduce reverse-order generated ID collisions, occupied service/group
names, and Huawei's aliased baseline rule name through public planning/rendering.
Extract internal/nativename keys from native render validation. Keep ASA group
namespaces, Fortinet context and native rule-chain identity; add Huawei rule-name
checks. Candidate-owned allocation indexes/reserves IDs and names, including
pending objects, using existing hashes and successive -new suffixes. Global
address/service names avoid all scopes to prevent local name shadowing. Plan and
Transfer use the same allocator; all work shares visit/cancellation limits.
Validation: go test ./plan ./vendors/...; go vet ./plan ./vendors/...

### Task 2: Exact service coverage

First reproduce union-covered service members being appended and charged again.
Add internal/servicecoverage FromTerms/FromTraffic helpers using the exact flow
algebra at a fixed singleton address pair. Preserve all five service dimensions.
Plan skips union-covered terms and updates coverage after additions; partial
coverage still adds the requested complete term. Risk service projections share
the helpers without changing relation direction, empty/unknown semantics or
resource limits. Use clear domain names in the changed candidate code.
Validation: independent bounded five-dimensional oracle, plan/analysis tests.

### Task 3: Bounded ranked candidate attempts

First reproduce MaxCandidates=1 rejecting an already safe append and exercise
late cheaper candidates, render rejection and exact/exceeded attempt limits.
Scan eligible appends within MaxVisits; retain the cheapest N in a bounded max
heap. Finish scanning before proofs. MaxCandidates (default 128) counts complete
proof/render attempts; prefilter rejection costs visits only. Create lazily after
all appends fail and budget remains. Untested alternatives at exhaustion return
ErrBudget; complete rejection returns ErrUnsafe. Other errors retain propagation.
Keep candidate drafts separate from proven Plan values. Transfer is not a search.
Validation: plan tests and observable bounded candidate benchmark.

## Final validation and review

Run go test -race ./..., go vet ./..., bounded flow/service fuzzing, existing
snapshot/CLI/approval/readback regressions and Plan/RiskExpression benchmark
comparisons. Review the full change range independently. Report local, CI and
device evidence separately. Update contracts and verification with actual results.
