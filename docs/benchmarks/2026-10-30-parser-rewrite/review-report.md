# Independent parser rewrite review

Reviewed 2026-10-30 against the frozen full-worktree baseline in `/tmp/firemon-rewrite-20261030/baseline`, not Git HEAD. Read AGENTS.md, the approved rewrite plan, docs/spec.md, original architecture plan, core report, progress ledger, and requesting-code-review criteria. Used golang-how-to, golang-safety and golang-refactoring review guidance. Review was read-only on the checkout; only external review artifacts were written. No network, commits, or subagents.

## Strengths

- `config/transaction.go:72` validates ownership, phase lifetime, every source claim and every typed identity before publishing any record or evidence. Explicit Replace retains existing order and does not silently choose native duplicate semantics.
- `config/builder.go:114` journals replacement ownership and evidence while tracking append boundaries. Nested failure restores the appropriate records, indexes, reader position and cached graph; successful nested work remains reversible by its outer phase. Inputs and typed accessor results are deep copied.
- `config/builder.go:96` delegates the ownership copy to immutable Seal and invalidates the cache on every successful transaction, including evidence-only commits. Rollback restores the previous cache.
- Seven vendor implementations preserve their original native stages, lexical structure and scope resolution. Function-level comparisons against the frozen baseline show the main migrations are ownership/API substitutions and file moves. Raw statement string sharing preserves bytes and is safe because the retained source string is immutable.
- Accepted records are Builder-owned; vendor temporary catalogs remain phase-local, and no legacy Session/Stage/Cursor orchestration or second retained parser Data was found. Static and dynamic NAT stay distinct. Source/Parser/Limits entry interfaces and graph/snapshot schema remain outside the changed boundary.
- Contract tests cover observable duplicate rejection without source loss, replacement order, nested rollback, foreign ownership, phase lifetime, copy isolation, evidence-only cache invalidation, scanning bounds and canonical baseline graphs after snapshot restoration.

## Issues

### Critical

None identified.

### Important — resolved during review

**Repeated deep copying of full typed catalogs in per-policy/per-NAT loops caused a large performance regression.**

The initially reviewed `vendors/fortinet/network.go` policyZones loop called `p.builder.Interfaces()` for every source/destination selector, reached twice per policy from `vendors/fortinet/policy.go:32`. Unlike the baseline read of p.data.Interfaces, each call deeply copied all interfaces and nested data. Similar patterns existed in VIP/interface NAT, Huawei service classification and SRX zone attachment checks.

A targeted synthetic Fortinet capture with 500 interfaces and 1000 policies reproduced the impact. Every iteration required a Complete graph. Five 200 ms samples per frozen binary produced these median results:

| Variant | ns/op | B/op | allocs/op |
| --- | ---: | ---: | ---: |
| Frozen baseline | 12,752,773 | 39,472,368 | 156,659 |
| Initial rewrite | 57,276,875 | 265,852,284 | 2,137,136 |
| Fixed rewrite | 12,552,645 | 38,239,782 | 137,133 |

The initial regression was 4.49 times slower and used 6.74 times as many allocated bytes. Existing parser benchmarks with two interfaces did not cover this dimension.

The executor corrected the issue during review. Current `vendors/fortinet/policy.go:16` and `vendors/fortinet/nat.go:29` capture one phase-local interface view and pass it read-only to helper functions; `vendors/fortinet/network.go:216` no longer clones the catalog per selector. `vendors/huawei/nat.go:218` follows only referenced services/groups through typed lookups, retaining local delta precedence and existing unsupported/cycle/budget rules. `vendors/srx/objects.go:184` uses the native zone ID directly. Focused source rereview and the rebuilt fixed benchmark confirm the Fortinet regression is resolved. Fixed timing is within baseline variation and allocation totals improve.

Reproduction: build `/tmp/firemon-rewrite-20261030/review-perf.go` with `GOWORK=off GOPROXY=off go build -o <binary> <source>` from each respective module root, then run `<binary> -test.benchtime=200ms`. Raw sample values are in `review-perf-results.txt`; the baseline, initial and fixed binaries are preserved. These short targeted measurements demonstrate this regression and correction; they do not replace the executor's planned repeated broad benchmarks.

### Minor

No actionable minor findings. Cosmetic import grouping and old comments are not delivery blockers.

## Recommendations

Retain the 500-interface/1000-policy benchmark as a regression workload so future safe-copy accessor changes are measured across both object and rule counts. The executor has agreed to adopt it. Do not relax Builder copying to optimize callers; retain phase-local views or typed lookup as used in the correction.

## Declined to judge

- Real-device behavior and acceptance: explicitly outside the authorized offline rewrite; no device evidence was supplied or sought.
- Native vendor syntax or capabilities absent from the frozen implementation and fixtures: this is a behavior-preserving migration, not expanded vendor support. Existing unsupported/pending evidence must continue to survive, and reviewed changes preserve it.
- NAT parity against the actual Perl oracle: the supplied six-vendor oracle evidence covers bounded objects/groups/services/interfaces/policies, not NAT. No NAT-oracle parity claim is supported by this review.
- CI, release, publication, adapter credentials or remote delivery: outside the read-only review assignment and current authorization.
- Final broad race/build/vet/fuzz/adapter completion and ten-sample benchmark statistics: the executor is running those gates; this review did not rerun them or infer their success from code inspection.
- Final documentation verification records still being edited by the executor: correctness of final commands/results must be checked against the executor's completed artifacts.

## Assessment

**Spec/plan alignment: Pass for reviewed implementation.** The architectural rewrite follows the approved boundary, preserves typed identity/order/unknown evidence, and avoids duplicate accepted graph ownership. The one measured performance defect was corrected without weakening ownership.

**Code quality: Pass after the performance correction.** No remaining concrete correctness or architectural findings were identified in this review. Source isolation, native scope/identity/order, transaction rollback/cache behavior, and changed lookup semantics were inspected against the frozen baseline.

**Ready to merge: Yes from this code-review seat, contingent on the executor completing its remaining authorized gates and benchmark regression adoption.** This is a technical review verdict, not authorization to merge, commit or publish.
