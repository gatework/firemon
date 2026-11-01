# Business lifecycle verification — 2026-10-31

The [nine-task plan](plans/2026-10-30-business-lifecycle.md) was implemented on
`feat/go-firewall` over the existing uncommitted parser rewrite. The comparison
baseline is the frozen pre-business directory at
`/tmp/firemon-business-20261030/baseline`, with HEAD
`19d1fb999feb63a2f5cf7c2450dec1e7e63da01a`. A bare HEAD diff would incorrectly
attribute the earlier parser work to this iteration. No commit, push, release,
database or real-device action was performed.

## Requirement evidence

| Task | Result and focused evidence |
| --- | --- |
| 1: joint policy batches | `plan/batch_test.go`: partial local rejection, paired targets, canonical fallback, whole-device proof and deterministic digest |
| 2: topology/business design | `inventory/topology_test.go`, `operations/batch_designer_test.go`: frozen manifest, explicit/automatic targets, static aliases, forward proof, coordinate-specific failures |
| 3: collection/analysis | Collector batch, Inspector, RevisionComparer, RiskBatch and convergence tests: ownership/lifecycle, independent failure, shared limits and signature grouping |
| 4: explicit native effects | `plan/native_test.go`, `policy/nat_intent_test.go`: atomic dependencies, whole NAT intent/outside proof, typed readback and pre-copy ingress accounting |
| 5: native forms | `vendors/native_commands_test.go`: 20 independently authored capture forms, full proof/readback, namespace/inline ownership and version refusals |
| 6: finite lifetime | Clock/schedule/vendor tests: independent clock binding, exact endpoints, DST refusal, lifetime before/during/after, policy-owned NAT and readback |
| 7: usage/lifecycle | Native usage and CLI tests: timestamps/revisions/windows/epochs, paired tuples, positive member evidence, explicit reclamation/migration and unknown evidence |
| 8: selected execution | BatchExecutor/reconstruction tests: real engine with simulated sessions, exact selection/authorization, restart, aborted/uncertain/unstarted outcomes, no replay, drift/tamper/missing baseline/cancellation |
| 9: real reference and gates | 37 isolated actual Perl invocations, retained source/artifact hashes, Go oracle assertions, serial measurements and local module gates below |

The deferred Task 2 DTO alias finding was corrected at the durable boundary.
Task 8 also reproduced and fixed final business packet rechecking outside a
finite lifetime. Original intent times stay intact; the final view check samples
the active window already fully proven by the native planner.

## Local gates

| Boundary | Command/result |
| --- | --- |
| Root Go 1.27.1 | `GOWORK=off GOPROXY=off go test -count=1 -race ./...`: PASS, 25 test-bearing packages |
| Root vet/build | `GOWORK=off GOPROXY=off go vet ./...`, `go build ./...`: PASS |
| Minimum Go 1.26.0 | `GOTOOLCHAIN=go1.26.0 GOWORK=off GOPROXY=off go test -count=1 ./...`: PASS |
| Pinned adapter | Isolated copy, `GOWORK=off GOPROXY=off` race/vet/build and module verification: PASS |
| Current-core adapter | Separate isolated adapter copy plus temporary go.work pointing at current core: race/vet/build PASS |
| Perl reference | [37 runs](business-oracle-runs.json), all exit 0; 31 source hashes verified; one expected ASA warning stream retained |

The pinned adapter still uses published core
`v0.0.0-20261029132556-0d50959d0a4d` and connector
`v0.0.0-20261026235641-c68c42b4bbcf`; module metadata contains no replacement.
It is distinct from current-core workspace verification. No dependency pin or
private source was published. The first temporary-workspace attempt encountered
macOS `/tmp` versus `/private/tmp` path identity; canonical absolute paths fixed
the harness, then all three checks passed.

Exact local logs and RED/GREEN evidence are in
`/tmp/firemon-business-20261030/task-*-*.log`; the execution ledger and per-task
reports are under the ignored `.superpowers/sdd/2026-10-30-business-lifecycle/`.
Tasks 1–4 had independent task reviews and addressed findings. Tasks 5–8 used the
recorded inline fallback after implementer workspace-credit failures. Final
whole-business review availability is recorded separately below; task self-review
is not represented as independent approval.

## Measurements and limits

Raw six-sample [before](benchmarks/2026-10-31-business/before.txt),
[after](benchmarks/2026-10-31-business/after.txt) and
[benchstat comparison](benchmarks/2026-10-31-business/comparison.txt) use the same
Go 1.27.1 toolchain, Apple M5 darwin/arm64 host and GOMAXPROCS=1. Workloads ran
serially with no concurrent tests. The identical common benchmark source was
copied into a separate baseline measurement directory; the original baseline
was not modified. Each benchmark uses 100ms minimum per sample and checks the
result. [Environment/binary/source hashes](benchmarks/2026-10-31-business/environment.json)
identify the comparison.

| Workload | Before → after median | Tradeoff |
| --- | --- | --- |
| Sparse compatible-pair discovery, 1,000 rules | 16.959ms → 1.681ms (-90.09%) | Allocated bytes +88.74% for exact signature index |
| Sparse compatible-pair discovery, 10,000 rules | 1,678.07ms → 18.82ms (-98.88%) | Allocated bytes +66.70% |
| Dense probe, 1,000 rules | 30.72ms → 31.54ms (+2.65%) | Exactly one proven pair followed by comparison-budget refusal |
| Dense probe, 10,000 rules | 316.4ms → 333.6ms (+5.43%) | Same bounded probe; full dense enumeration is not measured |
| Shared 16-member group, 1,000/10,000 rules | No significant timing difference | Same allocations and unknown-usage output |
| Existing optimizer 10/100 requests | Mostly no significant difference | Paired 100 case +1.15% timing; unchanged allocations/algorithm |

Sparse comparison uses the same adequate cap `n*(n-1)/2` so both versions return
the same successful empty candidate list. Separate default-budget probes show
[old refusal](benchmarks/2026-10-31-business/default-before.txt) and
[new success](benchmarks/2026-10-31-business/default-after.txt) at both sizes.
Those different outcomes are not counted as speedup measurements.

[Covered PlanBatch](benchmarks/2026-10-31-business/batch.txt) and
[append PlanBatch](benchmarks/2026-10-31-business/batch-addition.txt) are new-API
baselines, not comparisons against independent single-request scripts. They use
1/8 requests and 1,000/10,000 rules. Covered duplicate-rule workloads take about
3.5ms/36ms. Append workloads have one eligible permit plus explicit deny peers,
and retain exact complete service/destination domains with nonadjacent new sources.
Dense append search over all eligible rules still reaches the configured visit
budget in large fixtures; the measured append baseline does not claim to solve
that separate scaling limit. Earlier parser benchmarks remain intact.

These are local synthetic results. Existing-session termination, arbitrary
NAT/schedule migration, broad firmware compatibility and actual device acceptance
are not established. No new CI or remote-publication evidence is claimed.

## Final review

A fresh-context whole-business reviewer was dispatched against the frozen
pre-business/candidate directories. It exited because the workspace was out of
credits, without findings or a verdict. The requested independent final review
therefore remains an open verification item. Root completed integrated self-review
of native ownership, finite/outside proofs, reconstruction, selected execution,
usage and evidence limits; no further blocking defect was identified. This is
self-review, not independent approval. Prior independent Tasks 1–4 reviews and
their corrected findings remain recorded. No code was changed by the failed
reviewer.

Baseline read-back confirmed every original file remains present. Original parser
fixtures/benchmark artifacts and adapter module pins are unchanged, the index is
empty and both worktree HEADs remain unchanged.
