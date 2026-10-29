# Lifecycle algorithm contracts implementation plan

> Execute inline with the executing-plans skill; retain failing-then-passing evidence and one final independent review.

**Goal:** Bound lifecycle configuration copies, distinguish candidate rejection from operational failure, and enforce consistent request region limits.

**Architecture:** Preserve concrete immutable graphs and layered computation limits. Each algorithm charges its own preparation and private passes; delegated public policy queries retain independent limits. Classify rejection at the stage that produces it.

**Spec:** The approved lifecycle review in the conversation, [specification](../spec.md), and [business contracts](../contracts.md).

## Global constraints

- Only Palo Alto, SRX, Huawei, Hillstone, Fortinet, Netscreen and ASA.
- Separate StaticNAT and DynamicNAT; no snapshot format change or new dependencies.
- Unknown evidence cannot authorize traffic or removal. Retain full policy, logging, schedule and NAT proofs.
- Preserve method signatures and errors.Is compatibility. Visits count records, not bytes or nested members.
- Normal-readback minimum capacity is checked before rendering, including no-change plans. It is necessary capacity, not a guarantee of future readback success.

### Task 1: Bound lifecycle copies and readback capacity

**Files:** root graph counts, policy equivalence/NAT preservation, analysis convergence/reclamation, plan preservation/readback/construction boundaries and focused regression tests.

**Interfaces:** Add allocation-free Firewall.StaticNATCount and DynamicNATCount. Use existing RecordCount and package-owned visit counters. Preserve ValidateChanges as a semantic validator; its bounded caller charges graph views first.

- [x] Reproduce oversized unused catalogs escaping low MaxVisits, including allocation-before-failure and readback cases.
- [x] Charge graph exports before materialization; share counters with private passes and NAT activation. Reuse exported rules in convergence.
- [x] Preflight two baseline copies and baseline plus two result copies in all plan creation paths, using subtraction to avoid overflow and without consuming current-operation visits.
- [x] Verify low/high budgets, cancellation, no-change plans and independent readback; run targeted packages.

### Task 2: Classify convergence refusals at their origin

**Files:** plan rejection/preservation and analysis convergence, with focused error-contract regressions.

**Interfaces:** Add plan.RejectionError with stage and cause, Error and Unwrap. Stages represent declaration compatibility, policy preservation and native representation. Native renderers continue to signal expected refusal only with ErrRender.

- [x] Reproduce fatal renderer errors being retried and hidden by Candidates.
- [x] Wrap local expected refusals; contextualize unexpected renderer failures with ordinary wrapping. Candidates accepts only a direct top-level RejectionError; cancellation and budgets take precedence.
- [x] Verify ordinary/wrapped fatal errors, foreign direct/wrapped RejectionError, normal refusal rows, empty commands and cancellation. Preserve errors.As/Is diagnostics.

### Task 3: Enforce input region bounds and complete verification

**Files:** analysis request optimizer tests/implementation, contracts and verification/status documentation.

- [x] Reproduce packed versus split requests bypassing MaxRegions.
- [x] Check RegionCount before grouping/copying; retain strict intermediate Union limits and exact fixed-point coalescing.
- [x] Verify sufficient-budget traffic equality, source/destination association, input ownership and oversized input allocations.
- [x] Run go test -race -count=1 ./..., go vet ./..., go build ./..., and a fresh whole-change review. Record evidence and ship to the previously authorized Go remote after verification.

## Review focus

- Reject oversized graphs before copying, including independently captured observations.
- Minimum readback preflight covers all creation paths without claiming to guarantee arbitrary observed graphs or later proof work.
- A renderer returning a nested structured rejection must remain an operational failure; raw sentinel matching is not provenance.
- No partial results on cancellation or budget failure; adequate budgets retain existing semantics.
- No new cross-pairs, policy/logging/NAT changes, or usage-only removal authorization.
