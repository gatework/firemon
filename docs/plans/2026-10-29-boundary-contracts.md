# Boundary contracts implementation plan

Spec: ../spec.md and the approved conversation plan. Baseline: b506b54.

## Global constraints
Seven vendors only; immutable graph, separate StaticNAT/DynamicNAT, staged cursor parsing. Standard library first, request-local state, no uncertain write replay. Retain semantic format 9, journal wire format and approval digests. Existing SSH commit/push authorization targets remote go, never origin. No release or live device operations.

### Task 1: Strict rendering
Keep Renderer.Render signature. Add plan.ValidateChanges and plan.ErrRender; cancellation first, validate complete graphs, identity, exact declared delta and native ordering. Invalid inputs use ErrInvalid; incomplete graphs ErrUnsafe; unsupported representation ErrRender. No partial commands, no-op returns nil. Planner falls back only for ErrRender; Preserve validates empty changes too. Tests cover seven direct and registry implementations, changes, ordering, errors and approval/readback compatibility.
Verification: go test -race ./...; go vet ./...

### Task 2: Usage evidence
Shared request validation and private indexed interval evaluation. Preserve tri-state rule/member evidence, revision/digest binding, contiguous windows and no deletion authority from non-use. Use existing Rules budget (default 100000), charge relevant observations and visits before expansion; cancellation in traversal and bounded sorting; no partial results. Compare against independent oracle and serial before/after benchmarks.
Verification: go test -race ./...; go vet ./...

### Task 3: Persistence boundaries
Add snapshot.ErrInvalid and deploy.ErrJournalFormat. Validate empty roots, nil/zero stores, typed-nil I/O, length limits; cancellation first. Detect short writes, preserve underlying I/O errors. Share private blob encoding/storage while preserving atomic publication, CAS, reservations and outbox. Preserve file formats. Test corrupt/truncated I/O, cancellation and ownership lifecycle.
Verification: go test -race ./...; go vet ./...

## Review Focus
Undeclared graph changes and native ordering; unknown evidence incorrectly granting deletion; input mutation across calls; filesystem side effects on invalid input; short writes and crash/recovery boundaries.

## Delivery
Fresh independent whole-diff review, standalone adapter validation with GOWORK=off and a published core pin, serial benchmarks, SSH push and exact-commit CI verification. Report local/CI/device evidence separately.
