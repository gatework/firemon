# Core parser rewrite report

Status: DONE. No commits; limited modifications to config/ and benchmarks/scanner_bench_test.go.

## Implemented
- Content replaces Cursor. Existing line/fragment bounds, UTF-8 cancellation checks, source ledger, checkpoint and pending/rewind contracts retained. XMLDocument.Content is the new source owner. Statement raw text references the retained immutable source instead of allocating a second copy.
- Builder owns one ordered table and identity map per concrete record type. The source permits one builder owner. No second full Data copy is retained.
- Builder.Begin/Commit validate every claim and every typed identity before applying any record or evidence. Emit inserts new IDs; Replace explicitly updates existing IDs without reordering. All accepted input and public record reads preserve deep-copy isolation.
- Explicit Phase supports rollback of append/replacement records, typed indexes, source claims, reader position and cached graph, including nested phases and cancellation. Transactions cannot escape the phase that created them.
- Builder.Seal caches immutable graphs until any record/evidence commit and avoids the prior Data()->Seal() double graph copy. Typed single-record/list accessors and HasAddress/HasAddressGroup/HasService/HasServiceGroup avoid whole-graph exports.
- Removed Session/Stage/Transaction.Commit(*Data) and Content.Begin; migrated prior config contracts to the new API. No compatibility aliases remain.

## Evidence
- Actual old-code RED: TestDuplicateRecordCannotClaimSource failed with `duplicate record accepted and source claimed` before the rewrite.
- New tests cover duplicate rejection before source claim, replacement ordering, failed replacement rollback, typed index cleanup, cached graph restoration/invalidation, nested replacement rollback, foreign transaction ownership, copy isolation, and phase lifetime.
- `GOWORK=off GOPROXY=off go test ./config -count=1` PASS.
- `GOWORK=off GOPROXY=off go vet ./config` PASS.
- Reviewed phase journals and append/replace ownership paths. Successful nested phases retain undo until the outer phase completes; failed inner phases restore only their own changes. Full vendor, race and benchmark verification remains root responsibility.

## Rulings
- Phase uses an undo journal internally rather than cloning all accepted records or retaining two Data copies. Its effects are private to one synchronous parser; rollback is atomic at phase return. Only replacements retain old records, and no mutable record reference escapes through accessors.
- Source and graph domain DTOs stay unchanged; low-level API removals are the user-approved migration boundary.
