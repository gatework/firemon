# Planning intent refactor evidence

Scope: the [approved plan](plans/2026-11-01-plan-intent.md), implemented on
2026-11-01 against the existing uncommitted parser and business lifecycle work.
The snapshot, journal and durable selection formats remain unchanged. No
deployment, publication or device action was performed.

## Ownership and compatibility

`plan.Plan` contains one private intent: access, policy batch, native batch,
preservation or transfer. Each intent owns its approval encoding and readback
proof dispatch. Common graphs/results remain on Plan; native identity mapping
still precedes the independent readback proof. Proof algorithms, candidate
selection, vendor capabilities and independent budgets are unchanged.

`plan.Reconstruction` owns the versioned input format and rebuilding. It is
separate from the report DTOs in operations. The operations adapter validates
material, loads its exact immutable revision, and supplies production renderer
selection. Baseline identity is checked before selecting the renderer; rebuilding
always re-runs planning and compares the resulting approval digest. The core
imports neither operations, vendors nor snapshot. See the
[core interface and limits](batch-execution.md) and [glossary](../GLOSSARY.md).

Ordinary batch approval deliberately excludes effective options and original
refused inputs, while native approval retains both. The five encodings preserve
their historical field order, null/empty distinctions, omitted fields and time
forms. Only policy/native business batches can reconstruct. Existing public Go
entrypoints, getters and operations error identities remain available.

## Frozen evidence

Before production edits, all 666 source files were frozen under
`/private/tmp/firemon-intent-20261101-9g5ni6pg/baseline`. This is the comparison
base, not Git HEAD, which predates the pending parser and lifecycle work.

An unchanged production copy generated 17 fixed fixtures: ten plan observations
(reuse, append, create, policy batch, covered batch, native batch, partial native
batch, preservation, unchanged preservation, transfer), report bytes, selection
bytes/checksum, policy reconstruction bytes/checksum, and finite native
reconstruction bytes/checksum. Repository tests read these fixtures without an
update mode. All 17 remain byte-for-byte unchanged after the refactor.

New core-interface tests failed first because the interface did not exist, then
passed after implementation. They cover owned material, concurrent independent
rebuilds, baseline-before-renderer ordering, nil/zero material, cancellation,
renderer errors, short writes, unsupported families and approval-digest mismatch.
Existing tests cover strict/bounded decoding before snapshot loading, original
refusals/options, all 20 supported native creation forms, finite packet intent,
restart, uncertainty without replay, independent readback and material corruption.

## Local checks

| Check | Result |
| --- | --- |
| Go 1.27.1 root `GOWORK=off GOPROXY=off go test -count=1 -race ./...` | PASS; 25 test-bearing packages |
| Root `go vet ./...` and `go build ./...` with workspace/network disabled | PASS |
| Minimum Go 1.26.0 root `go test -count=1 ./...` | PASS |
| Isolated adapter using published dependency pins | race/vet/build/module verification PASS |
| Separate adapter using current core via temporary go.work | race/vet/build/module verification PASS |

Pinned consumer verification still uses core
`v0.0.0-20261029132556-0d50959d0a4d` and connector
`v0.0.0-20261026235641-c68c42b4bbcf`; current-core verification is separate evidence.
No module pins changed. Logs, frozen file hashes and the implementation ledger
are in the scratch directory above and
`.superpowers/sdd/2026-11-01-plan-intent/`. Historical Perl fixture regressions ran
with the root tests; this structural refactor does not claim a new live Perl
Oracle run, remote CI, release or real-device acceptance.

## Measurements

[Before](benchmarks/2026-11-01-intent/before.txt),
[after](benchmarks/2026-11-01-intent/after.txt) and
[benchstat](benchmarks/2026-11-01-intent/comparison.txt) contain six samples per
workload, 100ms minimum each, Go 1.27.1, Apple M5 darwin/arm64, GOMAXPROCS=1.
Both versions ran the same benchmark/fixture source serially, with no concurrent
test jobs. Parsing, publication and initial proof are outside measurement;
Restore includes exact snapshot loading and full planning/proof.

Policy/finite planning and 1,000-rule, eight-request covered/addition batches show
no significant time difference in these samples. Finite reconstruction encoding
uses 10 versus 16 allocations, 3,872 versus 4,880 bytes, and takes 7.48% less time:
the owner reads its immutable inputs without cloning public getter results.
Policy encoding uses eight versus nine allocations but takes 1.08% more time;
policy restoration takes 1.09% more time with three additional allocations.
These are local workload measurements, not a claim that all operations are
faster. Retaining the explicit intent and reconstruction seam is the purpose of
the change.

## Final review

The final fresh-context reviewer was dispatched but returned no usable report;
no reviewer remained available when execution resumed. Independent review is
therefore OPEN. An author self-review compared the frozen implementation,
intent-specific encodings, getter ownership, readback dispatch, codec validation
order, budget charging and rebuilding. It found no additional blocking defect;
this is not independent approval. No behavior was silently excluded from that
review; real-device acceptance and remote CI remain unverified as stated above.

Final preservation checks found all 666 original files present. The 11 intended
production files and `docs/batch-execution.md` changed; the other 654 originals
remain byte-identical, including prior parser work and adapter pins. All 17
frozen compatibility fixtures match their original hashes. HEAD, empty index and
linked worktrees are unchanged; gofmt and `git diff --check` passed.

The architecture report was generated under the OS temporary directory and
opened with macOS `open`. Its three candidate cards, script inventory and local
links passed structural checks. Browser automation reported no available browser,
so rendered/CDN diagram inspection remains unverified. No HTML was added to the
repository.

Execution decisions: historical behavior was frozen on unchanged production
source for this refactor; the new codec interface had a missing-interface RED
before implementation. Intentionally breaking existing production merely to
make characterization tests fail would weaken the baseline. Incorrectly captured
characterization would miss an old behavior, so existing tests and independent
readback remain part of verification. The approved keep-local scope also takes
precedence over the generic branch-finishing integration menu; work and evidence
remain available without a commit or push.
