# Planning intent lifecycle

Historical plan. The [2026-11-07 continuation](2026-11-07-domain-migration.md)
supersedes its compatibility and reconstruction limits with explicit intent
kinds, approval 4, reconstruction 2 and both-snapshot migration binding.

Approved scope: concentrate the five existing planning intent families in `plan`:
access, policy batch, native batch, preservation and transfer. Preserve public
entry points, behavior, approval digests, report/reconstruction/selection bytes.
Reconstruction remains limited to the two business batch families. This is a
structural change, not a new planning algorithm or a budget/packet-proof rewrite.

## Constraints

- Preserve the current uncommitted parser and business lifecycle work. Compare
  against a complete frozen directory, not HEAD. No commit, push, publication or
  device actions. Snapshot format, journals and operation identities are unchanged.
- Use a private closed intent interface with five concrete records. The intent
  owns mode-specific state and approval/readback dispatch; Plan retains common
  graph/result state. Existing getters keep their values and ownership behavior.
- Ordinary batch options/original rejected inputs remain replay material only;
  native approval continues to include options and original/accepted inputs.
  Preserve legacy encoding, ordering, omitted fields, null/empty and time forms.
- Add opaque plan.Reconstruction with EncodeReconstruction, DecodeReconstruction,
  Revision and Rebuild(ctx, baseline, selectRenderer). The renderer selector has
  existing shape func(string) (Renderer, error). No snapshot/vendor imports in plan.
- operations.EncodePlan/RestorePlan stay compatible adapters. Validate bounded
  material before loading, baseline identity before selecting renderers, and
  replan before comparing digest. Reports never become executable authority.
- Keep original errors, context priority, independent computation budgets and
  immutable input/output ownership. Unclear semantics require actual Perl sources.

### Task 1: Freeze compatibility evidence

Freeze current directory and Git state. Characterize five planning families and
two batch reconstruction families with fixed synthetic inputs. Capture old bytes
in the unchanged baseline; assert full report/reconstruction/selection bytes and
digests. Add new codec interface tests before implementing it.
Verify targeted compatibility tests and existing approval/readback tests.

### Task 2: Concentrate the five intents

Replace optional Plan mode fields with five closed concrete intent records.
Move approval and readback proof dispatch into their owner. Preserve constructors,
getters, native identity remapping, all proof algorithms and exact legacy bytes.
Verify five-mode compatibility, full plan tests and dependent analysis/operations.

### Task 3: Own reconstruction in plan

Move bounded versioned reconstruction representation into plan independently of
report DTOs. Add opaque decoded material; operations owns exact snapshot loading
and supplies production renderer selection. Preserve existing operations methods,
errors, validation order, byte limits, algorithm/version and replay-only scope.
Verify RED/GREEN codec tests, byte goldens, malformed/budget/cancel cases, all
native creation forms, restart/idempotency/uncertain no-replay and readback.

### Task 4: Evidence, documentation and review

Add domain glossary and update reconstruction contracts. Generate the architecture
HTML report in the OS temp directory, then open it. Measure identical baseline
and final planning/reconstruction workloads serially, recording raw samples.
Run root race/vet/build, Go1.26 tests, isolated pinned/current adapter checks,
format/diff checks and baseline preservation. Perform final fresh-context review
when available; record credit failure without inventing approval.

## Review focus

Exact serialized bytes and error identities, independent baseline/readback
proofs, original versus accepted intent ownership, before-materialization input
charging, opaque reconstruction immutability, no dependency cycle, unsupported
non-batch reconstruction, and preservation of all pre-existing WIP.
