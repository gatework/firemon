# Selected execution and restart

`operations.BatchDesigner` produces reviewable per-device plans and independent
input issues. A report is not an executable import or write authorization.
The caller explicitly selects `Device`, immutable `Revision`, and `PlanDigest`;
migration also requires its retained `SourceRevision`.
`NewBatchExecutor(directory, deploymentEngine, snapshotStore)` then provides:

```go
prepared, err := executor.Prepare(ctx, "ticket-42", report, selected)
// Persist prepared.ID and prepared.Digest in the host's approval record.
result, err := executor.Apply(ctx, prepared.ID, prepared.Digest)
// A fresh process uses the same selection directory, snapshot store and journal.
recovered, err := executor.Recover(ctx, prepared.ID, prepared.Digest)
```

`Prepare` verifies every selected plan can be reconstructed using production
renderers. It persists the complete detached review (including unresolved inputs,
topology, original/real/translated coordinates and source mappings), plus exact
reconstruction material, with file and directory fsync before any device action.
An advisory lock serializes preparation across processes. Reusing an identity
with different review, selection order or material returns `ErrSelectionConflict`.
The SHA-256 selection digest covers the exact persisted bytes. The host must
retain that digest independently; a checksum does not authenticate arbitrary
material supplied with a new checksum.

Execution is sequential in explicit selection order. Each device uses the
existing `deploy.Engine.Apply` or `Recover`, with a stable operation ID derived
from length-prefixed batch, device, revision and plan-digest bytes. The engine
retains its own reservation, authorization, fresh-baseline, native configuration
ownership, receipt, persistence and independent readback requirements. Changing
the batch ID is a new operation, not a way to recover an uncertain write.

Results retain the full review and separate device outcomes: `applied`, `failed`,
`uncertain`, `aborted`, `cancelled`, `unstarted`. Device failures are in each
outcome's `Error` (excluded from JSON); the batch error represents selection/load
failure or context cancellation. A failure does not erase a successful peer or
roll it back. Cancellation stops subsequent devices. A terminal aborted journal
is not success. Repeated apply delegates to the same journal and never replays
pending commands. Recovery makes no Execute/Save calls and never starts an
unstarted device. Missing original snapshots cause local reconstruction failure;
other selected devices can still proceed.

`plan.EncodeReconstruction` / `operations.RestorePlan` use strict bounded JSON
version 2, algorithm `firemon-business-v2`, with a 4 MiB material limit.
It stores original baseline
revision, metadata, source/semantic digests, all original ordered inputs including
rejections, effective planner options and expected approval digest. Native inputs
retain NAT steps, declarations, provenance, packet proof requests, schedule clock
and finite windows. Snapshot bytes stay in the immutable snapshot store; retain
those blobs for the entire operation/recovery lifetime. `snapshot.Store.Load`
verifies their content hash. Restoration never reads a latest head, reparses
source or trusts a stored after-graph, commands or proof flags. It reruns full
planning, rendering and proof and requires the same plan digest.

The `plan` module owns this format independently of report documents.
`operations.RestorePlan` loads both retained snapshots when required;
`operations.EncodePlan` and its error alias were removed. A host with its own
snapshot and renderer adapters can use the core interface directly:

```go
revisions := plan.SnapshotRevisions{Baseline: revision}
if original.MigrationSource() != nil {
    revisions.Source = sourceRevision
}
checksum, err := plan.EncodeReconstruction(ctx, writer, revisions, original)
// Retain checksum independently; decoding does not authorize a write.
material, err := plan.DecodeReconstruction(ctx, reader, checksum)
// After checking err, load material.Revision() from the immutable snapshot store.
baseline, err := store.Load(ctx, material.Revision())
snapshots := plan.ReconstructionSnapshots{Baseline: baseline}
if material.SourceRevision() != "" {
    snapshots.Source, err = store.Load(ctx, material.SourceRevision())
}
// After checking err, supply a renderer selector with the existing shape.
rebuilt, err := material.Rebuild(ctx, snapshots, vendors.Renderer)
```

`DecodeReconstruction` checks the checksum, strict format and input budgets before
returning opaque, owned material. `Rebuild` checks baseline completeness,
metadata and semantic identity before invoking the selector. Every rebuild runs
planning and proof again with the saved effective options and checks the approval
digest. Decoded material is immutable and supports independent concurrent
rebuilds; nil and zero values cannot be rebuilt. Cancellation takes precedence at
each core entry point. Callers use `plan.ErrReconstruction`; the nil-reader error
in `RestorePlan` remains `operations.ErrInvalid`. The core module imports no
snapshot or vendor adapter. Migration checks source and target metadata and
semantic identity before selecting a renderer, then reruns the complete closure
and preservation proof against those exact immutable snapshots.

Material permits at most 100 inputs, 10,000 candidates, 10,000,000 visits, 65,536
regions and 65,536 combinations; effective original options must fit these
ceilings. Region and nested native containers are charged before materialization.
The complete persisted selection is limited to 16 MiB and 100 distinct devices.
Unsupported versions, extra fields/trailing JSON, checksum mismatch, unavailable
baseline or changed algorithm output stop reconstruction. Keep the original
algorithm available across software upgrades; this format does not promise
silent migration to a future planner.

Approval version 4 uses explicit access, policy, native, preserve, transfer and
migration kinds; all retain the inputs needed for reconstruction version 2.
Preservation candidates are untrusted proposals that must be resealed and proved.
Old approval bytes and reconstruction versions are not compatibility contracts.

Tests use temporary stores and synthetic sessions with the real deployment
engine, production renderers and independent native parsers. They cover restart,
selection/authorization binding, uncertainty without replay, aborted operations,
unstarted recovery, baseline drift, missing blobs, corruption and cancellation.
Twenty supported native NAT forms and finite packet intent reconstruct and
revalidate locally. These checks do not establish real-device acceptance.

See the [planning glossary](../GLOSSARY.md) and
[intent refactor evidence](intent-verification.md) for historical ownership checks,
and the [current implementation report](2026-11-07-domain-improvements.md) for
the new format and behavior verification.
